"""AWS Lambda@Edge Viewer-Request Event Handler for CloudFront Zero-Trust Inspection."""

import base64
from typing import Any, Dict
from .core.config import MitigationAction, RequestContext
from .core.evaluator import ZeroTrustEdgeEvaluator
from .mitigation.honeypot_diverter import HoneypotDiverter

evaluator = ZeroTrustEdgeEvaluator()


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda@Edge entrypoint triggered on CloudFront 'viewer-request'."""
    try:
        cf_record = event["Records"][0]["cf"]
        request = cf_record["request"]
        client_ip = request.get("clientIp", "127.0.0.1")
        uri = request.get("uri", "/")
        method = request.get("method", "GET")
        querystring = request.get("querystring", "")

        # Extract headers from CloudFront key-value format: {"header-name": [{"key": "Header-Name", "value": "val"}]}
        flat_headers: Dict[str, str] = {}
        for h_key, h_list in request.get("headers", {}).items():
            if h_list and len(h_list) > 0:
                flat_headers[h_key] = h_list[0].get("value", "")

        # Extract country code if CloudFront-Viewer-Country header is forwarded
        country_code = flat_headers.get("cloudfront-viewer-country", "US")

        # Extract body if present
        body = ""
        if "body" in request and request["body"].get("data"):
            raw_data = request["body"]["data"]
            if request["body"].get("encoding") == "base64":
                body = base64.b64decode(raw_data).decode("utf-8", errors="ignore")
            else:
                body = raw_data

        req_context = RequestContext(
            client_ip=client_ip,
            method=method,
            uri=uri,
            headers=flat_headers,
            query_string=querystring,
            body=body,
            country_code=country_code,
            request_id=cf_record.get("config", {}).get("requestId", "req-edge-test"),
        )

        decision = evaluator.evaluate(req_context)

        # 1. Immediate Hard Block
        if decision.action == MitigationAction.BLOCK:
            return {
                "status": "403",
                "statusDescription": "Forbidden",
                "headers": {
                    "content-type": [{"key": "Content-Type", "value": "application/json"}],
                    "x-zero-trust-action": [{"key": "X-Zero-Trust-Action", "value": "BLOCK"}],
                    "x-threat-risk-score": [{"key": "X-Threat-Risk-Score", "value": str(decision.risk_score)}],
                },
                "body": '{"error": "AccessDeniedByEdgePerimeterPolicy", "risk_score": %d}' % decision.risk_score,
            }

        # 2. Deception / Honeypot Diversion
        if decision.action == MitigationAction.DIVERT_HONEYPOT:
            decoy = HoneypotDiverter.generate_synthetic_decoy(uri)
            return {
                "status": str(decoy.status_code),
                "statusDescription": "OK" if decoy.status_code == 200 else "Forbidden",
                "headers": {
                    "content-type": [{"key": "Content-Type", "value": decoy.headers.get("Content-Type", "text/plain")}],
                    "x-decoy-engine": [{"key": "X-Decoy-Engine", "value": "Active-Zero-Trust"}],
                },
                "body": decoy.body,
            }

        # 3. Allow or Challenge (Inject Zero-Trust telemetry headers down to origin)
        request["headers"]["x-zero-trust-risk-score"] = [
            {"key": "X-Zero-Trust-Risk-Score", "value": str(decision.risk_score)}
        ]
        request["headers"]["x-zero-trust-action"] = [{"key": "X-Zero-Trust-Action", "value": decision.action.value}]
        return request

    except Exception as exc:
        # Fail-open with error tag to prevent dropping legitimate edge traffic in outage
        return {
            "status": "500",
            "statusDescription": "Edge Inspection Exception",
            "headers": {"x-edge-error": [{"key": "X-Edge-Error", "value": str(exc)[:80]}]},
            "body": '{"error": "EdgeException"}',
        }
