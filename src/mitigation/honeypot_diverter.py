"""Honeypot Decoy Diverter and Deception Routing Engine."""

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class DeceptionResponse:
    status_code: int
    headers: Dict[str, str]
    body: str


class HoneypotDiverter:
    """Generates synthetic deceptive payloads to decoy attackers while recording threat telemetry."""

    DECOY_ORIGIN_HOST = "honeypot-telemetry-sink.internal.aws"

    @classmethod
    def generate_synthetic_decoy(cls, uri: str) -> DeceptionResponse:
        """Returns realistic mock honey-tokens or decoy server responses."""
        if "admin" in uri.lower() or "login" in uri.lower():
            return DeceptionResponse(
                status_code=200,
                headers={"Content-Type": "application/json", "X-Decoy-Engine": "Active-Zero-Trust"},
                body='{"status":"authenticated","user":"guest_auditor","token":"decoy_tok_99182aef","session_active":true}',
            )

        if ".git" in uri.lower() or "config" in uri.lower():
            return DeceptionResponse(
                status_code=200,
                headers={"Content-Type": "text/plain", "X-Decoy-Engine": "Active-Zero-Trust"},
                body='[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n[remote "origin"]\n\turl = git@github.com:canary-internal/fake-repo.git',
            )

        return DeceptionResponse(
            status_code=403,
            headers={"Content-Type": "application/json"},
            body='{"error":"EdgeSecurityChallengeRequired","reason":"Suspicious Request Fingerprint"}',
        )

    @classmethod
    def get_decoy_origin_headers(cls) -> Dict[str, Any]:
        """Headers injected at CloudFront Edge to transparently divert request to honeypot origin."""
        return {
            "x-edge-diverted": "true",
            "x-edge-isolation-tier": "honeypot-sandbox",
            "host": cls.DECOY_ORIGIN_HOST,
        }
