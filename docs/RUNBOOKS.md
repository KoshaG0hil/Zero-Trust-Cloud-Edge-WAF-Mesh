# SOC Edge Incident Response Runbooks

## Runbook 1: Distributed Denial of Service (DDoS) Flood

### Severity: High / Critical
### Detection:
- CloudWatch Alarm `HighBlockedRequests` or `CloudFront4xxErrorSpike` enters `ALARM` state.
- Inbound request volume to CloudFront exceeds normal baseline by > 300%.

### Mitigation Workflow:
1. Identify high-velocity IPs via AWS WAF sampled requests:
   ```bash
   python -m src.cli evaluate --ip <SUSPICIOUS_IP>
   ```
2. Manually add rogue subnets to the dynamic IP blocklist if not caught automatically:
   ```bash
   python -m src.cli block-ip add --ip 198.51.100.0/24 --name zero-trust-waf-prod-banned-ips
   ```
3. Enable aggressive rate limiting on the WebACL via Terraform:
   - Decrease `rate_limit_threshold` from `300` to `100`.
   - Apply changes: `terraform apply -target=aws_wafv2_web_acl.edge_perimeter`

---

## Runbook 2: False Positive Remediation & Rule Exception

### Severity: Medium
### Detection:
- Legitimate enterprise customer or partner API client receives HTTP 403 Forbidden.
- Header `X-Zero-Trust-Action: BLOCK` is returned in response.

### Triage & Resolution:
1. Inspect the blocked request ID in WAF Access Logs or CloudWatch log group `/aws/lambda/us-east-1.edge-inspector`.
2. Determine which rule triggered the false positive (e.g. valid query containing SQL keywords like `select`).
3. Add a scoped exclusion in `rulesets/zero_trust_matrix.yaml` or AWS WAF rule override.
4. Verify resolution via CLI:
   ```bash
   python -m src.cli evaluate --uri "/legitimate/path" --body "..."
   ```
