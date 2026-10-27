# Edge Architecture & Threat Defense Mesh

## 1. High-Level Architecture Overview

The **Zero-Trust Cloud Edge & Intelligent WAF Bot Defense Mesh** provides sub-2ms perimeter protection across AWS global edge locations using CloudFront, AWS WAFv2, and Lambda@Edge.

```
                    Internet Traffic (Global Clients & Attackers)
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │     AWS CloudFront CDN Edge       │
                     │  - TLS 1.3 / Strict HSTS         │
                     │  - Custom Security Headers (CSP)  │
                     └─────────────────┬─────────────────┘
                                       │
                                       ▼
                     ┌───────────────────────────────────┐
                     │        AWS WAFv2 WebACL           │
                     │  1. Dynamic IP Blocklist          │
                     │  2. Token Bucket Rate Limiter     │
                     │  3. AWS Amazon IP Reputation      │
                     │  4. OWASP Top 10 Core CRS         │
                     │  5. SQLi / Injection Shields      │
                     └─────────┬─────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
      [Hard Block / Drop]                   [Sanitized Ingress]
       (HTTP 403 Response)                        │
                                                  ▼
                                ┌───────────────────────────────────┐
                                │        Lambda@Edge Engine         │
                                │  - Deep Payload Inspection        │
                                │  - Contextual Risk Scoring (0-100)│
                                │  - Honey-Token & Decoy Sandbox    │
                                └─────────────────┬─────────────────┘
                                                  │
                      ┌───────────────────────────┴───────────────────────────┐
                      ▼                                                       ▼
            [Decoy Diversion]                                         [Forward to Origin]
        Honeypot Sandbox Origin                                    ALB / API Gateway / ECS
      (Threat Intel Harvesting)                                   (Zero-Trust Token Enforced)
```

---

## 2. Request Lifecycle & Evaluation Flow

1. **Edge Ingress**:
   - Inbound TLS connection is terminated at the closest CloudFront Point of Presence (PoP).
   - Strict TLS 1.2/1.3 and HSTS (`max-age=31536000; includeSubDomains; preload`) are strictly enforced.

2. **Perimeter WAFv2 Filtering**:
   - **Priority 1**: Instant drop if IP is in the dynamic `AutomatedBannedIPSet`.
   - **Priority 2**: IP rate limiting triggers block if velocity exceeds threshold.
   - **Priority 3**: AWS Managed Threat Intelligence blocks known malicious botnets, Tor exit nodes, and anonymous proxies.
   - **Priority 4-5**: OWASP Core CRS and SQLi rule sets inspect payloads.

3. **Lambda@Edge Contextual Evaluation**:
   - Computes multi-factor risk score (0 - 100) combining user-agent entropy, header presence, payload regex, and geo-location.
   - Executes mitigation decision:
     - `ALLOW` (Score 0-25): Request passes with injected `X-Zero-Trust-Risk-Score`.
     - `CHALLENGE_CAPTCHA` (Score 26-65): Silent or interactive browser verification challenge.
     - `DIVERT_HONEYPOT` (Score 66-85): Seamlessly rerouted to canary honeypot without notifying attacker.
     - `BLOCK` (Score 86-100): Direct HTTP 403 response generated at edge.

4. **Continuous Telemetry & Autonomous Blacklisting**:
   - Decisions are emitted to CloudWatch Metrics and Kinesis Firehose.
   - CloudWatch Alarms trigger autonomous WAF IP set updates for repeat offenders.
