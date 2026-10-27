# Zero-Trust Cloud Edge & Intelligent WAF Bot Defense Mesh

[![CI/CD Pipeline](https://github.com/KoshaG0hil/Zero-Trust-Cloud-Edge-WAF-Mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/KoshaG0hil/Zero-Trust-Cloud-Edge-WAF-Mesh/actions/workflows/ci.yml)
[![GitHub Pages](https://github.com/KoshaG0hil/Zero-Trust-Cloud-Edge-WAF-Mesh/actions/workflows/pages.yml/badge.svg)](https://koshag0hil.github.io/Zero-Trust-Cloud-Edge-WAF-Mesh/)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![AWS](https://img.shields.io/badge/AWS-CloudFront%20%7C%20WAFv2%20%7C%20Lambda%40Edge-orange.svg)](https://aws.amazon.com/)
[![Terraform](https://img.shields.io/badge/IaC-Terraform%201.7+-purple.svg)](https://www.terraform.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade **AWS Edge Security & Zero-Trust Defense Mesh** providing sub-2ms perimeter inspection, real-time OWASP Top 10 mitigation, autonomous bot countermeasures, honeypot deception routing, and dynamic WAF blacklisting.

🌐 **Live Interactive SOC Dashboard:** [https://koshag0hil.github.io/Zero-Trust-Cloud-Edge-WAF-Mesh/](https://koshag0hil.github.io/Zero-Trust-Cloud-Edge-WAF-Mesh/)

---

## 🏛️ Architectural Overview

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

## ⚡ Core Capabilities

1. **Multi-Vector Zero-Trust Edge Scoring (0 - 100)**:
   - Evaluates inbound HTTP method, path, headers, query string, body, client IP, ASN, and geo-origin.
   - Computes weighted contextual risk scores within **< 2ms** latency overhead.

2. **OWASP Top 10 & Advanced Injection Shield**:
   - Detects SQL injection tautologies, UNION SELECT, time-based attacks, and stacked queries.
   - Blocks Stored/Reflected XSS, DOM event handlers, path traversal (`../../`), and cloud metadata SSRF attempts (`169.254.169.254`).

3. **Intelligent Bot Defense & Spoof Detection**:
   - Fingerprints offensive scanners (`sqlmap`, `nikto`, `masscan`, `wpscan`, `dirbuster`).
   - Identifies headless browsers (`Puppeteer`, `Playwright`, `HeadlessChrome`).
   - Validates search engine crawlers against authentic ASN ranges to prevent bot spoofing.

4. **Deception & Honeypot Diversion**:
   - Reroutes recon probes targeting honeypot endpoints (`/.git/config`, `/wp-login.php`, `/actuator`) to isolated decoy sandboxes, poisoning attacker recon data without exposing real infrastructure.

5. **Autonomous WAFv2 IP Blacklisting**:
   - Dynamically updates AWS WAFv2 IP Sets via boto3 controller when attack velocity thresholds are breached.

6. **Cryptographic SHA-256 Audit Bulletins**:
   - Produces tamper-evident SOC threat bulletins with deterministic SHA-256 integrity checksums.

---

## 🚦 Decision Matrix

| Risk Score Range | Decision Action | Edge Response / Behavior |
|:---|:---|:---|
| **0 – 25** | `ALLOW` | Clean request. Injects `X-Zero-Trust-Risk-Score` and passes to origin. |
| **26 – 65** | `CHALLENGE_CAPTCHA` | Suspicious signals (headless browser or burst velocity). Returns challenge. |
| **66 – 85** | `DIVERT_HONEYPOT` | Scraper or recon probe. Diverted to sandbox decoy. |
| **86 – 100** | `BLOCK` | Definitive attack vector (SQLi, XSS, SSRF, Sanctioned Geo). Immediate HTTP 403. |

---

## 🚀 Quickstart & Execution

### 1. Prerequisites & Installation
```bash
# Clone the repository
git clone https://github.com/KoshaG0hil/Zero-Trust-Cloud-Edge-WAF-Mesh.git
cd Zero-Trust-Cloud-Edge-WAF-Mesh

# Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Multi-Vector Attack Simulation
```bash
# Execute full multi-scenario edge threat simulation
python -m src.cli simulate

# Or using helper scripts
# Windows PowerShell:
.\run.ps1 -Action simulate
# Linux / macOS:
./run.sh simulate
```

### 3. Evaluate Individual Request
```bash
python -m src.cli evaluate \
  --ip "203.0.113.88" \
  --uri "/api/v1/search" \
  --query "q=' UNION SELECT null, username, password FROM users--" \
  --country "US"
```

### 4. Run Pytest Suite with Moto Mocks
```bash
pytest -v --cov=src
```

### 5. Deploy via Docker
```bash
docker build -t zero-trust-waf-mesh .
docker run --rm zero-trust-waf-mesh simulate
```

---

## 📦 Terraform Infrastructure as Code (IaC)

Deploy the full AWS edge stack in minutes:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars

# Review and apply
terraform init
terraform plan
terraform apply
```

### Managed AWS Resources:
- `aws_wafv2_web_acl.edge_perimeter`: Global WAFv2 WebACL (us-east-1).
- `aws_wafv2_ip_set.automated_blocklist`: Dynamic banned IP set.
- `aws_cloudfront_distribution.edge_cdn`: TLS 1.3 CDN with WAF association.
- `aws_cloudfront_response_headers_policy.strict_security_headers`: HSTS & CSP headers.
- `aws_iam_role.lambda_edge_exec`: Lambda@Edge execution role.
- `aws_cloudwatch_metric_alarm.high_waf_blocked_requests`: CloudWatch anomaly alert.

---

## 📊 Live Interactive Dashboard

Visit the [Live GitHub Pages Deployment](https://koshag0hil.github.io/Zero-Trust-Cloud-Edge-WAF-Mesh/) to experience:
- **Live Global Threat Map**: Animated beam visualizations from global attacker origins to CloudFront PoPs.
- **Interactive Attack Simulator**: Test custom SQLi, XSS, bot, and geo-spoofing payloads in real time.
- **Real-Time SOC Telemetry Feed**: Live event logging with risk scores and mitigation actions.

---

## 👤 Author & Maintainer

**Kosha Gohil**
- GitHub: [@KoshaG0hil](https://github.com/KoshaG0hil)
- Portfolio: [Cloud Security, DevSecOps & FinOps Architecture](https://github.com/KoshaG0hil)
