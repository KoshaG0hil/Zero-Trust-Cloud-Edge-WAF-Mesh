# Project Guide: Zero-Trust Cloud Edge & Intelligent WAF Mesh

## 1. Project Purpose & Philosophy
Modern web applications face sophisticated bot networks, API abuse, and injection attacks operating at global scale. Traditional perimeter firewalls rely on static IP lists and coarse geo-blocking, which fail against distributed residential proxies and automated credential stuffing.

This project delivers a **Zero-Trust Edge Perimeter**:
1. **Never Trust by Default**: Every request is inspected and scored at the CloudFront edge prior to reaching application backends.
2. **Contextual Multi-Vector Scoring**: Rather than binary allow/deny rules, a risk score (0-100) is calculated combining IP velocity, ASN risk, payload heuristics, and user-agent entropy.
3. **Deceptive Honeypot Sandboxing**: Attackers conducting reconnaissance are diverted to synthetic decoy origins to capture threat intelligence without exposing production infrastructure.
4. **Sub-2ms Edge Compute**: Inspection algorithms run efficiently inside Lambda@Edge and WAFv2 without adding noticeable latency for legitimate users.

---

## 2. Directory Structure

```
Zero-Trust-Cloud-Edge-WAF-Mesh/
├── .github/
│   └── workflows/
│       ├── ci.yml                 # Automated CI/CD test and lint pipeline
│       └── pages.yml              # GitHub Pages live dashboard deployment
├── docs/
│   ├── ARCHITECTURE.md            # Detailed edge architecture & data flow
│   ├── ZERO_TRUST_MATRIX.md       # Risk scoring weights & decision rules
│   └── RUNBOOKS.md                # SOC incident response procedures
├── reports/
│   └── sample_waf_telemetry.json  # Cryptographic SHA-256 telemetry artifact
├── rulesets/
│   ├── bot_signatures.yaml        # Scraper & crawler signatures
│   ├── owasp_top10.json           # Injection & traversal patterns
│   └── zero_trust_matrix.yaml     # Policy weights & thresholds
├── src/
│   ├── core/
│   │   ├── config.py              # Configuration & RequestContext models
│   │   └── evaluator.py           # Master Zero-Trust Risk Engine
│   ├── inspectors/
│   │   ├── bot_detector.py        # Scraper & headless browser inspector
│   │   ├── geo_inspector.py       # Geolocation & ASN risk inspector
│   │   ├── rate_limiter.py        # Sliding window rate limiter
│   │   └── sqli_xss_inspector.py  # OWASP injection heuristics
│   ├── mitigation/
│   │   ├── honeypot_diverter.py   # Decoy sandboxing logic
│   │   └── waf_controller.py      # AWS WAFv2 boto3 client wrapper
│   ├── reporters/
│   │   ├── telemetry_streamer.py  # CloudWatch metric formatter
│   │   └── threat_bulletin.py     # SHA-256 audit report generator
│   ├── cli.py                     # Rich interactive command-line interface
│   ├── lambda_edge_handler.py     # Production Lambda@Edge viewer-request
│   └── waf_automation_handler.py  # Dynamic IP blacklist automation
├── terraform/
│   ├── cloudfront.tf              # CloudFront CDN with strict HSTS/CSP
│   ├── cloudwatch_alarms.tf       # WAF anomaly alarms
│   ├── ip_sets.tf                 # Dynamic WAF IPSet
│   ├── lambda_edge.tf             # Lambda@Edge IAM execution roles
│   ├── main.tf                    # AWS provider & locals
│   ├── outputs.tf                 # WebACL & CloudFront outputs
│   ├── terraform.tfvars.example   # Safe example variables
│   ├── variables.tf               # Input definitions
│   └── waf_webacl.tf              # AWS WAFv2 WebACL with rule groups
├── tests/
│   ├── conftest.py                # Mock credentials & Moto WAFv2 fixture
│   ├── test_bot_detector.py       # Bot detection tests
│   ├── test_evaluator.py          # End-to-end evaluation tests
│   ├── test_geo_inspector.py      # Geo-fencing tests
│   ├── test_lambda_edge.py        # Lambda@Edge event tests
│   ├── test_rate_limiter.py       # Rate limiting tests
│   ├── test_sqli_xss.py           # OWASP injection tests
│   └── test_waf_controller.py     # Dynamic WAF IP set tests
├── Dockerfile                     # Container deployment image
├── HOW_TO_RUN.md                  # Quick operational runbook
├── index.html                     # Live SOC Cyber Threat Map & Simulator
├── LICENSE                        # MIT License
├── pyproject.toml                 # Build system & Ruff configuration
├── README.md                      # Comprehensive project presentation
├── requirements.txt               # Python package dependencies
├── run.bat                        # Windows CMD helper
├── run.ps1                        # PowerShell helper
└── run.sh                         # Unix shell helper
```

---

## 3. Technology Stack & Certifications Alignment
- **Cloud Provider**: Amazon Web Services (AWS)
- **Edge CDN**: AWS CloudFront
- **WAF**: AWS WAFv2 (Global scope, us-east-1)
- **Edge Compute**: AWS Lambda@Edge / CloudFront Functions
- **Infrastructure as Code**: HashiCorp Terraform 1.7+
- **Security Testing**: Pytest 8.0+, Moto 5.0+, Ruff
- **Language**: Python 3.10 – 3.12
- **Certifications Target**: AWS Certified Security - Specialty, AWS DevOps Engineer - Professional
