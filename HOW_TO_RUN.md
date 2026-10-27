# How to Run: Zero-Trust Cloud Edge & Intelligent WAF Mesh

A step-by-step operational guide for testing, simulating, and deploying the Zero-Trust Edge Security Engine.

---

## 1. Quick Local Execution

### Windows (PowerShell)
```powershell
cd c:\Users\gohil\Desktop\AWS\Zero-Trust-Cloud-Edge-WAF-Mesh

# Run multi-vector attack simulation
.\run.ps1 -Action simulate

# Evaluate custom attack request
.\run.ps1 -Action evaluate -Uri "/api/v1/auth" -Payload "' OR 1=1--"

# Run complete test suite
.\run.ps1 -Action test

# Run code linter
.\run.ps1 -Action lint
```

### Linux / macOS (Bash)
```bash
chmod +x run.sh

# Run simulation
./run.sh simulate

# Run tests
./run.sh test
```

---

## 2. CLI Command Reference

The platform includes an interactive CLI (`src/cli.py`):

### 1. `simulate`
Runs 7 high-fidelity attack scenarios (SQLi, XSS, Scraper bot, Sanctioned geo, Honeypot probe, Cloud metadata SSRF, and Clean user):
```bash
python -m src.cli simulate
```

### 2. `evaluate`
Evaluates an individual inbound HTTP request context:
```bash
python -m src.cli evaluate \
  --ip 203.0.113.50 \
  --method POST \
  --uri /api/v1/admin/login \
  --body "user=admin' OR '1'='1" \
  --country US \
  --asn 15169
```

### 3. `block-ip`
Manages AWS WAFv2 IP Sets dynamically:
```bash
# Add malicious IP to blocklist
python -m src.cli block-ip add --ip 198.51.100.22 --name zero-trust-waf-prod-banned-ips

# Remove IP from blocklist
python -m src.cli block-ip remove --ip 198.51.100.22 --name zero-trust-waf-prod-banned-ips
```

---

## 3. Running Unit Tests & Code Coverage
```bash
# Run pytest with code coverage
pytest -v --cov=src --cov-report=term-missing
```

All AWS services are mocked using Moto, meaning tests run 100% offline without incurring AWS charges or requiring cloud credentials.

---

## 4. Terraform Cloud Deployment
```bash
cd terraform

# Initialize providers
terraform init

# Review planned infrastructure
terraform plan

# Deploy to AWS account
terraform apply
```
