# Zero-Trust Edge Contextual Risk Scoring Matrix

## 1. Principles of Zero-Trust at the Edge
Under the Zero-Trust security model ("Never Trust, Always Verify"), all incoming network traffic arriving at CloudFront edge nodes is treated as inherently untrusted, regardless of source IP or past reputation.

---

## 2. Decision Tiers & Action Thresholds

| Risk Score Range | Decision Action | Edge Response / Behavior |
|:---|:---|:---|
| **0 – 25** | `ALLOW` | Clean request. Injects `X-Zero-Trust-Risk-Score` and passes to origin. |
| **26 – 65** | `CHALLENGE_CAPTCHA` | Suspicious signals (e.g. headless browser or high velocity). Returns challenge. |
| **66 – 85** | `DIVERT_HONEYPOT` | Highly suspect scraper or reconnaissance probe. Diverted to sandbox decoy. |
| **86 – 100** | `BLOCK` | Definitive attack vector (SQLi, XSS, SSRF, Sanctioned Geo). Immediate HTTP 403. |

---

## 3. Threat Scoring Vectors & Weights

| Threat Vector | Indicator / Pattern | Risk Score Weight |
|:---|:---|:---|
| **SQL Injection (SQLi)** | `UNION SELECT`, `' OR 1=1`, time-based delays | **95** (Immediate Block) |
| **Cross-Site Scripting (XSS)** | `<script>`, `javascript:`, DOM event handlers | **85** (Immediate Block) |
| **Cloud Metadata SSRF** | `169.254.169.254`, `latest/meta-data` | **100** (Immediate Block) |
| **Path Traversal / LFI** | `../../`, `/etc/passwd`, `win.ini` | **95** (Immediate Block) |
| **Honeypot Probing** | `/.git/config`, `/wp-login.php`, `/actuator` | **100** (Honeypot / Block) |
| **Sanctioned Geolocation** | Origin country in KP, IR, SY, CU | **95** (Immediate Block) |
| **Offensive Tool Scrapers** | `sqlmap`, `nikto`, `masscan`, `wpscan` | **75** (Honeypot / Block) |
| **Rate Limit Burst** | Exceeds requests per minute threshold | **70** (Challenge / Block) |
| **Spoofed Search Crawler** | Claims to be Googlebot from non-Google ASN | **90** (Immediate Block) |
| **Missing User-Agent** | Empty or non-standard User-Agent header | **40** (Challenge) |
