# Threat Hunting with Cloudflare WAF (Web Application Firewall) Overview

Cloudflare WAF protects web applications by filtering and monitoring HTTP traffic. Threat hunting here focuses on identifying malicious traffic patterns, probing attacks, exploitation attempts, and evasion tactics to prevent breaches.

---

## 2. Log Sources

| Log Source               | Description                                          |
|-------------------------|------------------------------------------------------|
| **Firewall Events Logs** | Blocked/allowed requests based on WAF rules          |
| **HTTP Request Logs**    | Details of incoming HTTP requests                     |
| **Challenge Logs**       | CAPTCHA or JS challenge events triggered              |
| **Rate Limiting Logs**   | Traffic rate limits triggered                         |
| **Bot Management Logs**  | Detection of automated or suspicious bot traffic     |
| **Security Alerts**      | Alerts generated from security events and anomalies  |

---

## 3. Threat Hunting (Attack Lifecycle Focus)

### A. **Reconnaissance & Probing**

| Keyword/Field           | Description                                            |
|------------------------|--------------------------------------------------------|
| `sql_injection_attempt`| SQL injection patterns detected in requests           |
| `xss_attempt`          | Cross-site scripting attack vectors                    |
| `path_traversal`       | Attempts to access restricted file system paths       |
| `suspicious_user_agent`| Uncommon or malformed User-Agent strings               |
| `scanner_activity`     | Requests resembling automated vulnerability scans     |

---

### B. **Exploitation Attempts**

| Keyword/Field           | Description                                            |
|------------------------|--------------------------------------------------------|
| `waf_block`            | Requests blocked by specific WAF rules                 |
| `command_injection`    | Indicators of OS command injection in parameters       |
| `remote_file_inclusion`| Attempts to include remote resources                    |
| `csrf_attempt`         | Cross-site request forgery attack patterns             |
| `unauthorized_access`  | Access to restricted URLs without proper authorization |

---

### C. **Evasion & Evasive Techniques**

| Keyword/Field           | Description                                            |
|------------------------|--------------------------------------------------------|
| `rate_limit_exceeded`  | Requests exceeding allowed rate thresholds             |
| `challenge_bypass`     | Attempts to bypass CAPTCHA or JS challenges             |
| `ip_spoofing`          | Suspicious IP header anomalies or proxy use             |
| `encoded_payload`      | Use of URL-encoded or obfuscated payloads               |
| `cookie_tampering`     | Suspicious or malformed cookie values                    |

---

### D. **Bot & Automated Traffic Detection**

| Keyword/Field           | Description                                            |
|------------------------|--------------------------------------------------------|
| `known_bad_bot`        | Traffic from recognized malicious bots or scrapers     |
| `credential_stuffing`  | Multiple login attempts from same IP/user agent        |
| `crawler_activity`     | High-volume automated crawling behavior                 |
| `suspicious_referrer` | Referrer headers indicating suspicious traffic sources |

---

## Additional Recommendation

1. Identify patterns of reconnaissance such as SQLi, XSS, and path traversal attempts.  
2. Detect exploitation attempts blocked or allowed by WAF rules.  
3. Monitor for evasion tactics like challenge bypass, rate limiting breaches, and payload obfuscation.  
4. Profile bot activity for credential stuffing, scraping, or automated attack behaviors.  
5. Correlate IP reputation, user-agent anomalies, and referrer headers with suspicious traffic.  

---


