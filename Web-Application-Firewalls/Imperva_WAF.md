# Threat Hunting with Imperva WAF Overview

Imperva provides robust Web Application Firewall (WAF), DDoS protection, bot management, and application security. Threat hunting focuses on detecting attack attempts, malicious bots, evasion techniques, and suspicious administrative activities impacting web applications.

---

## 2. Log Sources

| Log Source               | Description                                              |
|-------------------------|----------------------------------------------------------|
| **WAF Logs**             | Blocked/allowed requests based on security policies      |
| **Bot Management Logs**  | Detection of automated or suspicious bot traffic         |
| **DDoS Protection Logs** | Traffic anomalies and rate limiting events                |
| **Access Logs**          | User authentication and session activity                  |
| **Audit Logs**           | Administrative actions and configuration changes          |
| **Security Alerts**      | Alerts generated from security events and anomalies       |

---

## 3. Threat Hunting (Attack Lifecycle Focus)

### A. **Reconnaissance & Probing**

| Keyword/Field            | Description                                              |
|-------------------------|----------------------------------------------------------|
| `sql_injection_attempt`  | SQL injection patterns detected in HTTP requests         |
| `xss_attempt`            | Cross-site scripting attack attempts                      |
| `path_traversal`         | Attempts to access restricted files or directories       |
| `scanner_activity`       | Requests resembling automated vulnerability scans         |
| `suspicious_user_agent`  | Uncommon or malformed User-Agent headers                  |

---

### B. **Exploitation Attempts**

| Keyword/Field            | Description                                              |
|-------------------------|----------------------------------------------------------|
| `waf_block`              | Requests blocked by WAF policies                          |
| `command_injection`      | OS command injection signatures detected                  |
| `remote_file_inclusion`  | Attempts to include remote resources                      |
| `unauthorized_access`    | Access attempts without proper authorization              |
| `csrf_attempt`           | Cross-site request forgery attack vectors                 |

---

### C. **Evasion & Evasive Techniques**

| Keyword/Field            | Description                                              |
|-------------------------|----------------------------------------------------------|
| `rate_limit_triggered`   | Rate limits triggered due to suspicious request volumes  |
| `challenge_bypass`       | Attempts to bypass CAPTCHA or challenge-response tests   |
| `encoded_payload`        | Use of URL-encoded or obfuscated payloads                 |
| `cookie_tampering`       | Suspicious or malformed cookie values                      |
| `header_manipulation`    | Unusual or inconsistent HTTP headers                      |

---

### D. **Bot & Automated Traffic Detection**

| Keyword/Field            | Description                                              |
|-------------------------|----------------------------------------------------------|
| `known_bad_bot`          | Traffic from recognized malicious or scraping bots       |
| `credential_stuffing`    | Multiple login attempts from same IP/user agent           |
| `crawler_activity`       | High-volume automated crawling behavior                    |
| `suspicious_referrer`   | Referrer headers indicating suspicious sources            |

---

### E. **Administrative & Configuration Events**

| Keyword/Field            | Description                                              |
|-------------------------|----------------------------------------------------------|
| `admin_login_success`    | Successful administrator logins                           |
| `admin_login_failure`    | Failed admin login attempts                               |
| `config_change`          | Changes to WAF or security policy configurations          |
| `privilege_escalation`   | Elevation of user privileges                              |
| `unauthorized_command`   | Execution of unauthorized commands or API calls           |

---

## 4. Additional Recommendations

1. Monitor reconnaissance activity through WAF blocks and scanning patterns.  
2. Detect exploitation attempts via blocked requests, unauthorized access, and command injections.  
3. Identify evasion by spotting challenge bypass, rate limit triggers, and payload obfuscation.  
4. Analyze bot traffic for credential stuffing and scraping behaviors.  
5. Audit administrative logs for suspicious logins and configuration changes.  

---

