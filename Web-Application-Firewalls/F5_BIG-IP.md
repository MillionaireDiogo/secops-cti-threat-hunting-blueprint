# Threat Hunting with F5 BIG-IP (FS_BIG-IP) Overview

F5 BIG-IP is an advanced application delivery controller (ADC) offering load balancing, SSL/TLS termination, WAF, and access management. Threat hunting targets malicious traffic patterns, administrative abuse, configuration tampering, and network-level attacks.

---

## 2. Log Sources

| Log Source               | Description                                        |
|-------------------------|--------------------------------------------------|
| **ASM/WAF Logs**         | Web Application Firewall events and policy violations |
| **Access Logs**          | User authentication and admin access logs        |
| **Audit Logs**           | Configuration changes and admin actions           |
| **System Logs**          | Device health, errors, and network events         |
| **DNS and Network Logs** | DNS queries, traffic flow, and protocol anomalies |

---

## 3. Threat Hunting (Attack Lifecycle Focus)

### A. **Reconnaissance & Probing**

| Keyword/Field            | Description                                         |
|-------------------------|-----------------------------------------------------|
| `waf_rule_triggered`     | WAF rules triggered by suspicious request patterns |
| `sql_injection_attempt`  | SQL injection attack signatures                      |
| `xss_attempt`            | Cross-site scripting attack attempts                 |
| `bad_user_agent`         | Malformed or rare User-Agent headers                 |
| `port_scan`              | Detection of port scanning activities                |

---

### B. **Exploitation Attempts**

| Keyword/Field            | Description                                         |
|-------------------------|-----------------------------------------------------|
| `waf_block`              | Requests blocked by WAF policies                     |
| `unauthorized_access`    | Attempts to access restricted URLs or management UI |
| `command_injection`      | OS command injection patterns detected               |
| `ssl_handshake_failure`  | SSL/TLS handshake errors indicating probing or MITM |
| `rate_limit_triggered`   | Rate limiting triggered by suspicious bursts         |

---

### C. **Evasion & Evasive Techniques**

| Keyword/Field            | Description                                         |
|-------------------------|-----------------------------------------------------|
| `challenge_bypass`       | Attempts to bypass WAF or CAPTCHA challenges        |
| `encoded_payload`        | Use of encoded or obfuscated payloads               |
| `ip_spoofing`            | Suspicious or forged IP addresses                    |
| `cookie_manipulation`    | Suspicious or malformed cookie values                |
| `header_tampering`       | Unusual or inconsistent HTTP headers                 |

---

### D. **Administrative & Configuration Events**

| Keyword/Field            | Description                                         |
|-------------------------|-----------------------------------------------------|
| `admin_login_success`    | Successful admin or operator logins                  |
| `admin_login_failure`    | Failed login attempts to management interfaces       |
| `config_change`          | Changes to device or WAF configurations              |
| `privilege_escalation`   | Elevation of admin or user privileges                 |
| `unauthorized_command`   | Execution of unauthorized CLI or API commands        |

---

### E. **Network & System Anomalies**

| Keyword/Field            | Description                                         |
|-------------------------|-----------------------------------------------------|
| `cpu_spike`              | Unexpected CPU usage spikes                          |
| `memory_spike`           | Unusual memory consumption                           |
| `device_reboot`          | Unexpected device restarts                           |
| `dns_anomaly`            | Suspicious DNS query patterns                        |
| `dos_attack`             | Indicators of denial-of-service or flooding attacks |

---

## 4. Additional Recommendations

1. Identify reconnaissance attempts by tracking WAF rule triggers and suspicious user agents.  
2. Detect exploitation attempts through blocked requests, SSL errors, and unauthorized access.  
3. Look for evasion tactics such as payload encoding, challenge bypass, and header manipulation.  
4. Monitor administrative activities, including login attempts, privilege changes, and config modifications.  
5. Analyze system performance and network logs for anomalies indicating compromise or attacks.  

---
