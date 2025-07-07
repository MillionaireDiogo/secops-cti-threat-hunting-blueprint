# Threat Hunting with Palo Alto Networks Firewall Overview

Palo Alto Networks firewalls provide rich, granular logs covering traffic, threat events, VPN, user activity, URL filtering, and configuration changes. Their logs are critical for detecting lateral movement, command and control, malware infections, and policy violations.

---

## 2. Log Sources

| Log Source                  | Description                                                                |
|----------------------------|----------------------------------------------------------------------------|
| **Traffic Logs**            | Allowed/denied session details including source/destination IPs, ports, apps, URLs |
| **Threat Logs**             | Alerts on detected malware, exploits, vulnerabilities, and C2 traffic     |
| **URL Filtering Logs**      | HTTP/S URL categories accessed and blocked URLs                           |
| **User-ID Logs**            | User-to-IP mapping, authentication and login/logout events                |
| **VPN Logs**                | VPN connection establishment and termination                              |
| **Configuration Logs**      | Policy, object, and system configuration changes                          |
| **System Logs**             | Device status, system events, and administrative actions                  |

---

## 3. Threat Hunting Categories & Keywords

### A. Traffic & Connection Anomalies

| Keyword/Field             | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `action:deny`            | Denied sessions — scanning, brute-force attempts                           |
| `action:allow`           | Allowed sessions — inspect for suspicious or rare destinations             |
| `src_ip`                 | Source IP address — check for threat intelligence matches                   |
| `dst_ip`                 | Destination IP — critical assets or unusual external endpoints              |
| `dst_port`               | Target ports — especially high-risk or uncommon ports                       |
| `application`            | Monitored apps — unexpected apps may indicate suspicious behavior          |
| `bytes_sent` / `bytes_received` | Large data flows suggesting exfiltration                              |
| `session_duration`       | Long or short unusual session durations                                    |

---

### B. Threat & Malware Detection

| Keyword/Field             | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `threat_name`            | Detected malware, exploit names, or C2 indicators                          |
| `severity`               | Alert severity — prioritize high and critical                             |
| `action:blocked`         | Threats blocked by firewall or IPS                                         |
| `virus`                  | Malware detection alerts                                                  |
| `spyware`                | Spyware or adware detection                                               |

---

### C. VPN & User Activity

| Keyword/Field             | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `vpn_event`              | VPN connect/disconnect events                                              |
| `user`                   | User-ID associated with IPs                                                |
| `auth_success`           | Successful user authentications                                            |
| `auth_failure`           | Failed logins — possible brute-force                                       |
| `user_group`             | Group memberships for user activity context                               |

---

### D. Configuration & Policy Changes

| Keyword/Field             | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `config_change`          | Policy, object, or device config changes                                   |
| `admin_login`            | Administrative access events                                               |
| `failed_admin_login`     | Failed admin login attempts                                                |

---

### E. URL Filtering & Application Control

| Keyword/Field             | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `url_category`           | Access to risky or blocked URL categories                                  |
| `app_blocked`            | Blocked application traffic                                                |
| `app_allowed`            | Allowed unusual or risky application use                                  |

---

## 4. Additional Recommendations

1. Review denied traffic logs for scanning or brute force (`action:deny`).  
2. Investigate threat logs for malware, exploits, and C2 traffic.  
3. Analyze VPN user activity and authentication logs.  
4. Audit configuration changes and admin access events.  
5. Monitor URL filtering and application control for suspicious behavior.  
6. Correlate large data transfers or unusual application use with threat indicators.  

---
