# Threat Hunting with Fortinet FortiGate Firewall Overview

FortiGate firewalls provide comprehensive logs covering network traffic, security events, VPN activity, user authentication, and configuration changes. Fortinet’s rich logging and integrated threat intelligence make it well suited for identifying advanced threats, lateral movement, and policy violations.

---

## 2. Log Sources

| Log Source                   | Description                                                            |
|-----------------------------|------------------------------------------------------------------------|
| **Traffic Logs**             | Allowed/denied session details including src/dst IP, ports, protocols  |
| **Event Logs**               | System events, policy violations, anomalies, and threat detections     |
| **VPN Logs**                 | VPN tunnel establishment, authentication success/failure              |
| **User Authentication Logs** | User logins via VPN or management interface                            |
| **Configuration Change Logs** | Firewall policy, rule, and system configuration modifications          |
| **IPS/IDS Logs**             | Intrusion prevention system alerts and signature detections            |
| **Application Control Logs** | Traffic categorized by applications, with allowed/blocked decisions    |
| **Web Filter Logs**          | HTTP/S traffic inspection and URL category access                      |
| **Antivirus Logs**           | Malware detections and file scan results                              |

---

## 3. Threat Hunting Categories & Keywords

### A. Traffic & Connection Anomalies

| Keyword/Field              | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| `action:deny`             | Blocked traffic — look for repeated denies from same IP or unusual sources  |
| `action:accept`           | Allowed traffic — inspect for unexpected external destinations or ports     |
| `src_ip`                  | Source IP address — cross-check reputation and geolocation                  |
| `dst_ip`                  | Destination IP — monitor access to critical internal assets                 |
| `dst_port`                | Focus on high-risk ports (22, 3389, 445, 8080)                              |
| `session_duration`        | Long sessions possibly indicating beaconing or C2 channels                 |
| `bytes_in` / `bytes_out`  | Large data transfers potentially indicating data exfiltration              |
| `protocol`                | Unusual protocols or ports for business context                            |
| `geoip`                   | Connections from unexpected countries                                      |

---

### B. VPN & Remote Access

| Keyword/Field             | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `vpn_event`              | VPN tunnel established or terminated                                        |
| `vpn_auth_success`       | Successful VPN logins                                                       |
| `vpn_auth_fail`          | Failed login attempts potentially indicating brute-force                    |
| `user`                   | VPN user identity — unusual login times or geos                            |

---

### C. Policy & Configuration Changes

| Keyword/Event            | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `policy_created`        | New firewall policy added — review for unauthorized or risky rules          |
| `policy_modified`       | Changes to existing policies                                               |
| `policy_deleted`        | Removal of policies that could reduce security posture                      |
| `admin_login`           | Management interface login events, especially from unfamiliar IPs           |
| `config_backup`         | Configuration exports or backups                                           |

---

### D. Threat Prevention & Intrusion Events

| Keyword/Event            | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `ips_event`             | IPS alerts triggered by suspicious activity                                |
| `virus_detected`        | Malware detected by antivirus engine                                       |
| `attack_signature`      | Known exploit or attack signature triggered                                |
| `botnet_activity`       | Communication patterns typical of botnets or C2                            |

---

### E. Lateral Movement & Internal Traffic

| Keyword/Event            | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `internal_to_internal`  | Allowed traffic between internal segments potentially violating segmentation|
| `port_scan`             | Detection of port scanning activity within internal networks                |
| `admin_ports`           | Access to admin ports internally (SSH, RDP, WinRM)                         |

---

### F. Application & Web Control

| Keyword/Event            | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `app_blocked`           | Blocked application traffic signaling enforcement of security policy       |
| `app_allowed`           | Allowed risky or unusual application traffic                              |
| `web_filter_event`      | Suspicious URL category access or blocked web content                      |

---

## 4. Additional Recommendations

1. **Establish baselines** for normal traffic volumes, sources, and destinations.  
2. **Review denied connection logs** for repeated scanning or brute force attempts.  
3. **Correlate VPN user activities** with endpoint and asset data.  
4. **Audit policy changes** and rule modifications regularly.  
5. **Prioritize high-severity IPS and antivirus alerts.**  
6. **Detect lateral movement** by analyzing internal traffic patterns and port scans.  
7. **Monitor application and web traffic** for policy violations or suspicious activity.  

---


