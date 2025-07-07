# Threat Hunting with Check Point Firewall Overview

Check Point Firewalls provide rich logging for traffic filtering, VPN tunnels, user authentication, and policy changes. Their logs contain granular info about allowed/blocked traffic, threat prevention, user identities, and admin actions, making them ideal for threat hunting at network perimeter and internal segmentation points.

---

## 2. Log Sources (Check Point SmartLog / SmartEvent / Log Export)

| Log Source                        | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| **Firewall Traffic Logs**         | Records allowed/denied network sessions with source/dest IP, ports, protocols |
| **Threat Prevention Logs**        | Intrusion prevention, IPS, antivirus, anti-bot, anti-spam event logs         |
| **VPN Logs**                     | VPN connection start/stop, authentication success/failure                   |
| **User Authentication Logs**      | User logins, identity awareness, and Active Directory integration events    |
| **Policy and Rule Changes**       | Logs of firewall rule additions, deletions, or modifications                 |
| **Management Access Logs**        | CLI, Web UI, API admin login attempts and commands                           |
| **NAT Logs**                     | Source/destination NAT translation events                                   |
| **Identity Awareness Logs**       | User identity mappings to IP addresses, login/logout events                 |
| **Application Control Logs**      | Traffic classified by application, with allowed/blocked actions             |

---

## 3. Threat Hunting Categories 

### A. Traffic & Connection Anomalies

| Keyword/Field                     | Description                                                                |
|-----------------------------------|----------------------------------------------------------------------------|
| `action:Drop`                    | Firewall dropped/blocked connection — check for repeated drop from same src|
| `action:Accept`                  | Allowed traffic — hunt for unusual destinations or services                |
| `service:Any`                   | Broad service allowed — often too permissive                              |
| `dst_port:22`                   | SSH traffic, often targeted for brute-force or lateral movement            |
| `src_ip`                       | Source IP, correlate with reputation or geo-location                       |
| `dst_ip`                       | Destination IP, focus on critical assets or unusual external IPs           |
| `session_duration`              | Long-lived sessions which might indicate beaconing or persistent channels  |
| `bytes_sent` / `bytes_received` | Large data transfers possibly indicating data exfiltration                |
| `protocol`                     | Focus on uncommon or suspicious protocols (e.g., SMB, RDP on non-standard ports) |

---

### B. Policy & Configuration Changes

| Keyword/Event                    | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| `rule_added`                   | New firewall rule added — verify legitimacy                              |
| `rule_modified`                | Rule modified, especially for ports, sources, or destination IPs          |
| `rule_deleted`                 | Rule removal could signal attacker pivot or misconfiguration              |
| `policy_install`               | Policy installation event — verify if expected or unexpected              |
| `admin_login`                  | Management login, especially from unknown IP or during off-hours           |
| `config_backup`                | Configuration backup or export activity                                   |
| `threat_prevention_enabled`   | Changes to threat prevention features (enabled/disabled)                  |

---

### C. User Identity & Authentication

| Keyword/Event                    | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| `user_authentication:Success` | Successful user login via VPN or identity awareness                       |
| `user_authentication:Failure` | Failed login attempts indicating brute force or credential stuffing       |
| `identity_aware`               | User-to-IP mapping logs used to tie user actions to network sessions      |
| `privileged_user`              | Elevated users performing administrative tasks                            |
| `vpn_connect`                  | VPN connection established or terminated                                  |

---

### D. Threat Prevention & Intrusion Events

| Keyword/Event                    | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| `threat_name`                  | Detected threat signature or malware name                                |
| `attack_type`                  | Type of attack (exploit, brute-force, malware, botnet, etc.)              |
| `severity`                    | Threat severity (high, medium, low) — prioritize accordingly             |
| `malware_detected`             | Malware or virus detection                                                |
| `exploit_attempt`              | Exploit blocked by IPS                                                   |
| `botnet_activity`              | Traffic identified as C2 communication                                   |
| `sandbox_detection`            | Suspicious files or behaviors flagged in sandbox                          |

---

### E. VPN & Remote Access

| Keyword/Event                    | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| `vpn_login_success`            | Successful VPN user connection                                           |
| `vpn_login_failure`            | Failed VPN connection attempts                                            |
| `tunnel_established`           | VPN tunnel start                                                        |
| `tunnel_terminated`            | VPN tunnel end                                                          |
| `multiple_failed_logins`       | Repeated authentication failures — brute force indicator                  |

---

### F. NAT & Address Translation

| Keyword/Event                    | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| `nat_translation`              | Source or destination NAT translation events                            |
| `port_forwarding`              | Unusual or unauthorized port forwarding rules                           |
| `unexpected_external_ip`       | Internal IP mapped to unexpected external IP                             |

---

### G. Lateral Movement & Internal Traffic

| Keyword/Event                    | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| `internal_to_internal`         | Allowed traffic between internal segments that might violate policy      |
| `admin_ports`                  | Access to administrative ports (3389, 5985, 22) within internal network  |
| `sequential_port_scan`         | Scan activity within internal subnets                                   |
| `suspicious_process`           | Application or service traffic indicating possible lateral movement      |

---

### H. Application & URL Control

| Keyword/Event                    | Description                                                               |
|---------------------------------|---------------------------------------------------------------------------|
| `application_blocked`          | Blocked application traffic indicating policy enforcement                 |
| `application_allowed`          | Allowed risky or unexpected application traffic                          |
| `url_category`                 | Suspicious or unclassified URL category access                          |
| `file_download`                | Potentially malicious file downloads over HTTP/HTTPS                     |

---

## 4. Additional Recommendation

1. **Baseline Normal Traffic:** Understand typical source/destination IPs, ports, user VPN activity.  
2. **Monitor Denied Connections:** Look for repeated denied connections that might indicate scanning or brute force.  
3. **Correlate Identity & Traffic:** Use identity awareness logs to tie network activity to specific users.  
4. **Review Policy Changes:** Audit firewall rule changes for potential attacker manipulation.  
5. **Investigate VPN Logins:** Detect anomalous VPN logins by time, geography, or user behavior.  
6. **Focus on Threat Prevention Logs:** Prioritize high-severity malware or exploit attempts.  
7. **Detect Lateral Movement:** Look for unexpected internal communications or admin port usage.  
8. **Leverage Threat Intelligence:** Cross-reference IPs and domains with external threat feeds.  

---
