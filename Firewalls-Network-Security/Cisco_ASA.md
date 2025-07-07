# Threat Hunting with Cisco ASA Firewall Overview

Cisco ASA (Adaptive Security Appliance) firewalls log extensive information about network sessions, connections allowed/denied, VPN activity, NAT, and administrative events. These logs help detect lateral movement, unauthorized access attempts, data exfiltration, and policy changes.

---

## 2. Log Sources (Syslog from Cisco ASA)

| Log Source                     | Description                                                                  |
|-------------------------------|------------------------------------------------------------------------------|
| **Traffic Logs**               | Records of allowed and denied connections, including source/destination IPs, ports, protocols |
| **VPN Logs**                  | Details on VPN tunnel establishment, authentication success/failures         |
| **NAT Logs**                  | Network Address Translation events                                           |
| **Authentication Logs**        | User login/logout to management interfaces or VPN                            |
| **Configuration Change Logs** | Rule additions, deletions, or policy changes                                |
| **Intrusion Alerts**          | Integrated IDS/IPS alerts, signature detections                             |
| **System Events**             | Device health, reboot, interface status                                     |

---

## 3. Threat Hunting Categories & Keywords

### A. Traffic & Connection Anomalies

| Keyword/Field               | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `%ASA-4-106023`            | Denied TCP connection from outside to inside — common for scanning/brute-force |
| `%ASA-6-302013`            | Built inbound TCP connection (allowed) — monitor for suspicious ports/destinations |
| `src_ip`                   | Source IP address — check for suspicious or known-malicious IPs             |
| `dst_ip`                   | Destination IP address — watch critical assets or unusual external targets  |
| `dst_port`                 | Destination port — focus on unexpected or high-risk ports (22, 3389, 445)   |
| `protocol`                 | Network protocol used (TCP, UDP, ICMP) — anomalous protocols may be suspect |
| `bytes_sent` / `bytes_received` | High volume traffic could indicate data exfiltration                       |
| `long_duration`            | Sessions lasting unusually long may indicate persistent connections or C2   |
| `%ASA-6-302014`            | Built outbound TCP connection — useful for spotting unusual outbound access |

---

### B. VPN & Remote Access

| Keyword/Field               | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `%ASA-6-302015`            | VPN tunnel established — monitor for unusual user or times                  |
| `%ASA-6-302016`            | VPN tunnel terminated                                                      |
| `%ASA-6-302021`            | VPN authentication success                                                 |
| `%ASA-6-302022`            | VPN authentication failure — brute force or credential stuffing indicator  |
| `vpn_user`                 | User connected via VPN — look for unusual logins or geolocations           |

---

### C. NAT & Address Translation

| Keyword/Field               | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `%ASA-6-302010`            | NAT translation event — monitor for unusual or unauthorized mappings        |
| `port_forwarding`           | Forwarding rules that expose internal services externally                   |

---

### D. Configuration & Policy Changes

| Keyword/Field               | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `%ASA-6-111008`            | Configuration changed by user — verify legitimacy                          |
| `config_backup`             | Backups or exports of configuration files                                  |
| `admin_login`               | Management interface logins (SSH, ASDM, Console) — focus on unusual sources |
| `failed_login`              | Failed admin login attempts — possible brute-force                          |

---

### E. Intrusion Prevention & Alerts

| Keyword/Field               | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| IDS/IPS alerts             | Signature-based detections, blocked exploits                               |
| `malware_detected`          | Malware or virus alerts from integrated IPS                                |
| `exploit_attempt`           | Attempts to exploit vulnerabilities blocked by firewall                   |

---

### F. Lateral Movement & Internal Scanning

| Keyword/Field               | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| `sequential_port_scan`     | Series of denied connection attempts scanning internal IP ranges           |
| `internal_to_internal`     | Unexpected internal traffic between segments                              |
| `admin_ports`              | Traffic to management ports internally (3389, 22, 5985)                    |

---

## 4. Additional Recommendation

1. **Monitor denied connection logs** for brute-force or scanning (`%ASA-4-106023`).  
2. **Analyze allowed connections** for anomalous destination IPs or ports (`%ASA-6-302013`, `%ASA-6-302014`).  
3. **Review VPN authentication logs** for unusual user activity or failed attempts.  
4. **Track NAT translations** to detect unexpected external exposure.  
5. **Audit configuration changes** to detect suspicious modifications or unauthorized access.  
6. **Correlate IDS/IPS alerts** for exploit or malware detection.  
7. **Detect lateral movement** through sequential port scanning or unexpected internal connections.  

---
