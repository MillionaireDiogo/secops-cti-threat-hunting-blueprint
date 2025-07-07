# Threat Hunting with Juniper SRX Firewall Overview

Juniper SRX firewalls provide extensive logging on network traffic, session events, VPN activity, user authentication, NAT, and configuration changes. Their logs offer deep visibility into network behavior, making them useful for detecting lateral movement, scanning, policy violations, and intrusion attempts.

---

## 2. Log Sources

| Log Source                  | Description                                                                |
|----------------------------|----------------------------------------------------------------------------|
| **Firewall Traffic Logs**   | Session allow/deny events with source/destination IPs, ports, protocols    |
| **VPN Logs**                | VPN tunnel establishment, authentication success/failure                  |
| **NAT Logs**                | NAT translations and address mappings                                     |
| **User Authentication Logs**| Login/logout events for admin or VPN users                                |
| **Configuration Change Logs**| Changes in policies, firewall rules, or system configurations            |
| **Intrusion Detection Logs**| IDS/IPS alerts for suspicious or malicious activity                       |
| **System and Device Logs**  | Device health, interface status, and operational events                   |

---

## 3. Threat Hunting Categories & Keywords

### A. Traffic & Connection Anomalies

| Keyword/Field           | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `rt_FLOW_SESSION_CREATE` | New session creation logs — monitor for unusual or unauthorized sessions    |
| `action:deny`           | Denied connection attempts — potential scanning or brute-force             |
| `action:permit`         | Allowed connections — inspect for unusual destinations or ports             |
| `src_ip`                | Source IP — check against reputation and geolocation                        |
| `dst_ip`                | Destination IP — critical assets or unexpected external targets             |
| `dst_port`              | Focus on sensitive or uncommon ports (22, 3389, 445)                        |
| `bytes_in` / `bytes_out`| Large data transfers — possible data exfiltration                           |
| `session_duration`      | Long-lived sessions that may indicate persistence or C2 channels           |

---

### B. VPN & Remote Access

| Keyword/Field           | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `vpn_tunnel_up`         | VPN tunnel establishment — verify legitimate connections                    |
| `vpn_auth_success`      | Successful VPN authentication                                               |
| `vpn_auth_failure`      | Failed VPN login attempts — brute force or credential stuffing indicator    |
| `user`                  | VPN user identity — analyze for abnormal patterns                          |

---

### C. NAT & Address Translation

| Keyword/Field           | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `nat_translation`       | NAT events showing internal to external IP mappings                         |
| `port_forwarding`       | External port forwarding potentially exposing internal services             |

---

### D. Configuration & Policy Changes

| Keyword/Field           | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `policy_add`            | Addition of new firewall policy or rule                                    |
| `policy_modify`         | Modification of existing policies                                          |
| `policy_delete`         | Deletion of policies potentially lowering security                        |
| `admin_login`           | Admin access to firewall management interface                              |
| `failed_admin_login`    | Failed attempts to access admin interface                                  |

---

### E. Intrusion Prevention & Alerts

| Keyword/Field           | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `ids_alert`             | IDS/IPS triggered alerts for exploits or suspicious behavior               |
| `malware_detected`      | Detection of malware or malicious files                                    |
| `exploit_attempt`       | Attempted exploitation of vulnerabilities                                  |

---

### F. Lateral Movement & Internal Traffic

| Keyword/Field           | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `internal_to_internal`  | Unexpected permitted traffic within internal segments                       |
| `port_scan`             | Detection of scanning activity inside the network                          |
| `admin_ports`           | Traffic targeting administrative ports (SSH, RDP, WinRM)                   |

---

## 4. Additional Recommendations

1. **Establish baseline session patterns** and typical allowed traffic.  
2. **Monitor denied connection logs** for scanning or brute-force attempts.  
3. **Analyze VPN logs** for failed and successful authentications.  
4. **Audit firewall policy changes** regularly for suspicious modifications.  
5. **Investigate IDS/IPS alerts** for indications of attacks or malware.  
6. **Detect lateral movement** by inspecting internal traffic flows and port scans.  

---
