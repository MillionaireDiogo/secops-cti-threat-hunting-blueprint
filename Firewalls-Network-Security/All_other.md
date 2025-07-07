# Firewall Threat Hunting Guide Overview

Firewalls are critical perimeter and internal segmentation devices. Effective threat hunting seeks to detect malicious behaviors hidden in the logs that signature-based systems might miss. This guide helps you spot anomalies across connection patterns, rule changes, traffic types, and attacker behaviors.

---

## 2. Log Source Categories

| Log Source                        | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| **Allowed Connection Logs**       | Records of successful inbound/outbound traffic (src/dst IP, port, protocol) |
| **Denied/Blocked Traffic Logs**   | Details of blocked connection attempts, including rule matches               |
| **Firewall Configuration Logs**   | Logs for configuration changes, rule modifications, and admin activities     |
| **User Authentication Logs**      | Logs of user login attempts, especially for admin interfaces (e.g., VPN)     |
| **VPN/Tunnel Events**             | Tunnel initiation/termination and user identity correlation                 |
| **NAT/Translation Logs**          | Network Address Translation events, including port mapping and usage         |
| **IPS/IDS Alerts**                | Inline intrusion prevention events and signatures                           |
| **Traffic Anomaly Metrics**       | Rate-based or volume-based thresholds triggering alerts                      |
| **Geo‑IP/Geolocation Logs**       | Logs indicating unusual country-based traffic                               |
| **Application Layer Logs**        | HTTP/S, DNS, SMTP, FTP metadata and anomalies                               |
| **Management Access Logs**        | CLI/API/Web UI admin access, especially from unusual IPs                     |

---

## 3. Threat Hunting Categories 

### A. Connection & Traffic Anomalies

| Keyword/Metric                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `DENY` or `BLOCK`                 | Indicates rejected traffic — check for repeated blocks from same source      |
| `ALLOW`                           | Successful traffic — analyze for unusual destinations or ports              |
| `unusual_port`                    | Traffic to non-standard ports that deviate from baseline                    |
| `geo_mismatch`                    | Connections from countries never accessed previously                        |
| `dst_port_22`                     | SSH access — focus on sudden increases on internal or external-facing ports |
| `src_ip_reputation`               | Known-bad IPs or threat actor IPs observed in traffic                        |
| `long_duration`                   | Persistent outbound connections (> 1hr)                                     |
| `high_frequency`                  | Burst of short-lived connections indicating scanning or C2 beaconing         |
| `dns_tunnel`                      | Excessive DNS queries or unusually long encoded hostnames                    |
| `protocol_mismatch`               | Non-DNS traffic using DNS ports or vice versa                                |

---

### B. Rule & Config Changes

| Keyword/Event                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `rule_added`                      | New firewall rule — ensure it's audited before allowing behavior            |
| `rule_deleted`                    | Rule removal — could open bypass during offense                             |
| `rule_modified`                   | Changes in port, source/destination — review context                        |
| `admin_login`                     | Web/CLI/API login — particularly from unfamiliar IPs or off-hours           |
| `config_backup`                   | Scheduled backups — unusual or failed attempts may indicate tampering       |
| `firmware_upgrade`                | Unplanned firmware changes or hidden upgrades                               |

---

### C. Authentication & Access Events

| Keyword/Event                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `vpn_login`                       | VPN sessions from unknown users, geographies, or at odd times               |
| `failed_login`                    | Multiple failures indicating brute-force or credential stuffing             |
| `sizelimit_exceeded`              | Unusual session data volumes — low-and-slow exfiltration                   |
| `used_admin_credentials`         | Elevated privilege used from unusual endpoints                              |

---

### D. Lateral Movement & Internal Focus

| Keyword/Event                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `internal_src_conn`               | Firewall allowing internal-to-internal traffic — deviation from policy     |
| `inter_segment_conn`              | Allowed across zones — check segmentation adherence                         |
| `host_scanning`                   | Sequential port scans across internal subnets                              |
| `arp_scan`                        | Unusual ARP floods signaling reconnaissance                                |

---

### E. Threat Intelligence & Reputation

| Keyword/Indicator                 | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `threat_intel_match`             | IP/domain matches from TI feed — correlate to firewall logs                |
| `known_malicious_domain`         | Blocked or allowed access to known bad domains                              |
| `sinkhole_traffic`               | Communication with known sinkholes or C2 destinations                      |
| `ransomware_C2`                  | Beaconing patterns typical of ransomware or malware command infrastructure |

---

### F. Layer 7 / Application Inspection

| Keyword/Event                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `http_url_dns`                    | Suspicious HTTP traffic over non-standard ports or via DNS proxies         |
| `asp_shell_upload`                | Detection of web-shell or suspicious uploads                              |
| `smtp_attachment`                 | Malware distribution via email attachments                               |
| `http_user_agent_anomaly`         | Rare or encoded user agents indicative of scripts                          |
| `proxy_evasion`                   | Bypassing HTTP proxy via tunnels, SSH, or ICMP tunneling                   |

---

### G. Data Exfiltration & Tunneling

| Keyword/Event                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| `large_data_transfer`            | High-volume uploads (> 1GB) outside business hours                         |
| `protocol_tunnel`                | Tunneling using DNS, ICMP, HTTP, or SSH                                   |
| `ssl_certificate_anomaly`        | Self-signed or unusual certs on outbound TLS sessions                     |
| `encrypted_command_channel`      | Persistent encrypted channels on non-standard ports                       |

---

## 4 Recommended Hunting Workflow

1. **Baseline Analysis**  
   Determine normal traffic patterns (ports, geos, protocols).

2. **Focused Alerting**  
   Tune alerts on deny/allow spikes and rule changes.

3. **Context Enrichment**  
   Combine firewall data with TI, asset databases, DHCP, IDPS, VPN logs.

4. **Session Correlation**  
   Track sessions across allow/deny, NAT, VPN logs to map attacker play.

5. **Rule Auditing**  
   Review recent/temporary access rules added/changed.

6. **User & Endpoint Focus**  
   Identify switches to internal critical systems or strange elevated logins.

7. **Behavioral Hunting**  
   Run queries by category (ex: scan detection, geo anomalies, exfil patterns).

---



