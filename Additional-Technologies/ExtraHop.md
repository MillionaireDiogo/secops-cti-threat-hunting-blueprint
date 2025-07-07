# Threat Hunting with ExtraHop Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for ExtraHop—a leading network detection and response (NDR) platform. Use these indicators to detect lateral movement, exfiltration, policy evasion, protocol abuse, and advanced threats on the network.

## Log Sources
- ExtraHop Security & Event Logs  
- Network Flow Logs  
- Protocol Analysis Logs  
- Device/Asset Discovery Logs  
- Threat & Alert Logs  
- Policy Violation Logs  
- Integration/API Logs  
- Admin Activity Logs  

---

## Network & Protocol Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `UnusualPort`, `PortScanDetected`    | Port/protocol scanning, use of non-standard ports.       |
| `ProtocolAnomaly`, `MalformedPacket` | Detection of unexpected or abnormal protocol usage.      |
| `LateralMovement`, `EastWestTraffic` | Unusual or high-volume internal network communications.  |
| `UnencryptedSensitiveData`           | Sensitive data transmitted without encryption.           |
| `SMBExec`, `RemoteCommand`           | Lateral movement via remote exec (e.g., SMB, WMI, RDP).  |
| `C2Traffic`, `BeaconingDetected`     | Communication with command and control (C2) endpoints.   |
| `DNS_Tunneling`, `CovertChannel`     | Use of DNS or other protocols for data exfiltration.     |

---

## Asset Discovery & Behavior

| **Keyword / Event**                     | **Description / Risk**                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `NewDeviceDiscovered`                   | Unrecognized or unmanaged device on the network.         |
| `DeviceTypeChange`, `RoleChange`        | Asset masquerading, device role change.                  |
| `UnusualMAC`, `MACSpoofing`             | MAC address spoofing or impersonation.                   |
| `IPConflict`, `DHCPAnomaly`             | Duplicate IPs, strange DHCP behavior.                    |
| `ShadowITDetected`                      | Unapproved SaaS or cloud services accessed.              |

---

## Application & Data Activity

| **Keyword / Event**                     | **Description / Risk**                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `SensitiveDataTransfer`                 | Large or unauthorized data movement (exfiltration).      |
| `BulkFileTransfer`, `UnusualUpload`     | Mass file transfers, especially to external hosts.       |
| `UnusualDownload`, `BulkDownload`       | Multiple or large downloads (DLP risk).                  |
| `ApplicationAnomaly`, `UnusualAppUsage` | Rare or never-before-seen app usage.                     |
| `HTTP_Tunneling`, `ProxyUsage`          | Use of HTTP or proxy for covert communications.          |

---

## Threat, Policy, & Alert Events

| **Keyword / Event**                 | **Description / Risk**                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `ThreatDetected`, `MalwareAlert`    | Detected malware, exploit, or policy breach.             |
| `RansomwareDetected`                | Indicators of ransomware, e.g., SMB lockout, file renames.|
| `PolicyViolation`                   | Violation of network security or usage policies.         |
| `AlertSuppressed`, `AlertFlood`     | Alert suppression or flooding to mask activity.          |

---

## Admin & Integration Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`      | Unusual or failed admin logins.                          |
| `ConfigChange`, `PolicyChange`        | Unauthorized configuration or policy modifications.      |
| `APITokenCreated`, `APITokenRevoked`  | Creation or revocation of API tokens (integration risk). |
| `IntegrationAdded`, `IntegrationError`| New integrations, or failures in integration/automation. |

---

## Advanced Threat Indicators

- Sequence of port scans, protocol anomalies, and lateral movement  
- Large or repeated internal-to-external data transfers  
- Unrecognized device or asset spikes on the network  
- Burst of alerts or suppressed alerting (alert fatigue or evasion)  
- Use of non-standard apps, proxies, or tunnels for covert communication  
- Ransomware or mass encryption/lockout events  
- Admin changes or API activity outside normal hours

---

**Tip:**  
Correlate ExtraHop logs with firewall, endpoint, SIEM, and threat intelligence for a holistic, real-time view of network-based threats and response.

