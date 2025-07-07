# Threat Hunting with Claroty Overview

This file covers threat hunting keywords, suspicious activities, and log sources for Claroty—an operational technology (OT), industrial control systems (ICS), and IoT security platform. Use these indicators to detect network intrusions, policy violations, anomalous device behavior, and advanced threats in industrial environments.

## Log Sources
- Claroty Platform Security Event Logs  
- Asset Inventory & Discovery Logs  
- Network Traffic Logs  
- Policy Violation Logs  
- Vulnerability & Risk Reports  
- Integration/API Logs  
- Admin/Configuration Change Logs  
- Incident/Alert Logs  

---

## Asset Discovery & Device Events

| **Keyword / Event**                    | **Description / Risk**                                      |
| -------------------------------------- | ----------------------------------------------------------- |
| `NewAssetDiscovered`                   | Unrecognized device or asset detected on network.           |
| `DeviceTypeChanged`                    | Device reclassified (possible masquerade/spoofing).         |
| `UnmanagedDeviceActivity`              | Activity from unmanaged or rogue assets.                    |
| `MACAddressConflict`, `IPConflict`     | Potential spoofing, scanning, or asset collision.           |
| `FirmwareChanged`                      | Unexpected firmware update on critical device.              |

---

## Network & Communication Events

| **Keyword / Event**                 | **Description / Risk**                                     |
| ----------------------------------- | ---------------------------------------------------------- |
| `UnusualNetworkConnection`          | Device communication with new or external endpoints.        |
| `ProtocolAnomaly`                   | Use of non-standard or unauthorized protocols.              |
| `PortScanDetected`                  | Scanning/reconnaissance activity detected.                  |
| `LateralMovementDetected`           | Attempted movement between network segments or zones.       |
| `CommandAndControl`                 | Communication with known C2 infrastructure.                 |
| `BroadcastStorm`                    | Network flooding (possible DoS or misconfig).               |

---

## Policy, Compliance & Threat Events

| **Keyword / Event**                 | **Description / Risk**                                     |
| ----------------------------------- | ---------------------------------------------------------- |
| `PolicyViolation`                   | Device or user breached security policy.                   |
| `ComplianceStatusChanged`           | Asset suddenly non-compliant (possible attack/compromise). |
| `CriticalVulnerabilityDetected`     | New high-severity vulnerability identified.                |
| `MalwareDetected`, `ExploitAttempt` | Malicious activity or exploitation detected.               |
| `UnauthorizedCommand`               | Device received/attempted command outside normal range.    |
| `DataExfiltrationAttempt`           | Large or unusual outbound data flows.                      |

---

## Admin, Configuration & Integration Events

| **Keyword / Event**                 | **Description / Risk**                                     |
| ----------------------------------- | ---------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`    | Unusual or failed admin logins.                            |
| `ConfigChange`, `PolicyChange`      | Unauthorized changes to configurations or policies.        |
| `IntegrationAdded`, `APIKeyCreated` | New integrations or API tokens (monitor for abuse).        |
| `LoggingDisabled`                   | Logging/auditing disabled (possible cover-up).             |

---

## Advanced Threat Indicators

- Burst of new asset discoveries or device changes  
- Device communication with known malicious or external IPs  
- Lateral movement or multiple devices breaching segmentation  
- Mass compliance status changes (many devices non-compliant)  
- Large outbound data flows or protocol anomalies  
- Repeated policy violations or threat alerts  
- Firmware or configuration changes outside maintenance windows  
- Disabling of monitoring/logging features

---

**Tip:**  
Correlate Claroty logs with firewall, SIEM, and network infrastructure logs for unified monitoring across IT and OT environments.

