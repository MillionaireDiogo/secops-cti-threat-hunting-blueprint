# Threat Hunting with Armis_Security Overview

This file provides threat hunting keywords, suspicious activity indicators, and log sources for Armis Security—a platform focused on asset visibility, IoT, OT, and unmanaged device security. Use these indicators to detect risks, unauthorized activity, and threats in connected environments.

## Log Sources
- Armis Console Event Logs  
- Asset Inventory Logs  
- Device Activity & Behavior Logs  
- Policy Violation Logs  
- Integration/API Logs  
- Alert/Incident Logs  
- Network Traffic Logs (from Armis sensors)  

---

## Asset Discovery & Device Registration

| **Keyword / Event**                   | **Description / Risk**                                    |
| ------------------------------------- | --------------------------------------------------------- |
| `NewDeviceDiscovered`                 | Unrecognized device detected on network.                  |
| `DeviceTypeChanged`                   | Asset misidentification (potential device spoofing).      |
| `UnmanagedDeviceActivity`             | Activity from devices not enrolled in corporate policies. |
| `DeviceClassificationChanged`         | Asset reclassification (could hide rogue devices).        |
| `DeviceAddedToGroup`, `DeviceRemovedFromGroup` | Device moved to/from monitored groups (policy evasion). |

---

## Authentication & Access Events

| **Keyword / Event**               | **Description / Risk**                                 |
| --------------------------------- | ------------------------------------------------------ |
| `UnauthorizedAccess`              | Device attempted access to restricted assets.          |
| `AccessDenied`                    | Denied access events (probing, recon).                 |
| `UnusualLoginLocation`            | Authentication from unexpected location/IP.            |
| `PrivilegeEscalation`             | Devices/users gaining elevated access.                 |

---

## Policy & Compliance Events

| **Keyword / Event**             | **Description / Risk**                                      |
| ------------------------------- | ----------------------------------------------------------- |
| `PolicyViolation`               | Device violated corporate or network security policy.       |
| `ComplianceStatusChanged`       | Asset suddenly non-compliant (configuration drift/attack).  |
| `PolicyChanged`, `PolicyDisabled`| Changes to or disabling of enforced security policies.      |

---

## Device Behavior & Threat Detection

| **Keyword / Event**                     | **Description / Risk**                                     |
| --------------------------------------- | ---------------------------------------------------------- |
| `AnomalousActivity`                     | Behavior deviating from device's normal pattern.           |
| `UnusualDataTransfer`                   | Large or unexpected data transfer (possible exfiltration). |
| `LateralMovementDetected`               | Attempts to access multiple network segments.              |
| `CommandAndControl`                     | Indicators of device communicating with known C2.          |
| `MalwareDetected`, `RansomwareDetected` | Malware, ransomware, or exploit attempts detected.         |
| `PortScanDetected`                      | Device performing reconnaissance on local network.         |
| `UnusualProtocolUsage`                  | Use of non-standard protocols (exfiltration/tunneling).    |

---

## Integration & API Monitoring

| **Keyword / Event**         | **Description / Risk**                                 |
| --------------------------- | ------------------------------------------------------ |
| `APIKeyCreated`             | New API key created (integration abuse risk).          |
| `APIAccessDenied`           | Multiple failed API authentication attempts.           |
| `IntegrationAdded`          | Addition of new integration—check for legitimacy.      |
| `WebhookCreated`            | New webhooks (possible for exfiltration/alert bypass). |

---

## Advanced Threat Indicators

- Burst of new device discoveries in short time window  
- Devices moving between trusted/untrusted VLANs  
- Mass compliance status change (many assets non-compliant)  
- Multiple devices with identical MAC/IP addresses (spoofing)  
- Device communication with known malicious IPs/domains  
- Large-scale asset type reclassification  
- Alert suppression or disabling of notification channels

---

**Tip:**  
Correlate Armis logs with SIEM, firewall, and network flow data for end-to-end IoT/OT risk monitoring and incident response.

