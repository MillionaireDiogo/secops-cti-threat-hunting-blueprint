# Threat Hunting with Cisco_Meraki Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Cisco Meraki—a cloud-managed network, wireless, and security platform. Use these indicators to detect unauthorized access, device tampering, policy evasion, and suspicious network activity.

## Log Sources
- Meraki Dashboard Event Logs  
- Security Appliance (MX) Logs  
- Access Point (MR) Logs  
- Switch (MS) Logs  
- VPN & Client VPN Logs  
- Admin Activity Logs  
- Device Registration Logs  
- API/Integration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                    | **Description / Risk**                                   |
| -------------------------------------- | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`  | Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)      | Dashboard or VPN logins from unusual devices/IPs.        |
| `MFABypass`, `MFAEnrollmentRemoved`    | Bypassing or removing multi-factor authentication.       |
| `AccountLocked`, `AccountDisabled`     | Accounts locked/disabled due to suspicious activity.     |
| `AdminLogin`, `FailedAdminLogin`       | Unusual or failed admin logins.                          |
| `NewAdminAdded`, `AdminRoleChanged`    | New admin accounts or privilege escalation.              |

---

## Network Access & Client Activity

| **Keyword / Event**                       | **Description / Risk**                                   |
| ----------------------------------------- | -------------------------------------------------------- |
| `NewDeviceConnected`, `ClientJoin`        | Unknown/unexpected device connection to network.         |
| `MACSpoofing`, `IPConflict`               | Device impersonation or network scanning.                |
| `SSIDChange`, `NetworkChange`             | Unauthorized or suspicious wireless/network config changes.|
| `HighBandwidthUsage`                      | Unusual spikes (possible exfiltration or malware).       |
| `GuestAccessGranted`                      | Unapproved or unexpected guest network use.              |
| `ClientVPNConnection`                     | Unusual VPN sessions or endpoints.                       |
| `DeviceRoaming`                           | Frequent network hopping/location changes.               |
| `BlockedClient`, `AccessDenied`           | Devices denied access (potential scanning or attack).    |

---

## Security & Threat Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `MalwareDetected`, `ThreatAlert`      | Threat or malware detected on client or network.         |
| `IDSAlert`, `IPSAlert`                | Intrusion detection/prevention triggered.                |
| `PolicyViolation`, `AccessBlocked`    | Enforcement of content or security policies.             |
| `UnusualTraffic`, `SuspiciousTraffic` | Traffic anomalies (C2, DGA, tunneling, etc.).            |

---

## Configuration & Admin Events

| **Keyword / Event**                    | **Description / Risk**                                   |
| -------------------------------------- | -------------------------------------------------------- |
| `ConfigChange`, `NetworkChange`        | Unauthorized config or network modifications.            |
| `FirmwareUpdate`, `Rollback`           | Unscheduled or unauthorized firmware changes.            |
| `APIKeyCreated`, `APIKeyRevoked`       | New API keys or revocation—monitor for abuse.            |
| `IntegrationAdded`, `ThirdPartyApp`    | Addition of new integrations (potential for data exposure).|

---

## Advanced Threat Indicators

- Multiple failed logins or admin changes in short window  
- Guest or unknown device spikes on secure networks  
- Rapid configuration or firmware changes  
- IDS/IPS alerts in correlation with high bandwidth/odd traffic  
- VPN access from high-risk geographies  
- Device MAC/IP spoofing detected  
- External integrations with excessive permissions  
- Disabled or bypassed security features/policies

---

**Tip:**  
Correlate Meraki logs with firewall, endpoint, and cloud security monitoring for a full view of campus, branch, and remote network risk.

