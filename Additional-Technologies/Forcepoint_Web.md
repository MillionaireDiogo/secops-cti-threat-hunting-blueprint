# Threat Hunting with Forcepoint Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Forcepoint—a leading provider of web security, data loss prevention (DLP), cloud access security broker (CASB), and insider threat solutions. Use these indicators to detect data exfiltration, policy evasion, malware delivery, cloud misuse, and risky user behavior.

## Log Sources
- Forcepoint Web Security Logs  
- DLP Incident Logs  
- CASB/Cloud Security Logs  
- Policy Violation Logs  
- User Activity Logs  
- Threat/Alert Logs  
- Admin Activity Logs  
- API/Integration Logs  

---

## Web & Cloud Activity

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `Denied`, `Blocked`                   | User denied access to websites, cloud apps, or data.     |
| `NewAppDiscovered`, `ShadowIT`        | Detection of unsanctioned or risky cloud apps.           |
| `FileDownload`, `BulkDownload`        | Large or unusual file downloads (possible exfiltration). |
| `FileUpload`, `BulkUpload`            | Unusual uploads—risk of cloud data movement.             |
| `ExternalShare`, `ShareLinkCreated`   | Sharing files/data outside the organization.             |
| `UnusualCloudUsage`, `OffHoursAccess` | Cloud or web use outside of normal patterns/hours.       |

---

## DLP & Policy Violation Events

| **Keyword / Event**                     | **Description / Risk**                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `PolicyViolation`, `DLPIncident`        | Policy or DLP rule violation (e.g., sensitive data moved).|
| `SensitiveDataDetected`, `PII`, `PHI`   | Movement or sharing of confidential data.                |
| `DownloadBlocked`, `UploadBlocked`      | Blocked transfer of risky files or content.              |
| `EncryptionDisabled`                    | Disabling encryption for cloud storage or file transfer. |
| `CategoryBypassAttempt`                 | User attempt to circumvent web or DLP policy.            |

---

## Threat & Malware Detection

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `MalwareDetected`, `VirusDetected`    | Malicious files detected in downloads or web traffic.    |
| `PhishingDetected`, `PhishingBlocked` | Detection/block of phishing sites or emails.             |
| `ExploitKitDetected`                  | Known exploit kits detected in user web sessions.        |
| `DriveByDownload`                     | Indicators of silent/automatic downloads (attack risk).  |

---

## Admin & Integration Events

| **Keyword / Event**                 | **Description / Risk**                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`    | Unusual or failed admin logins.                          |
| `ConfigChange`, `PolicyChange`      | Unauthorized/suspicious configuration or policy changes. |
| `RoleChanged`, `PermissionChanged`  | Unexpected admin/user privilege or role changes.         |
| `APITokenCreated`, `APITokenRevoked`| Creation or revocation of API tokens (abuse risk).       |
| `IntegrationAdded`, `ThirdPartyApp` | New integration or app added—verify legitimacy.          |

---

## Advanced Threat Indicators

- Mass downloads, uploads, or file shares in a short window  
- Multiple DLP/policy violations from the same user or device  
- Rapid discovery and use of unsanctioned cloud apps  
- Disabled encryption or DLP controls  
- Admin or API changes outside business hours  
- Blocked or denied access to critical web/cloud services  
- Repeated malware or phishing alerts tied to user/web activity

---

**Tip:**  
Correlate Forcepoint logs with endpoint, firewall, and identity systems for a comprehensive approach to data security, web/cloud activity, and insider risk.

