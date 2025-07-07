# Threat Hunting with Bitglass Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Bitglass—a Cloud Access Security Broker (CASB) and data protection platform. Use these indicators to monitor cloud app usage, detect data exfiltration, policy evasion, and insider threats.

## Log Sources
- Bitglass Admin Console Logs  
- Cloud App Activity Logs  
- Policy Violation Logs  
- User Access Logs  
- DLP Incident Logs  
- Integration/API Logs  
- Threat/Alert Logs  

---

## Authentication & Access Events

| **Keyword / Event**                     | **Description / Risk**                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`   | Multiple/repeated failed logins (brute force).           |
| `SuccessfulLogin` (New Device/IP)       | Logins from unexpected devices, IPs, or geolocations.    |
| `MFABypass`, `MFAEnrollmentRemoved`     | Bypassing or removing multi-factor authentication.       |
| `SessionHijack`                         | Suspicious session persistence or reuse.                 |
| `DeviceRegistration`                    | Unusual device registration or new endpoints.            |

---

## Cloud App & SaaS Activity

| **Keyword / Event**                  | **Description / Risk**                                    |
| ------------------------------------ | --------------------------------------------------------- |
| `NewAppDiscovered`                   | Detection of unsanctioned/shadow IT cloud apps.           |
| `AppAccessed` (Unusual/Off-hours)    | Accessing cloud apps outside normal patterns.             |
| `DataDownload`, `DataUpload`         | Large/bulk downloads or uploads (possible exfiltration).  |
| `AppSharing`, `ShareLinkCreated`     | Unexpected sharing of files/data via cloud apps.          |
| `AnomalousAppUsage`                  | App usage not typical for user/role/location.             |
| `ThirdPartyIntegrationAdded`         | Addition of unsanctioned third-party integrations.        |

---

## DLP & Policy Violation Events

| **Keyword / Event**                     | **Description / Risk**                                      |
| --------------------------------------- | ----------------------------------------------------------- |
| `PolicyViolation`                       | Triggered by risky data movements or access.                |
| `SensitiveDataExposed`                  | Detection of PII, PHI, PCI, or confidential data.           |
| `DLPIncident`, `DLPBlocked`             | DLP events—data transfer or sharing blocked/stopped.        |
| `DownloadBlocked`, `UploadBlocked`      | Prevented data transfer actions.                            |
| `EncryptionDisabled`                    | Disabling of data encryption for cloud storage/apps.        |

---

## Admin & Privilege Events

| **Keyword / Event**                 | **Description / Risk**                                 |
| ----------------------------------- | ------------------------------------------------------ |
| `AdminCreated`, `AdminRemoved`      | Privilege escalation or reduction of oversight.        |
| `RoleChanged`, `PermissionChanged`  | Unexpected changes in permissions/roles.               |
| `BulkUserProvisioning`              | Rapid creation or removal of user accounts.            |

---

## Threat, Alert & Integration Monitoring

| **Keyword / Event**         | **Description / Risk**                                 |
| --------------------------- | ------------------------------------------------------ |
| `MalwareDetected`           | Malware events triggered in cloud files or traffic.    |
| `PhishingDetected`          | Phishing links/files in cloud app usage.               |
| `ThreatAlert`               | General risk and security alerts.                      |
| `APITokenCreated`           | New API tokens (automation abuse risk).                |
| `APIAccessDenied`           | Multiple failed API authentication attempts.           |
| `IntegrationAdded`          | New integrations (possible for data exposure).         |

---

## Advanced Threat Indicators

- Multiple cloud DLP or threat alerts in short timeframe  
- Mass downloads/uploads of data, especially outside business hours  
- New/unapproved cloud app integrations or third-party add-ons  
- Privileged/admin actions from suspicious IPs or countries  
- Rapid addition/removal of users, roles, or permissions  
- Disabling DLP, encryption, or policy enforcement features  
- Multiple policy violations involving sensitive data

---

**Tip:**  
Correlate Bitglass logs with cloud provider, endpoint, and identity sources for a complete view of SaaS/cloud security risk.

