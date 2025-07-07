# Threat Hunting with Box Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Box—a cloud content management and file sharing service. Use these indicators to detect data exfiltration, account compromise, insider threats, and risky sharing or collaboration activity.

## Log Sources
- Box Admin Console Logs  
- User Activity Logs  
- Collaboration and Sharing Logs  
- File Access Logs  
- API/Integration Logs  
- DLP/Policy Violation Logs  
- Device Registration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple failed logins—possible brute force attempts.    |
| `SuccessfulLogin` (New Device/IP)    | Logins from unusual devices, IPs, or locations.          |
| `MFABypass`, `MFAEnrollmentRemoved`  | Bypassing or removing multi-factor authentication.       |
| `DeviceAdded`, `DeviceRemoved`       | Unusual device registrations or removals.                |
| `SessionHijack`                      | Suspicious session extension or reuse.                   |

---

## File & Folder Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FileDownloaded`, `BulkDownload`     | Large or bulk downloads (possible data exfiltration).    |
| `FileUploaded`, `BulkUpload`         | Bulk uploads, especially to new or unmonitored folders.  |
| `FileDeleted`, `FileRestored`        | Deleting/restoring files—covering tracks or misuse.      |
| `FilePreviewed`, `ItemAccessed`      | Large volume or odd-hours file previews/access.          |
| `FileCopied`, `ItemCopied`           | Copying sensitive files/folders, especially in bulk.     |

---

## Collaboration & Sharing Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `ShareLinkCreated`, `PublicSharedLink`| Creation of public or open share links (risk of exposure).|
| `ExternalCollabAdded`                | Adding external collaborators or domains.                |
| `PermissionChanged`                  | Granting elevated permissions to users/groups.           |
| `CollaborationInviteSent`            | Bulk or suspicious invites, especially to externals.     |
| `UnusualSharingPattern`              | Sharing to new domains or mass sharing activity.         |

---

## DLP & Policy Violations

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `PolicyViolation`                    | DLP triggers—sensitive data movement or exposure.        |
| `SensitiveDataShared`                | Detection of PII/PHI/PCI or confidential info sharing.   |
| `SharingPolicyChanged`               | Changes to sharing/visibility settings (bypass risk).    |
| `DownloadBlocked`, `UploadBlocked`   | Blocked file transfers (DLP enforcement).                |

---

## Admin & Integration Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`     | Unusual or failed admin logins.                          |
| `RoleChanged`, `PermissionChanged`   | Unexpected changes in user roles or admin privileges.     |
| `IntegrationAdded`, `AppIntegration` | New app integrations (risk of data exposure).            |
| `APITokenCreated`, `APITokenRevoked` | API tokens created or revoked (watch for abuse).         |

---

## Advanced Threat Indicators

- Mass file/folder downloads, uploads, or deletions  
- Sharing sensitive data via public or open links  
- Addition of external collaborators not previously seen  
- Rapid permission escalations or role changes  
- Multiple DLP/policy violations in short timeframe  
- Suspicious device additions/removals  
- Integration of new apps or APIs with broad permissions  
- Logins, shares, or downloads from unusual geographies or IPs

---

**Tip:**  
Correlate Box logs with endpoint DLP, email, and SIEM alerts for end-to-end data movement and insider risk detection.

