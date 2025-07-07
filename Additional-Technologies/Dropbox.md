# Threat Hunting with Dropbox Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Dropbox—a cloud file storage, sharing, and collaboration platform. Use these indicators to detect data exfiltration, account compromise, risky sharing, and insider threats.

## Log Sources
- Dropbox Admin Console Logs  
- User Activity Logs  
- File Access & Activity Logs  
- Sharing & Collaboration Logs  
- API/Integration Logs  
- DLP/Policy Violation Logs  
- Device Registration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)    | Logins from new or unusual devices, IPs, or locations.   |
| `MFABypass`, `MFAEnrollmentRemoved`  | Bypassing or removing multi-factor authentication.       |
| `DeviceAdded`, `DeviceRemoved`       | Unusual device registrations or removals.                |
| `SessionHijack`, `SessionExtended`   | Suspicious session reuse or keep-alive.                  |

---

## File & Folder Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FileDownloaded`, `BulkDownload`     | Large or bulk file downloads (possible exfiltration).    |
| `FileUploaded`, `BulkUpload`         | Bulk uploads, especially to new folders.                 |
| `FileDeleted`, `FileRestored`        | Deleting/restoring files—potential data theft/cover-up.  |
| `FilePreviewed`, `ItemAccessed`      | Mass or off-hours file previews or accesses.             |
| `FileCopied`, `ItemCopied`           | Copying files/folders (especially sensitive, in bulk).   |

---

## Sharing & Collaboration Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `ShareLinkCreated`, `PublicLink`     | Creation of public/open share links (exposure risk).     |
| `ExternalShare`, `ExternalCollab`    | Sharing files/folders with external users/domains.       |
| `PermissionChanged`                  | Granting elevated permissions to users/groups.           |
| `InviteSent`, `CollaborationInvite`  | Bulk or unusual invites, especially to externals.        |
| `UnusualSharingPattern`              | Sharing to new/untrusted domains or mass sharing.        |

---

## DLP & Policy Violations

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `PolicyViolation`                    | DLP trigger—sensitive data exposure or movement.         |
| `SensitiveDataShared`                | Detection of PII/PHI/PCI or confidential info sharing.   |
| `SharingPolicyChanged`               | Changes to sharing/visibility settings (bypass risk).    |
| `DownloadBlocked`, `UploadBlocked`   | Blocked file transfers by policy.                        |

---

## Admin & Integration Events

| **Keyword / Event**                  | **Description / Risk**
