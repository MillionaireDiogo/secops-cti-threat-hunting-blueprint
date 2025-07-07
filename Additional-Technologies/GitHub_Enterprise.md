# Threat Hunting with GitHub_Enterprise Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for GitHub Enterprise—an enterprise source control and DevOps platform. Use these indicators to detect account compromise, credential abuse, code/data exfiltration, admin abuse, and risky integrations.

## Log Sources
- GitHub Enterprise Audit Logs  
- User Activity Logs  
- Repo Access Logs  
- Commit & Push Logs  
- Webhook/Integration Logs  
- API Access Logs  
- Admin Activity Logs  
- SAML/SSO Authentication Logs  

---

## Authentication & Access Events

| **Keyword / Event**                     | **Description / Risk**                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`   | Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)       | Logins from new devices, IPs, or geographies.            |
| `MFABypass`, `MFAEnrollmentRemoved`     | Bypassing or removing multi-factor authentication.       |
| `SAMLSSOFailed`, `SSOFailure`           | SSO errors—potential abuse or misconfiguration.          |
| `SessionHijack`, `SessionExtended`      | Suspicious session reuse or extension.                   |

---

## Repository & Code Activity

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `RepoCloned`, `BulkClone`             | Mass cloning of repositories (potential exfiltration).   |
| `MassDownload`, `ArchiveExport`       | Download/export of many files or whole repos.            |
| `ForcePush`, `BranchDeleted`          | Overwriting/deleting history (covering tracks).          |
| `SensitiveFileAccessed`               | Access to secrets, keys, or sensitive files.             |
| `SecretPushed`, `CredentialLeaked`    | Secrets or credentials pushed to repo/codebase.          |
| `LargeCommit`, `BulkCommit`           | Commits with large data or many files (possible dump).   |
| `FileDeleted`, `FileRestored`         | Deleting/restoring files to cover tracks.                |

---

## Collaboration, Sharing & Integration Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `RepoShared`, `CollaboratorAdded`    | Unexpected sharing or adding external collaborators.     |
| `OrgInviteSent`, `BulkInvite`        | Bulk invites to users (especially to externals).         |
| `PermissionChanged`                  | Privilege escalation or reduction of oversight.          |
| `WebhookCreated`, `IntegrationAdded` | New webhooks/integrations (possible data exfiltration).  |
| `APITokenCreated`, `APITokenRevoked` | Creation/revocation of API tokens (automation risk).     |
| `ThirdPartyAppAuthorized`            | New third-party app access (review for risk).            |

---

## Admin & Configuration Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`     | Unusual or failed admin logins.                          |
| `ConfigChange`, `PolicyChange`       | Unauthorized config or policy modifications.             |
| `OrgSettingsChanged`                 | Changes to organization settings (visibility, access).   |
| `AuditLogCleared`, `LogDeleted`      | Deletion of logs/audit trails (covering tracks).         |

---

## Threat & Advanced Indicators

- Bulk repo clone/download activity from one user/IP  
- Sensitive data (keys, secrets) committed to public/private repos  
- Mass collaborator or admin role changes in short time  
- Rapid webhook or integration creation  
- Repeated failed logins or SSO errors  
- Deletion of audit logs or repo history  
- Unexpected sharing/invitation of external accounts  
- New third-party app authorizations without business case

---

**Tip:**  
Correlate GitHub logs with endpoint, DLP, and identity monitoring for full-lifecycle DevOps/code security and insider risk detection.

