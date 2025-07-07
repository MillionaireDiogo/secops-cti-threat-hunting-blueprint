# Threat Hunting with Dashlane Overview

This file outlines threat hunting keywords, suspicious activities, and log sources for Dashlane—a cloud-based password manager. Use these indicators to monitor for account compromise, insider threats, policy bypass, and risky credential management behavior.

## Log Sources
- Dashlane Admin Console Logs  
- User Activity & Access Logs  
- Audit Logs  
- Device Registration Logs  
- Failed Authentication Logs  
- API/Integration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple failed logins (brute force attempts).           |
| `SuccessfulLogin` (New Device/IP)    | Logins from unexpected devices, IPs, or geolocations.    |
| `MFABypass`, `MFAEnrollmentRemoved`  | Multi-factor bypass or removal (risk of compromise).     |
| `DeviceAdded`                        | New device added to account.                             |
| `DeviceRemoved`                      | Device removed—check if not user-initiated.              |

---

## Vault & Credential Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `PasswordExported`, `ExportVault`    | Bulk export of passwords (possible exfiltration).        |
| `CredentialCopied`                   | Copying sensitive data (look for bulk or odd-hours).     |
| `ItemShared`, `ShareInviteSent`      | Unexpected sharing or invites to external parties.       |
| `DeleteItem`, `RestoreItem`          | Deleting/restoring credentials (cover tracks or misuse). |
| `BulkItemAccess`                     | Multiple credentials accessed in a short period.         |

---

## Admin & Privilege Events

| **Keyword / Event**                 | **Description / Risk**                                 |
| ----------------------------------- | ------------------------------------------------------ |
| `AdminAccountCreated`, `Removed`    | Privilege escalation or reduction of oversight.        |
| `RoleChanged`, `PermissionChanged`  | Unexpected changes in permissions/roles.               |
| `InviteAdmin`, `InviteTeamMember`   | Bulk or unusual invitations.                           |

---

## Integration & API Monitoring

| **Keyword / Event**         | **Description / Risk**                                 |
| --------------------------- | ------------------------------------------------------ |
| `APITokenCreated`           | Creation of API tokens (check necessity/legitimacy).   |
| `APITokenRevoked`           | Token revocation (verify not suspicious).              |
| `IntegrationAdded`          | New integrations (possible third-party data exposure). |
| `FailedAPIAccess`           | Failed API authentications—possible brute force.       |

---

## Advanced Threat Indicators

- Mass export or copying of credentials  
- Device additions/removals at abnormal hours  
- Rapid admin changes or role escalations  
- Sharing credentials with untrusted or external domains  
- Bulk credential access or export  
- Disabling or tampering with audit logging

---

**Tip:**  
Correlate Dashlane audit logs with endpoint, email, and network alerts to catch early signs of abuse or compromise.

