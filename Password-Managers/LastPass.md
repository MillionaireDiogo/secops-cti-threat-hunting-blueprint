# Threat Hunting with LastPass Overview

This file covers threat hunting keywords, suspicious activities, and log sources for LastPass—a cloud-based enterprise password manager. Use these indicators to detect account compromise, insider threats, policy evasion, and risky credential behaviors.

## Log Sources
- LastPass Admin Console Logs  
- User Activity Logs  
- Audit Logs  
- Device Registration Logs  
- Failed Authentication Logs  
- API/Integration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)    | Access from new/unexpected devices, IPs, or geolocations.|
| `MFABypass`, `MFAEnrollmentRemoved`  | Multi-factor bypass or removal (risk of compromise).     |
| `DeviceAdded`, `DeviceRegistered`    | New device registration—watch for suspicious activity.   |
| `DeviceRemoved`, `DeviceDeauthorized`| Device removal—especially if not user-initiated.         |

---

## Vault & Credential Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `ExportVault`, `VaultExported`       | Bulk export of vault/secrets (possible exfiltration).    |
| `CredentialCopied`, `ItemCopied`     | Copying sensitive credentials (in bulk or off-hours).    |
| `ShareItem`, `ItemShared`            | Unexpected sharing of vaults/items or invites to externals.|
| `DeleteItem`, `RestoreItem`          | Deleting/restoring credentials to cover tracks/misuse.   |
| `BulkItemAccess`                     | Mass access to credentials in short period.              |

---

## Admin & Privilege Events

| **Keyword / Event**                 | **Description / Risk**                                 |
| ----------------------------------- | ------------------------------------------------------ |
| `AdminCreated`, `AdminRemoved`      | Privilege escalation or reduction of oversight.        |
| `RoleChanged`, `PermissionChanged`  | Changes in permissions/roles, especially for admins.   |
| `InviteAdmin`, `InviteUser`         | Bulk or suspicious invitations (especially to externals).|

---

## Integration & API Monitoring

| **Keyword / Event**         | **Description / Risk**                                 |
| --------------------------- | ------------------------------------------------------ |
| `APITokenCreated`           | New API tokens (potential automation abuse).           |
| `APITokenRevoked`           | Token removal (confirm if legitimate).                 |
| `IntegrationAdded`          | New integrations (possible third-party data exposure). |
| `FailedAPIAccess`           | Failed API authentications (possible brute force).     |

---

## Advanced Threat Indicators

- Mass export or copying of credentials  
- Device additions/removals at abnormal hours  
- Rapid admin changes or role escalations  
- Sharing credentials or vaults with untrusted/external users  
- Bulk credential access or export  
- Disabling or tampering with audit logging  
- Credential access from unusual locations or at odd hours  
- Repeated failed logins from same IP/device

---

**Tip:**  
Correlate LastPass audit logs with endpoint, email, and network monitoring for early detection of abuse or compromise.

