# Threat Hunting with Keeper_Security Overview

This file covers threat hunting keywords, suspicious activities, and log sources for Keeper Security—a cloud-based password manager. Use these indicators to identify compromise, policy bypass, insider threats, and risky credential management behavior.

## Log Sources
- Keeper Admin Console Logs  
- Keeper Audit Logs  
- User Activity & Access Logs  
- Device Registration Logs  
- Failed Authentication Logs  
- API/Integration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)    | Access from new/unexpected devices, IPs, geolocations.   |
| `MFABypass`, `MFAEnrollmentRemoved`  | Multi-factor bypass or removal (risk of compromise).     |
| `DeviceAdded`                        | New device registration—watch for suspicious activity.   |
| `DeviceRemoved`                      | Device removal—especially if not user-initiated.         |

---

## Vault & Credential Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `ExportVault`, `ItemExported`        | Bulk export of vault or secrets (possible exfiltration). |
| `CredentialCopied`                   | Copying sensitive data (especially in bulk/odd hours).   |
| `ItemShared`, `ShareInviteSent`      | Unexpected sharing of vaults/items, or invites to externals. |
| `DeleteItem`, `RestoreItem`          | Deleting/restoring credentials (cover tracks or misuse). |
| `BulkItemAccess`                     | Mass access to credentials in short period.              |

---

## Admin & Privilege Events

| **Keyword / Event**                 | **Description / Risk**                                 |
| ----------------------------------- | ------------------------------------------------------ |
| `AdminCreated`, `AdminRemoved`      | Privilege escalation or reduction of oversight.        |
| `RoleChanged`, `PermissionChanged`  | Changes in permissions/roles, especially for admins.   |
| `InviteAdmin`, `InviteUser`         | Bulk or suspicious invitations (esp. to externals).    |

---

## Integration & API Monitoring

| **Keyword / Event**         | **Description / Risk**                                 |
| --------------------------- | ------------------------------------------------------ |
| `APITokenCreated`           | Creation of API tokens (automation abuse risk).        |
| `APITokenRevoked`           | Token removal (confirm if legitimate).                 |
| `IntegrationAdded`          | New integrations (possible third-party data exposure). |
| `FailedAPIAccess`           | Failed API authentications (possible brute force).     |

---

## Advanced Threat Indicators

- Mass export or copying of credentials  
- Rapid device additions/removals  
- Bulk admin or privilege changes  
- Sharing secrets/vaults with untrusted/external users  
- Disabling/tampering with audit logging  
- Credential access at odd hours or unusual locations  
- Repeated failed logins from same IP/device

---

**Tip:**  
Correlate Keeper Security logs with endpoint, network, and cloud security events for a comprehensive security posture.

