# Threat Hunting with Bitwarden Overview

This file covers threat hunting keywords, suspicious activities, and log sources for Bitwarden—a cloud-based open-source password manager. Use these indicators to monitor for compromise, insider threat, or credential abuse within your organization.

## Log Sources
- Bitwarden Audit Logs  
- User Access Logs  
- Organization Event Logs  
- Admin Console Logs  
- API Access Logs  
- Device Registration Logs  
- Failed Authentication Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Repeated failed logins—possible brute force attempts.    |
| `SuccessfulLogin` (New Location)     | Access from unexpected countries/IPs/devices.            |
| `MFABypass`, `MFAReset`, `DisableMFA`| Multi-factor bypass, reset, or disable (risk escalation).|
| `DeviceEnrolled`                     | New device registrations—watch for suspicious activity.  |
| `DeviceRevoked`                      | Removal of devices, especially if not by the user.       |

---

## Vault & Item Operations

| **Keyword / Event**                   | **Description / Risk**                                 |
| ------------------------------------- | ------------------------------------------------------ |
| `CreateVault`, `DeleteVault`          | Creating/deleting vaults—possible staging or cover-up. |
| `VaultShared`, `InviteUserToVault`    | Unexpected sharing of sensitive vaults or items.       |
| `ItemExported`, `ItemCopied`          | Bulk export or copy of secrets (exfiltration).         |
| `ItemDeleted`                         | Removing items to hide malicious activity.             |
| `ItemAccessed` (Bulk/Off-hours)       | Large/odd-hours secret access.                         |

---

## Organization & Admin Activity

| **Keyword / Event**               | **Description / Risk**                                  |
| --------------------------------- | ------------------------------------------------------- |
| `CreateAdmin`, `RemoveAdmin`      | Escalation of privileges or weakening oversight.        |
| `RoleChanged`, `PermissionUpdate` | Unexpected changes to user or vault permissions.        |
| `InviteSent`                      | Bulk invites or invites to untrusted domains.           |
| `EmergencyAccessGranted`          | Granting or using emergency access (risk of misuse).    |

---

## Integration & API Monitoring

| **Keyword / Event**         | **Description / Risk**                                 |
| --------------------------- | ------------------------------------------------------ |
| `APITokenCreated`           | Creation of API tokens (possible automation abuse).    |
| `APITokenRevoked`           | Revocation of tokens—verify legitimacy.                |
| `FailedAPIAccess`           | Repeated failed API auth—possible brute force.         |
| `IntegrationAdded`          | New third-party integrations—watch for data exposure.  |

---

## Advanced Threat Indicators

- Mass export or copy of secrets  
- Unusual device registration spikes  
- Bulk removal or disabling of user accounts/devices  
- Sharing of vaults/items to external/untrusted emails  
- Administrative actions outside normal hours  
- Disabling or tampering with audit logging  
- Emergency access or account recovery used unexpectedly  

---

**Tip:**  
Correlate Bitwarden logs with endpoint/network monitoring and SIEM alerts for enhanced threat detection.

