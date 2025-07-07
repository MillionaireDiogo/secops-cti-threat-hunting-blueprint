# Threat Hunting with JumpCloud Overview


This file covers threat hunting keywords and indicators for JumpCloud—a cloud-based directory, SSO, and device management platform. Use these keywords and log sources to monitor for suspicious access, privilege escalation, device actions, and potential compromise.

## Log Sources
- JumpCloud Admin Console Audit Logs  
- Directory Insights Logs  
- SSO Event Logs  
- Device Management Logs  
- API Access Logs  
- User Activity Logs  
- System Alerts  

---

## Authentication & Access

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed` | Unsuccessful login attempts (possible brute force).      |
| `SuccessfulLogin` (Unusual Location)  | Access from unexpected geographies/IPs.                  |
| `MFABypass`, `MFAEnrollmentRemoved`   | Bypass or removal of multi-factor authentication.        |
| `PasswordReset`, `PasswordChanged`    | Account compromise, especially for privileged users.     |
| `SuspiciousSSOLogin`                  | Unusual or high-risk SSO events.                         |
| `LegacyAuthAttempt`                   | Use of deprecated or insecure protocols.                 |

---

## User & Group Management

| **Keyword / Event**                 | **Description / Risk**                                      |
| ----------------------------------- | ----------------------------------------------------------- |
| `CreateUser`, `DeleteUser`          | Addition/deletion of user accounts, especially privileged.  |
| `ModifyUser`, `UpdateUser`          | Unexpected user attribute/role changes.                     |
| `AddUserToGroup`, `RemoveUserFromGroup` | Privilege escalation, backdooring, or lateral movement.   |
| `CreateGroup`, `DeleteGroup`        | Group creation/deletion that could impact access controls.  |
| `RoleAssignmentChanged`             | Changes to admin/privileged roles.                          |

---

## Device Management

| **Keyword / Event**                  | **Description / Risk**                              |
| ------------------------------------ | --------------------------------------------------- |
| `RegisterDevice`, `UnregisterDevice` | Device join/leave events, especially bulk or off-hours. |
| `DeviceLock`, `DeviceWipe`           | Potential sabotage or cover-up operations.           |
| `DevicePolicyChanged`                | Security policy modifications on managed endpoints.  |
| `CommandSent`                        | Mass or suspicious remote commands to devices.       |
| `OSUpdatePushed`                     | Pushing updates (check for timing/legitimacy).       |

---

## Directory & SSO Activity

| **Keyword / Event**                      | **Description / Risk**                                     |
| ---------------------------------------- | ---------------------------------------------------------- |
| `SSOApplicationAssigned`                 | New apps assigned—potential SSO phishing or data theft.    |
| `SSOApplicationRemoved`                  | Removal of apps—check for exfiltration.                    |
| `IdPChanged`, `SAMLConfigChanged`        | Changes to SAML/IdP configuration (backdoor risk).         |
| `SSOAppConsentGranted`                   | New OAuth grants to third-party applications.              |

---

## API & Integration Monitoring

| **Keyword / Event**           | **Description / Risk**                                   |
| ----------------------------- | -------------------------------------------------------- |
| `APITokenCreated`             | Unexpected API tokens—possible automation abuse.         |
| `APIAccessDenied`             | Multiple failed API authentications (brute force).       |
| `APICallFromUnknownIP`        | API calls from new or untrusted IP addresses.            |
| `IntegrationFailure`          | Abnormal errors or failed external integrations.         |

---

## Advanced Threat Indicators

- Mass password resets or account unlocks  
- Rapid group membership changes (esp. admin groups)  
- Admin actions from unusual geographies or new devices  
- Sudden changes to device or SSO configuration  
- API calls from suspicious IPs or at odd hours  
- Removal of device security/enforcement policies  
- Disabling logging, auditing, or alerting features

---

**Tip:**  
Correlate JumpCloud logs with endpoint, network, and cloud provider events for comprehensive threat detection.

