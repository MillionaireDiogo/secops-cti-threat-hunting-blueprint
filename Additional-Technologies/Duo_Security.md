# Threat Hunting with Duo_Security Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Duo Security—a widely used MFA, SSO, and zero trust platform. Use these indicators to detect authentication abuse, bypass attempts, privilege escalation, and insider threats.

## Log Sources
- Duo Authentication Logs  
- Admin Console Logs  
- Access & Activity Logs  
- Device Registration Logs  
- API/Integration Logs  
- Policy & Configuration Logs  
- Security Alert Logs  

---

## Authentication & Access Events

| **Keyword / Event**                     | **Description / Risk**                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`   | Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)       | Logins from new/unusual devices, IPs, or locations.      |
| `MFABypass`, `BypassCodeUsed`           | Bypassing or circumventing multi-factor authentication.  |
| `MFAEnrollmentRemoved`                  | Removing enrolled MFA for a user (possible risk).        |
| `DeviceAdded`, `DeviceRemoved`          | Unusual device registrations or removals.                |
| `SessionExtended`                       | Suspicious session reuse or extension.                   |

---

## Push, OTP, and Authentication Methods

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `DuoPushAccepted`, `DuoPushDenied`   | Push notification accepted or denied (look for fatigue). |
| `MultiplePushRequests`               | MFA fatigue attacks (many pushes in a short time).       |
| `OTPUsed`, `OTPResent`               | OTP requests—monitor for bulk or failed attempts.        |
| `PhoneCallUsed`, `SMSUsed`           | Authentication via phone/SMS—consider interception risk. |

---

## Policy & Configuration Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `PolicyChanged`, `ConfigChange`       | Unauthorized or unexpected changes to policy/config.     |
| `MFAEnforcementDisabled`              | Disabling MFA enforcement (serious risk).                |
| `SelfEnrollmentAllowed`               | Opening enrollment to all users (potential abuse).       |
| `GroupMembershipChanged`              | Users added to or removed from protected groups.         |

---

## Admin & Privilege Events

| **Keyword / Event**                 | **Description / Risk**                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`    | Unusual or failed admin logins.                          |
| `RoleChanged`, `PermissionChanged`  | Unexpected changes in admin/user privileges.             |
| `CreateAdmin`, `RemoveAdmin`        | Privilege escalation or reduction of oversight.          |

---

## Integration & API Monitoring

| **Keyword / Event**           | **Description / Risk**                                 |
| ----------------------------- | ------------------------------------------------------ |
| `APITokenCreated`             | New API tokens (automation/integration abuse risk).    |
| `APITokenRevoked`             | API tokens revoked—verify if expected.                 |
| `IntegrationAdded`            | New integrations or third-party connections.           |
| `APIAccessDenied`             | Failed API authentication attempts.                    |

---

## Advanced Threat Indicators

- Multiple failed logins or MFA bypass attempts in short window  
- Push fatigue (many push requests sent rapidly to user)  
- Device registrations or removals outside business hours  
- Admin/configuration changes without approval  
- Disabling MFA enforcement or broadening self-enrollment  
- Logins, device, or policy changes from suspicious geographies  
- API or integration changes without business justification

---

**Tip:**  
Correlate Duo logs with identity, VPN, and endpoint monitoring for strong detection of authentication-based attacks and account compromise.

