# Threat Hunting with MobileIron Overview

# MobileIron.md

## Description
This file provides threat hunting keywords and indicators for MobileIron (Ivanti) Mobile Device Management (MDM), helping detect compromise, insider threat, and policy evasion in managed mobile environments.

## Log Sources
- MobileIron Audit Logs  
- Device Compliance & Activity Logs  
- Enrollment Logs  
- Policy Change Logs  
- Admin Access Logs  
- App Management Logs  
- System Alerts  
- Integration/API Access Logs  

---

## Device Enrollment & Registration

| **Keyword / Event**          | **Description / Risk**                                   |
| ---------------------------- | -------------------------------------------------------- |
| `DeviceEnrollment`           | New/bulk device enrollments, especially off-hours.       |
| `DeviceUnenrollment`         | Devices removed from management (policy evasion).        |
| `DeviceWipe`                 | Remotely wiping devices (potential cover-up).            |
| `DeviceRetire`               | Unexpected device retirements.                           |
| `EnrollmentFailure`          | Multiple failed or suspicious enrollments.               |
| `DeviceReenrollment`         | Frequent or unexplained re-enrollment activity.          |

---

## Policy & Configuration Changes

| **Keyword / Event**            | **Description / Risk**                                       |
| ------------------------------ | ------------------------------------------------------------ |
| `PolicyUpdate`, `PolicyDelete` | Unauthorized policy modifications or deletions.              |
| `CompliancePolicyChanged`      | Loosening device or app compliance requirements.             |
| `ConfigurationProfileChanged`  | Modifications to device profiles or security settings.        |
| `VPNPolicyChange`              | Changes to VPN configuration (potential bypass).             |
| `RestrictionProfileRemoved`    | Disabling security restrictions on devices.                  |

---

## App & Content Management

| **Keyword / Event**          | **Description / Risk**                                    |
| ---------------------------- | --------------------------------------------------------- |
| `AppInstall`, `AppRemove`    | Installation or removal of security/monitoring apps.      |
| `AppWhitelistChanged`        | Unauthorized change to allowed apps list.                 |
| `AppBlacklistChanged`        | Removal of apps from blacklist (potential abuse).         |
| `ContentPush`                | Large/unusual content distribution to devices.            |

---

## User & Admin Activity

| **Keyword / Event**          | **Description / Risk**                                         |
| ---------------------------- | -------------------------------------------------------------- |
| `AdminLogin`, `AdminLogout`  | Unusual admin logins, especially after hours.                  |
| `FailedAdminLogin`           | Brute force attempts on admin accounts.                        |
| `UserRoleChange`             | Escalation of privileges or RBAC changes.                      |
| `CreateUser`, `DeleteUser`   | Creation/deletion of admin or privileged users.                |

---

## Device Actions & Remote Operations

| **Keyword / Event**            | **Description / Risk**                               |
| ------------------------------ | ---------------------------------------------------- |
| `RemoteLock`, `RemoteWipe`     | Frequent or suspicious use of device lock/wipe.      |
| `ResetPasscode`                | Multiple/repeated passcode resets.                   |
| `PushCommand`                  | Unusual or mass device management commands sent.     |

---

## Integration, API, and System Alerts

| **Keyword / Event**           | **Description / Risk**                                 |
| ----------------------------- | ----------------------------------------------------- |
| `APITokenCreated`             | Unexpected API/service tokens (automation abuse).      |
| `APIKeyAccessDenied`          | Failed API authentication attempts.                    |
| `IntegrationFailure`          | Integration errors or abnormal external connections.   |
| `SystemAlert`                 | High-priority system errors or warnings.               |

---

## Advanced Threat Indicators

- Mass device or user unenrollments  
- Policy changes from unrecognized admin accounts  
- Sudden increase in non-compliant device count  
- App whitelisting/blacklisting changes without approval  
- Device actions from unexpected geolocations or networks  
- Repeated failed device or admin authentications  
- Removal/disabling of critical monitoring or security apps

---

**Tip:**  
Correlate MobileIron logs with SIEM, Azure AD, and network monitoring for deeper threat visibility.

