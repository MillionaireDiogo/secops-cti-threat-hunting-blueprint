# Threat Hunting with Jamf_Pro Overview

This file covers threat hunting and suspicious activity detection for Jamf Pro, focusing on Apple device management environments. Use these keywords and log sources to monitor for potential compromise, misuse, or insider threats.

## Log Sources
- Jamf Pro Server Logs  
- Jamf Pro Audit Logs  
- Jamf API Access Logs  
- Device Inventory Logs  
- macOS System Logs  
- User Initiated Device Actions Logs  
- Apple Push Notification Service (APNS) Logs  

---

## Device Enrollment & Registration

| **Keyword / Event**         | **Description / Risk**                                 |
| -------------------------- | ------------------------------------------------------ |
| `EnrollComputer`            | Mass or off-hours device enrollments.                  |
| `UnenrollComputer`          | Removing managed devices (policy evasion).             |
| `Re-enrollDevice`           | Unusual re-enrollments (potential evasion).            |
| `DeviceDeleted`             | Attempt to cover tracks or sabotage monitoring.        |
| `EnrollmentInvitationSent`  | Unexpected or bulk invitations (phishing risk).        |
| `PreStageEnrollment`        | New or modified pre-stage enrollments (abuse risk).    |

---

## Policy & Configuration Manipulation

| **Keyword / Event**           | **Description / Risk**                                     |
| ----------------------------- | ---------------------------------------------------------- |
| `CreatePolicy`, `UpdatePolicy`| Unauthorized/suspicious changes to config or compliance.   |
| `DeletePolicy`                | Removing enforcement or security policies.                 |
| `ScriptDeployed`              | Execution of new or unapproved scripts on endpoints.       |
| `ConfigurationProfileAdded`   | Addition of unapproved profiles (e.g., to bypass controls).|
| `RemoveConfigurationProfile`  | Removing critical security/compliance profiles.            |
| `RestrictedSoftwareChanged`   | Changes to software restriction rules.                     |

---

## App Management & Software Distribution

| **Keyword / Event**             | **Description / Risk**                           |
| ------------------------------- | ------------------------------------------------ |
| `InstallApplication`            | Bulk or unauthorized app installs.               |
| `RemoveApplication`             | Removal of security or monitoring software.      |
| `AppStoreAppDeployed`           | Non-catalog/unexpected App Store apps deployed.  |
| `SelfServicePolicyRun`          | Unusual use of Self Service for privileged apps. |

---

## User & Admin Activity

| **Keyword / Event**                | **Description / Risk**                                      |
| ----------------------------------- | ----------------------------------------------------------- |
| `CreateUser`, `DeleteUser`          | Suspicious creation or removal of local device users.        |
| `PrivilegeEscalationAttempt`        | Attempted privilege escalation on managed Mac devices.       |
| `AdminAccountAdded`                 | New or unauthorized admin account creation.                  |
| `LoginAsUser`                       | Use of Jamf admin to log in as other users (possible abuse).|

---

## Remote Commands & Device Actions

| **Keyword / Event**       | **Description / Risk**                                      |
| ------------------------- | ----------------------------------------------------------- |
| `WipeComputer`            | Device wipe command (potential sabotage or cover-up).       |
| `LockComputer`            | Unexplained remote locks.                                  |
| `ResetPassword`           | Bulk or repeated password resets.                           |
| `RemoteCommandSent`       | Large volume or suspicious remote commands.                 |

---

## API & Integration Abuse

| **Keyword / Event**         | **Description / Risk**                              |
| --------------------------- | --------------------------------------------------- |
| `APITokenCreated`           | Unexpected API tokens (possible automation abuse).  |
| `APIUserCreated`            | New service accounts without business justification.|
| `APIAccessDenied`           | Multiple failed API auth attempts (brute force).   |

---

## Advanced Threat Indicators

- Mass changes to device group membership  
- Devices moved to untrusted groups  
- Configuration profile push from unexpected IPs  
- New or unapproved extensions, kernel/system modifications  
- Removal of endpoint security tools  
- Unusual communication with external C2 or update servers  
- Jamf admin actions from foreign or unexpected geolocations

---

**Tip:**  
Correlate Jamf events with macOS system logs and network traffic for a comprehensive view of endpoint risk.

