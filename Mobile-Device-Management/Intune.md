# Threat Hunting with Intune Overview

This file focuses on threat hunting keywords and activities specific to Microsoft Intune (MDM), enabling detection of suspicious device management, compliance, and enrollment activities.

## Log Sources
- Intune Audit Logs  
- Intune Operational Logs  
- Azure AD Sign-in & Audit Logs  
- Microsoft Defender for Endpoint  
- Device Compliance Logs  
- Device Enrollment Logs  
- Conditional Access Logs  

---

## Device Enrollment & Registration

| **Keyword / Event**               | **Description / Risk**                                |
| --------------------------------- | ----------------------------------------------------- |
| `DeviceRegistered`                | New device registration; mass/unknown devices.        |
| `DeviceEnrollment`                | New or bulk enrollments, especially off-hours.        |
| `EnrollDevice`                    | Potential unauthorized enrollments.                   |
| `UnenrollDevice`                  | Attempt to evade policy enforcement.                  |
| `DeleteDevice`                    | Covering tracks; device wipe/tampering.               |
| `JoinType`                        | Watch for 'AzureADJoined' vs. 'Hybrid' anomalies.     |

---

## Policy & Profile Manipulation

| **Keyword / Event**                      | **Description / Risk**                               |
| ---------------------------------------- | ---------------------------------------------------- |
| `CreatePolicy`, `UpdatePolicy`           | Suspicious or unauthorized policy changes.           |
| `DeletePolicy`                           | Disabling compliance or security controls.           |
| `AssignmentChanged`, `AssignmentRemoved` | Modifying which users/devices receive policies.      |
| `CompliancePolicyUpdated`                | Tampering with device compliance requirements.       |
| `ConfigurationProfileCreated`            | Unusual configuration profile creation.              |
| `DeviceRestrictionPolicyChanged`         | Modifying device restrictions to weaken security.    |

---

## App Management

| **Keyword / Event**                    | **Description / Risk**                           |
| -------------------------------------- | ------------------------------------------------ |
| `InstallApp`, `DeployApp`              | Unusual or unauthorized app deployments.         |
| `RemoveApp`                            | Deleting monitoring/security/critical apps.      |
| `AppProtectionPolicyChanged`           | Loosening of data protection policies.           |
| `AppConfigPolicyAssignmentChanged`     | Suspect changes to app configuration assignments.|

---

## Compliance & Conditional Access

| **Keyword / Event**              | **Description / Risk**                                  |
| ------------------------------- | ------------------------------------------------------- |
| `ComplianceState=noncompliant`   | Multiple devices/users suddenly non-compliant.          |
| `GrantControlsChanged`           | Conditional access grant controls modified.             |
| `BypassConditionalAccess`        | Attempts to circumvent conditional access.              |
| `RequireMFA`                     | Conditional access requiring MFA removed or relaxed.    |

---

## Administrative & Privilege Operations

| **Keyword / Event**                  | **Description / Risk**                                    |
| ------------------------------------ | --------------------------------------------------------- |
| `AddAdmin`, `RemoveAdmin`            | Changes in Intune administrators; possible privilege abuse.|
| `RoleAssignmentChanged`              | Unexpected RBAC changes within Intune.                     |
| `DirectoryRoleAssignment`            | Elevation of user/device to privileged roles.              |

---

## Device Actions & Remote Operations

| **Keyword / Event**              | **Description / Risk**                              |
| ------------------------------- | --------------------------------------------------- |
| `WipeDevice`, `RemoteLock`       | Potential sabotage, data destruction, or cover-up.  |
| `ResetPasscode`                  | Repeated or unexplained passcode resets.            |
| `RetireDevice`                   | Removing devices from management unexpectedly.      |

---

## Advanced Threat & Suspicious Behavior Indicators

- Mass device enrollments or deletions  
- Multiple failed device enrollments  
- Devices reporting from unexpected locations or IPs  
- Repeated policy disablement or configuration changes  
- Compliance status manipulation  
- Use of outdated Intune clients or bypass of latest agent  
- Sudden drop in compliant device percentage  
- Addition of external/untrusted devices

---

**Tip:**  
Correlate Intune activity with Azure AD sign-in logs and Defender alerts for deeper threat context.

