# Threat Hunting with Exabeam Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Exabeam—a leading UEBA (User and Entity Behavior Analytics) and SIEM platform. Use these indicators to spot anomalous user or entity behaviors, privilege abuse, policy evasion, insider threats, and advanced attacks.

## Log Sources
- Exabeam Security Event Logs  
- User & Entity Behavior Analytics (UEBA) Logs  
- Ingested Authentication Logs  
- Ingested Application Logs  
- Ingested Network & Endpoint Logs  
- Threat & Alert Logs  
- Policy Violation Logs  
- Integration/API Logs  
- Admin Activity Logs  

---

## Authentication & Access Anomalies

| **Keyword / Event**                      | **Description / Risk**                                   |
| ---------------------------------------- | -------------------------------------------------------- |
| `MultipleFailedLogins`, `BruteForce`     | Excessive failed login attempts (possible brute force).  |
| `SuccessfulLogin` (Impossible Travel)    | Logins from two locations in short succession.           |
| `UnusualLoginTime`                       | Logins at off-hours or outside user's normal pattern.    |
| `MFABypass`, `AuthenticationBypass`      | Bypassing authentication controls.                       |
| `AccountLocked`, `AccountReset`          | Lockouts or password resets (potential compromise).      |

---

## Privilege & Role Escalation

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `PrivilegeEscalation`, `RoleChange`  | Users assigned to higher privileges or new roles.        |
| `AdminAdded`, `AdminPrivilegesGranted`| Privileges granted without change ticket or approval.     |
| `RBACChanged`, `GroupMembershipChanged`| Unusual changes in user or group membership.            |

---

## Lateral Movement & Unusual Behavior

| **Keyword / Event**                       | **Description / Risk**                                   |
| ----------------------------------------- | -------------------------------------------------------- |
| `LateralMovement`, `UnusualResourceAccess`| Accessing resources not typically used by user/entity.   |
| `AccessToSensitiveData`                   | User/entity accessed sensitive or regulated data.        |
| `UnusualFileAccess`, `BulkFileDownload`   | Mass access or downloads (possible exfiltration).        |
| `UnusualApplicationUsage`                 | Access to apps rarely or never used before.              |
| `ServiceAccountAbuse`                     | Unusual or risky service account activity.               |

---

## Threat, Alert & Policy Violation Events

| **Keyword / Event**                 | **Description / Risk**                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `ThreatDetected`, `HighRiskAlert`   | Risk or threat alerts (malware, C2, data exfiltration).  |
| `PolicyViolation`                   | Violation of security or access policies.                |
| `IntegrationAlert`                  | Issues or failures in log or data ingestion.             |
| `SuspiciousAutomation`              | Automated activity deviating from baseline.              |

---

## Admin & Integration Events

| **Keyword / Event**              | **Description / Risk**                                   |
| ------------------------------- | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin` | Unusual or failed admin logins.                          |
| `ConfigChange`, `PolicyChange`   | Unauthorized changes to platform config or detection rules.|
| `APITokenCreated`, `APITokenRevoked` | Creation or revocation of API tokens (automation risk).|
| `IntegrationAdded`, `IntegrationError` | New integrations or errors (data loss/exposure risk). |

---

## Advanced Threat Indicators

- Sequence of events indicating potential kill chain (recon, initial access, persistence, exfiltration)  
- Chained alerts across users/entities (peer group analytics)  
- Surge in high-risk scores for multiple users/devices  
- Admin actions or role escalations outside business hours  
- Unusual API/integration activity  
- Repeated failure in policy, detection, or logging mechanisms  
- Detection of rarely seen malware or C2 indicators

---

**Tip:**  
Correlate Exabeam logs and analytics with upstream security tools, endpoint, cloud, and identity sources to create end-to-end threat visibility and response.

