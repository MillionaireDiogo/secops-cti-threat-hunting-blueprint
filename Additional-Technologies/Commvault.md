# Threat Hunting with Commvault Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Commvault—an enterprise backup, recovery, and data protection platform. Use these indicators to detect backup tampering, data exfiltration, ransomware, policy evasion, and admin abuse.

## Log Sources
- Commvault Event & Audit Logs  
- Job/Task Logs  
- User Activity Logs  
- Admin Console Logs  
- API/Integration Logs  
- Policy/Configuration Change Logs  
- Backup/Restore Operation Logs  
- Security & Threat Alert Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New IP/Location)  | Admin/user access from new or unexpected sources.        |
| `MFABypass`, `MFAEnrollmentRemoved`  | Bypassing or removing multi-factor authentication.       |
| `AdminLogin`, `AdminChange`          | Unusual admin logins or privilege escalations.           |

---

## Backup, Restore & Data Movement Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `BackupJobCreated`, `BackupStarted`  | Abnormal backup jobs (timing, size, or destination).     |
| `BackupJobDeleted`, `JobCancelled`   | Deleting/cancelling scheduled or completed backups.      |
| `RestoreJobStarted`                  | Unusual or unauthorized restore operations.              |
| `BulkRestore`, `MassRestore`         | Large-scale data restoration (possible data theft).      |
| `BackupCopyCreated`                  | Creation of backup copies to unapproved destinations.    |
| `BackupExported`                     | Backups exported outside of policy (possible exfiltration).|
| `DataMovementToExternal`             | Backup/restore involving external storage/clouds.        |

---

## Policy, Configuration & Compliance Events

| **Keyword / Event**                    | **Description / Risk**                                   |
| -------------------------------------- | -------------------------------------------------------- |
| `PolicyChanged`, `PolicyDeleted`       | Modification or deletion of backup/retention policies.   |
| `ConfigChange`, `ScheduleChanged`      | Changes to backup schedules, destinations, or options.   |
| `RetentionPolicyModified`              | Shortened data retention (covering ransomware traces).   |
| `LoggingDisabled`, `AuditTrailCleared` | Disabling logs/auditing to hide activity.                |

---

## Admin & Privilege Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `CreateAdmin`, `DeleteAdmin`          | Privilege escalation or reduction of oversight.          |
| `RoleChanged`, `PermissionChanged`    | Unexpected admin/user role or permission changes.         |
| `BulkUserAdded`, `BulkUserRemoved`    | Rapid addition/removal of users (possible insider threat).|

---

## Threat, Ransomware & Alert Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `RansomwareDetected`, `MalwareAlert`  | Malware/ransomware found in backups or storage.          |
| `ThreatAlert`, `SuspiciousActivity`   | General risk and security alerts from Commvault.         |
| `BackupAnomalyDetected`               | Backup jobs with anomalous patterns or failures.         |
| `RestoreAnomalyDetected`              | Restore jobs outside usual business activity.            |

---

## Integration & API Monitoring

| **Keyword / Event**         | **Description / Risk**                                 |
| --------------------------- | ------------------------------------------------------ |
| `APITokenCreated`           | Creation of new API tokens (possible automation abuse).|
| `APIAccessDenied`           | Failed API authentication attempts.                    |
| `IntegrationAdded`          | New integrations with backup system (data risk).       |

---

## Advanced Threat Indicators

- Backup or restore jobs to unknown or external destinations  
- Bulk deletion or cancellation of backup jobs  
- Shortening or removal of retention policies  
- Mass restores or exports outside normal business hours  
- Multiple failed admin or user logins  
- Admin changes or privilege escalations without ticket/approval  
- Ransomware detected in backup jobs or frequent backup anomalies  
- Logging disabled or audit trail tampering

---

**Tip:**  
Correlate Commvault logs with endpoint, SIEM, and cloud provider activity for early detection of backup-targeted attacks and data loss.

