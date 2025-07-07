# Threat Hunting with BeyondTrust IAM (Privileged Access Monitoring) Overview

BeyondTrust IAM specializes in managing and monitoring privileged accounts and sessions. Hunting within BeyondTrust logs helps detect misuse of privileged credentials, unauthorized access, suspicious session activity, and potential insider threats.

---

## 2. Log Sources

| Log Source                 | Description                                                          |
|---------------------------|----------------------------------------------------------------------|
| **Session Logs**           | Detailed privileged session recordings, start/stop, duration, commands executed |
| **Access Logs**            | Privileged account login/logout events, authentication attempts      |
| **Audit Logs**             | Changes to IAM policies, roles, permissions, and configurations      |
| **Alert Logs**             | Triggered alerts on suspicious or anomalous privileged activity      |
| **User Activity Logs**     | Command executions, file transfers, clipboard usage during sessions  |

---

## 3. Threat Hunting Categories 

### A. Privileged Access Anomalies

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `session_start`          | Privileged session initiation — look for unusual times or users          |
| `session_end`            | Session termination — abrupt or unusually long sessions                  |
| `failed_login`           | Failed privileged login attempts — brute force or credential guessing    |
| `privileged_user`        | Accounts with elevated permissions — monitor for unusual activity        |
| `access_denied`          | Denied access attempts to privileged resources                           |

---

### B. Suspicious Session Activity

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `command_executed`       | Commands run during privileged sessions — watch for dangerous commands (e.g., `net user`, `shutdown`, `regedit`) |
| `file_transfer`          | Upload/download of files during sessions — potential data exfiltration   |
| `clipboard_usage`        | Clipboard activity transferring sensitive data                          |
| `multiple_sessions`      | Same user with simultaneous sessions from different IPs or devices      |

---

### C. Policy & Configuration Changes

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `role_change`            | Modifications to privileged roles or account permissions                 |
| `policy_update`          | Changes to access policies or session controls                           |
| `audit_log_change`       | Alterations or deletions of audit logs                                  |

---

### D. Alerting & Anomaly Detection

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `alert_triggered`        | Alerts for anomalous privileged behavior                                |
| `session_recording_disabled` | Session recording turned off or bypassed                             |
| `unusual_login_time`     | Access outside of normal working hours                                  |
| `new_privileged_account` | Creation of new privileged accounts                                    |

---

## 4. ✅ Recommended Hunting Workflow

1. Identify unusual privileged login times and sources.  
2. Monitor failed privileged login attempts for brute force activity.  
3. Inspect privileged session commands for suspicious or unauthorized actions.  
4. Track file transfers or clipboard use in privileged sessions for data exfiltration risks.  
5. Audit policy changes affecting privileged roles or session monitoring.  
6. Investigate alerts and disabled session recordings as potential evasion tactics.  

---
