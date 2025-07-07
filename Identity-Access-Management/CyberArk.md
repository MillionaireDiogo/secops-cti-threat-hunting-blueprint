# Threat Hunting with CyberArk Privileged Access Management (PAM) Overview

CyberArk PAM secures and monitors privileged accounts and sessions across the enterprise. Hunting through CyberArk logs helps identify unauthorized access, credential misuse, suspicious session activity, and potential insider threats.

---

## 2. Log Sources

| Log Source                  | Description                                                            |
|----------------------------|------------------------------------------------------------------------|
| **Session Logs**            | Detailed recordings and metadata of privileged sessions                |
| **Access Logs**             | Privileged account authentication successes and failures               |
| **Audit Logs**              | Changes to PAM configurations, policies, and account permissions       |
| **Alert Logs**              | Alerts triggered by anomalous or risky privileged activity             |
| **Password Vault Logs**     | Access and changes to stored credentials                               |
| **User Activity Logs**      | Commands executed, file operations, and other actions within sessions  |

---

## 3. Threat Hunting Categories 

### A. Privileged Access Anomalies

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `session_start`          | Privileged session start events — unusual times or accounts             |
| `session_end`            | Session termination — abrupt or unusually long durations                |
| `failed_login`           | Failed privileged login attempts — brute force or credential guessing   |
| `privileged_user`        | Elevated accounts — monitor for unusual access patterns                 |
| `access_denied`          | Denied access attempts to privileged resources                          |

---

### B. Suspicious Session Activity

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `command_executed`       | Commands run during sessions — watch for dangerous commands (e.g., `net user`, `shutdown`, `regedit`) |
| `file_transfer`          | Upload/download activity during sessions — potential data exfiltration  |
| `clipboard_usage`        | Clipboard actions involving sensitive data                              |
| `multiple_sessions`      | Simultaneous sessions by same user from different IPs or devices        |

---

### C. Configuration & Policy Changes

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `policy_change`          | Modifications to PAM policies, roles, or permissions                    |
| `account_change`         | Changes to privileged account details                                   |
| `audit_log_modification`| Alterations or deletions of audit logs                                  |
| `admin_login`            | Administrative console access events                                    |
| `failed_admin_login`     | Failed admin login attempts                                             |

---

### D. Alerting & Anomaly Detection

| Keyword/Field             | Description                                                              |
|--------------------------|--------------------------------------------------------------------------|
| `alert_triggered`        | Alerts on anomalous privileged activity                                |
| `session_recording_disabled` | Session recording turned off or bypassed                             |
| `unusual_login_time`     | Access outside normal business hours                                   |
| `new_privileged_account` | Creation of new privileged accounts                                    |

---

## 4. Additonal Recommendations

1. Identify privileged sessions starting at unusual times or from unusual locations.  
2. Track failed privileged login attempts to detect brute force or credential stuffing.  
3. Analyze commands executed in sessions for suspicious activity.  
4. Monitor file transfers and clipboard usage within privileged sessions.  
5. Audit configuration and policy changes affecting PAM security posture.  
6. Investigate triggered alerts and disabled session recordings.  

---
