# Threat Hunting with Imperva DB Overview

This file documents threat hunting hypotheses, suspicious event keywords, and detection logic for monitoring database activity and potential security threats using Imperva Database Security (formerly known as SecureSphere Database Activity Monitoring).

## Log Sources
- Imperva Database Activity Monitoring (DAM) logs
- Database audit logs (Oracle, SQL Server, MySQL, etc.)
- User activity logs
- Database error logs
- Imperva Security Policies & Alerts
- Network traffic logs (for monitoring SQL over the wire)
- Imperva Agent logs

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**           | **Description / Threat Scenario**                                            |
|-------------------------------|------------------------------------------------------------------------------|
| `Access Denied`               | Failed or unauthorized access attempts to database objects.                   |
| `Failed Login`                | Multiple failed logins; possible brute force or credential stuffing.           |
| `Privilege Escalation`        | Unusual grant of admin or DBA rights.                                        |
| `User Created`                | Creation of new user accounts, especially with elevated privileges.           |
| `User Dropped`                | Removal of accounts—may be used to cover malicious actions.                   |
| `Role Granted`                | New role or privilege assignments, especially outside normal provisioning.     |
| `Role Revoked`                | Revocation of roles/privileges, potentially to weaken defense or cover tracks. |
| `Schema Changed`              | Unexpected schema modifications, such as table creation or alteration.         |
| `Drop Table`                  | Table deletion—potential sabotage or evidence tampering.                      |
| `SELECT * FROM`               | Unusually broad queries; possible data reconnaissance or mass data exfiltration.|
| `Bulk Data Export`            | Use of export utilities or large result sets; risk of data leakage.            |
| `Grant All Privileges`        | Risky escalation or backdoor creation.                                       |
| `Execute Procedure`           | Unusual or unauthorized stored procedure execution.                           |
| `Database Link`               | Creation or use of links between databases; may indicate lateral movement.     |
| `Audit Policy Changed`        | Disabling or tampering with database auditing features.                        |
| `Bypass Auditing`             | Attempts to evade logging mechanisms.                                         |

---

## Imperva-Specific Suspicious Events & Alerts

- Policy violation: Access to sensitive tables/columns (PII, PCI, PHI)
- Alerts for access outside approved hours or from unusual locations
- Security rule triggers: SQL injection patterns, DDL/DML anomalies
- Use of admin accounts from non-standard hosts
- Multiple failed logins followed by a successful one
- Suspicious use of utility commands (e.g., xp_cmdshell, UTL_HTTP)

---

## High-Risk Behaviors & Use Cases

- Database access from service accounts outside automation windows
- Admin privilege escalation without change management
- Unauthorized access to backup tables or logs
- Sudden increase in data export or download activities
- Access to deprecated or legacy databases

---

## Advanced Threat Indicators

- Reconnaissance: systematic access to system tables (e.g., `information_schema`)
- Use of SQL injection payloads or abnormal query patterns
- Attempts to disable or alter auditing/logging functions
- Chained commands or stored procedures for lateral movement
- Access attempts from TOR exit nodes or known malicious IPs

---

## Response Recommendations

- Enable and monitor all Imperva and native DB audit logs
- Set alerts for privilege changes, mass data exports, and policy violations
- Regularly review user account and privilege assignments
- Apply least privilege principle for database access
- Conduct regular database vulnerability scans and policy reviews

---

## References

- [Imperva Database Security Documentation](https://docs.imperva.com/bundle/v14.6-database-security-user-guide/page/56098.htm)
- [Best Practices for Imperva Database Activity Monitoring](https://www.imperva.com/resources/resource-library/best-practices-database-security-dam/)
- [OWASP Top 10 – SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
