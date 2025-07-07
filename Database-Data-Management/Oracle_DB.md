# Oracle Database Threat Hunting Overview

Oracle Database is a high-performance RDBMS often used in enterprise environments to store mission-critical data. Due to its complexity and privileged access requirements, Oracle is a high-value target for attackers aiming to:

- Bypass authentication via vulnerabilities or default accounts
- Abuse PL/SQL packages and procedures
- Steal or exfiltrate sensitive data
- Escalate privileges
- Execute operating system commands via external procedures

---

## Recommended Log Sources

| Source Type                    | Description / Use |
|--------------------------------|-------------------|
| **Oracle Alert Log**           | Critical internal errors, instance startup/shutdown. |
| **Oracle Listener Log**        | Incoming client connections, failed attempts, remote access patterns. |
| **Oracle Audit Trail (AUD$ Table)** | Captures session starts, DML/DDL, and login events. |
| **Fine-Grained Auditing (FGA)**| Tracks access to specific tables or columns. |
| **Database Vault / Unified Audit Logs** | Advanced logging and auditing (if configured). |
| **System Logs / Syslog**       | OS-level user and process activity. |
| **Firewall Logs**              | Access to port 1521 (default Oracle port) or others. |

---

## Suspicious Keywords 

### 1. Authentication & Login Abuse

| Keyword              | Description |
|----------------------|-------------|
| `ORA-01017`          | Invalid username/password — login failure (often brute-force attempts). |
| `ORA-28000`          | Account locked due to too many failed attempts. |
| `ORA-28001`          | Password expired — might lead to attempts at resetting credentials. |
| `ORA-28221`, `ORA-28003` | Strong authentication failures. |
| `SYS`, `SYSTEM`, `DBA` | Login attempts with default privileged accounts. |

---

### 2. Reconnaissance & Enumeration

| Keyword              | Description |
|----------------------|-------------|
| `ALL_TABLES`, `DBA_TABLES`, `USER_TABLES` | Lists all or user-specific tables — used for mapping database contents. |
| `ALL_USERS`, `DBA_USERS` | Lists users and roles — attacker recon. |
| `ALL_SOURCE`, `DBA_SOURCE` | Used to view PL/SQL code of procedures and packages. |
| `v$session`, `v$process` | Monitoring other sessions — used for surveillance or process injection. |
| `UTL_INADDR`, `UTL_HTTP`, `UTL_SMTP`, `UTL_TCP` | Network-capable PL/SQL packages — often abused. |

---

### 3. Suspicious SQL / PL/SQL Activity

| Keyword              | Description |
|----------------------|-------------|
| `GRANT DBA`          | Privilege escalation — attacker granting admin access to self. |
| `CREATE USER`, `ALTER USER`, `DROP USER` | User account manipulation — often post-compromise. |
| `DROP TABLE`, `TRUNCATE TABLE`, `DELETE` | Destructive operations — suspicious without context. |
| `CREATE OR REPLACE PROCEDURE`, `FUNCTION`, `PACKAGE` | Code injection or persistence via PL/SQL. |
| `DBMS_SCHEDULER`     | Can schedule OS-level jobs — abused for persistence or RCE. |
| `EXECUTE IMMEDIATE`  | Dynamic SQL execution — often used for obfuscation or injections. |
| `EXTERNAL PROCEDURE` | Used to run OS-level commands via shared libraries. |

---

### 4. OS-Level Abuse & Code Execution

| Keyword              | Description |
|----------------------|-------------|
| `JAVA`               | Java stored procedures can be used for RCE inside Oracle. |
| `LIBRARY`            | Custom shared object files for external procedures. |
| `DBMS_JAVA`, `DBMS_JAVA_TEST`, `DBMS_JAVA.RUNJAVA` | Java-based execution — high-risk for RCE. |
| `EXEC dbms_scheduler.create_job` | Can launch OS commands if improperly configured. |
| `utl_file`           | Read/write access to the file system — data staging or exfil. |

---

### 5. Data Access & Exfiltration

| Keyword              | Description |
|----------------------|-------------|
| `SELECT * FROM`      | Full-table scans — suspicious if done repeatedly on sensitive tables. |
| `EXPORT`, `DATA PUMP`, `expdp`, `impdp` | Tools for exporting/importing large datasets — may indicate data theft. |
| `spool`              | Writes query output to local file — used for offline exfiltration. |
| `ftp`, `http`, `wget`, `curl` | Look for in conjunction with UTL_HTTP or scheduler jobs. |

---

### 6. Network Access & Listener Abuse

| Keyword              | Description |
|----------------------|-------------|
| `listener.log`       | Log file where remote connections are logged — review for abuse. |
| `TNS`                | Oracle’s Transparent Network Substrate — exploited in older vulnerabilities. |
| `remote OS authentication` | Misconfigurations allowing OS user authentication over the network. |
| `tnsnames.ora`, `sqlnet.ora` | Files controlling remote access — monitor for unauthorized changes. |

---

## Additiona Tips

- Monitor for excessive `ORA-01017` errors — a sign of brute-force attempts.
- Alert on `GRANT DBA` or `CREATE USER` commands from unexpected accounts.
- Flag use of packages like `UTL_HTTP`, `DBMS_JAVA`, or `DBMS_SCHEDULER`.
- Watch for `DROP`/`TRUNCATE` statements issued during non-maintenance periods.
- Analyze `listener.log` for unexpected client IPs or unusual service names.
- Audit PL/SQL changes (`CREATE OR REPLACE PROCEDURE`) for backdoor code.

---

