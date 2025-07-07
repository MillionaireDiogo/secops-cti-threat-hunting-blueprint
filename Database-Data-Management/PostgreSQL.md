# PostgreSQL Threat Hunting Overview

PostgreSQL is a powerful open-source relational database that supports advanced features like stored procedures, user-defined functions, and extensions. It’s a common backend for modern web applications and is increasingly targeted due to:

- Misconfigured authentication (e.g., trust-based auth)
- Exposure of the default port (5432) to the internet
- Abused extensions (e.g., `file_fdw`, `pg_execute_server_program`)
- SQL injection or misuse of procedural languages (`plpgsql`, `plpythonu`, etc.)

---

## Recommended Log Sources

| Source Type               | Description / Use |
|---------------------------|-------------------|
| **PostgreSQL Log File**   | Connection attempts, authentication failures, executed queries. |
| **Audit Extension Logs**  | If `pgaudit` is installed, it provides detailed query-level logging. |
| **System Logs (syslog)**  | OS-level events, user logins, and file system actions. |
| **Firewall / Network Logs** | Remote access to port 5432, scanning activity, exfiltration routes. |

---

## Suspicious Keywords 

### 1. Authentication & Login Abuse

| Keyword               | Description |
|------------------------|-------------|
| `FATAL: password authentication failed` | Brute-force or credential stuffing attempts. |
| `FATAL: role ... does not exist`        | Access attempt using a non-existent user. |
| `authentication failed`                 | Generic failed login — monitor frequency. |
| `peer authentication failed`            | OS-level auth failure — possible misconfig or abuse. |
| `trust authentication`                 | Indicates no-password authentication — insecure setup. |

---

### 2. Reconnaissance & Metadata Enumeration

| Keyword             | Description |
|---------------------|-------------|
| `pg_user`, `pg_roles`      | Lists user and role info — used for privilege mapping. |
| `pg_database`, `pg_tables` | Shows available databases and tables — recon phase. |
| `information_schema`       | Metadata about schemas, tables, columns — useful to attackers. |
| `current_user`, `session_user` | Identify the executing user's privileges. |
| `pg_stat_activity`         | Lists running sessions and queries — abused for monitoring. |

---

### 3. Dangerous SQL Statements

| Keyword             | Description |
|---------------------|-------------|
| `DROP TABLE`, `DROP DATABASE` | Destructive actions — data loss if misused. |
| `TRUNCATE`, `DELETE FROM`     | Potential mass deletion — flag bulk or unfiltered use. |
| `UPDATE`                      | Can modify large amounts of data — check for WHERE clause. |
| `COPY TO`, `COPY FROM`        | Reads/writes files to/from server — often abused for exfiltration. |
| `SELECT * FROM`               | Mass data reads — suspicious if high-volume or targeting sensitive tables. |

---

### 4. Code Execution / OS-Level Abuse

| Keyword                   | Description |
|---------------------------|-------------|
| `COPY ... TO PROGRAM`     | Executes shell commands — dangerous for RCE. |
| `pg_read_file()`, `pg_stat_file()` | Reads files on the server — used for recon or exfiltration. |
| `pg_ls_dir()`             | Lists directory contents — filesystem reconnaissance. |
| `lo_export()`             | Exports large objects to disk — possible staging. |
| `pg_execute_server_program()` | Executes OS-level programs (PostgreSQL 13+) — high RCE risk. |

---

### 5. Procedural Language / Extension Abuse

| Keyword                 | Description |
|-------------------------|-------------|
| `CREATE EXTENSION`      | Adds new capabilities — may introduce dangerous functions. |
| `plpythonu`, `plperlu`  | Untrusted procedural languages — often abused for RCE. |
| `DO $$` / `CREATE FUNCTION` | Inline function execution — may contain dangerous logic. |
| `EXECUTE` (dynamic SQL) | Obfuscated SQL injection or privilege escalation. |

---

### 6. Data Exfiltration & Export

| Keyword              | Description |
|----------------------|-------------|
| `COPY TO`            | Writes query results to file or program — major exfiltration path. |
| `SELECT INTO`        | Can stage data in new tables — preps for export. |
| `UNION SELECT`       | SQLi technique to combine data from multiple sources. |
| `pg_dump`, `psql`    | Legitimate CLI tools for full DB exports — flag unusual use. |
| `ftp`, `curl`, `wget`| If found in shell commands or functions, may indicate data theft. |

---

### 7. Network / Listener Monitoring

| Keyword              | Description |
|----------------------|-------------|
| `connection authorized` | Watch for unexpected user/IP combinations. |
| `port 5432`, `listen_addresses` | Monitor for external exposure of PostgreSQL service. |
| `host all all 0.0.0.0/0` | In `pg_hba.conf` — allows connections from anywhere. |
| `pg_hba.conf`, `postgresql.conf` | Watch for unauthorized config changes. |

---

## Additional Tips

- Enable and monitor `pgaudit` for detailed logging of DDL, DML, and function calls.
- Look for repeated `FATAL: password authentication failed` entries for brute-force detection.
- Alert on execution of procedural languages like `plpythonu`, `plperlu`, or dangerous extensions.
- Monitor the use of `COPY TO PROGRAM`, `pg_execute_server_program`, and other OS-executing features.
- Use `pg_stat_activity` to track long-running queries, especially those accessing sensitive tables.

---

