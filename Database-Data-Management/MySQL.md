# MySQL Threat Hunting Overview

MySQL is a widely-used relational database often targeted in attacks due to:

- Weak or default credentials
- SQL injection vulnerabilities
- Misconfigurations (e.g., remote access without firewalling)
- Abuse of administrative functions
- Lateral movement via stored procedures or UDFs

---

## Recommended Log Sources

| Source Type               | Description / Use |
|---------------------------|-------------------|
| **MySQL General Query Log** | Logs every query received by the server — high value for hunting, but heavy. |
| **MySQL Error Log**       | Authentication failures, startup errors, plugin issues. |
| **MySQL Slow Query Log**  | Useful for spotting long-running or mass data queries. |
| **Audit Plugin Logs**     | Tracks query activity by user — available via 3rd-party or enterprise plugins. |
| **System Logs**           | OS-level logins, process launches, network activity. |
| **Firewall / Network Logs** | Access attempts to port 3306 or other MySQL ports. |

---

## 🔍 Suspicious Keywords (with Descriptions)

### 1. 🚪 Authentication & Access Abuse

| Keyword             | Description |
|---------------------|-------------|
| `Access denied`     | Failed login attempt — often seen in brute-force attacks. |
| `authentication failed` | Indicates a bad password or missing account. |
| `root`              | Login attempts using the root account — especially from external sources. |
| `plugin authentication` | Plugin issues may reveal misconfigurations or exploit attempts. |

---

### 2.Reconnaissance & Enumeration

| Keyword             | Description |
|---------------------|-------------|
| `SHOW DATABASES`    | Lists all databases — used in discovery or scanning. |
| `SHOW TABLES`       | Lists tables in a selected database. |
| `INFORMATION_SCHEMA`| System table with metadata about all schemas, tables, and columns. |
| `mysql.user`        | Table storing user credentials and privileges — often targeted by attackers. |
| `SELECT user()`     | Reveals current user — used for recon. |
| `SELECT version()`  | Shows the MySQL version — used to identify exploitable versions. |

---

### 3. Suspicious Query Behavior

| Keyword             | Description |
|---------------------|-------------|
| `SELECT * FROM`     | Mass data retrieval — flag if targeting sensitive tables. |
| `UNION SELECT`      | SQL injection pattern often used to extract data from other tables. |
| `OR 1=1`            | Classic SQLi bypass technique — alerts for injection attempts. |
| `INTO OUTFILE`      | Dumps query results into a file — often used for exfiltration. |
| `INTO DUMPFILE`     | Similar to OUTFILE — used in MySQL to dump data or binaries. |

---

### 4. Dangerous SQL Commands

| Keyword             | Description |
|---------------------|-------------|
| `DROP TABLE`        | Deletes a table — can be part of data destruction or ransom attacks. |
| `DROP DATABASE`     | Deletes entire databases — highly destructive. |
| `DELETE FROM`       | Deletes data from a table — suspicious if applied without WHERE clause. |
| `TRUNCATE`          | Empties a table — total data wipe. |
| `UPDATE`            | Modifies rows in a table — mass updates outside business hours are suspicious. |

---

### 5. Remote Code Execution & Plugins

| Keyword             | Description |
|---------------------|-------------|
| `LOAD_FILE()`       | Reads files from the filesystem — can leak sensitive data (e.g., `/etc/passwd`). |
| `LOAD DATA`         | Imports data — can be abused to upload or overwrite content. |
| `SELECT ... FROM DUAL` | Often used in injection payloads or testing expressions. |
| `CREATE FUNCTION`   | Used to install UDFs (User Defined Functions) — a method for RCE. |
| `sys_exec()` / `lib_mysqludf_sys` | Signs of custom UDFs used for system command execution. |

---

### 6. 📤 Data Exfiltration

| Keyword             | Description |
|---------------------|-------------|
| `mysqldump`         | Tool for exporting entire databases — legitimate but dangerous when used improperly. |
| `scp`, `ftp`, `wget`, `curl` | If seen in conjunction with MySQL functions or shells, may indicate exfiltration. |
| `OUTFILE` / `DUMPFILE` | Writes results to files — commonly abused in exfil scenarios. |

---

### 7. 🌐 Network Misuse or Misconfigurations

| Keyword             | Description |
|---------------------|-------------|
| `3306`, `3307`      | Default MySQL ports — watch for connections from external IPs. |
| `bind-address = 0.0.0.0` | Configuration allowing external access — a major misconfiguration. |
| `unauthorized host` | Failed remote connection — may indicate scanning or brute-force attempts. |

---

## Pro Tips

- Alert on access to `mysql.user`, `INFORMATION_SCHEMA`, or `SHOW DATABASES` from unknown users.
- Monitor for `mysqldump` or `INTO OUTFILE` usage, especially by web app users.
- Detect repeated failed logins, especially against `root` or service accounts.
- Monitor for execution of `DROP`, `TRUNCATE`, or mass `DELETE` queries outside business hours.
- Watch for `CREATE FUNCTION` and `lib_mysqludf_sys` — strong indicators of attempted code execution.

---

