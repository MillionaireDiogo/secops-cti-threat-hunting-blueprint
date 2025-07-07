# Microsoft SQL Server Threat Hunting Overview

## Overview

Microsoft SQL Server is a critical database engine, often targeted by attackers to gain access to sensitive data, execute arbitrary code, or move laterally in a network. Common attack vectors include:

- **Brute force / password spraying**
- **SQL Injection**
- **Abuse of xp_cmdshell or sp_executesql**
- **Unauthorized privilege escalation**
- **Lateral movement via linked servers**

---

## Recommended Log Sources

| Source Type                 | Description / Use |
|----------------------------|-------------------|
| **SQL Server Error Logs**  | Failed login attempts, database-level activity, errors. |
| **Windows Event Logs**     | Authentication attempts, privilege escalation, service actions. |
| **SQL Server Audit Logs**  | Tracks T-SQL activity like SELECT, EXECUTE, and more. |
| **Firewall / Network Logs**| Unusual port access (default 1433), exfiltration attempts. |
| **Sysmon (if available)**  | Process creation, command-line logging, network connections. |
| **Azure Monitor / Defender for SQL** | Cloud telemetry for SQL databases on Azure. |

---

## Suspicious Keywords 

### 1.Command Execution / `xp_cmdshell` Abuse

| Keyword        | Description |
|----------------|-------------|
| `xp_cmdshell`  | Executes OS commands from SQL Server. Often abused to run arbitrary code. |
| `sp_configure` | Used to enable/disable features like `xp_cmdshell`. Watch for configuration changes. |
| `cmd.exe`      | Windows command interpreter; used for OS-level actions from SQL. |
| `powershell`   | Powerful scripting engine. Often used in post-exploitation for downloading payloads or recon. |
| `wscript`, `cscript` | Used to execute VBScript or JScript files — commonly abused for persistence. |
| `curl`, `wget` | Tools used to download files from the internet. Rare in SQL context. |
| `bitsadmin`    | A utility to download/upload files; often used for stealthy data exfiltration. |

---

### 2.Reconnaissance & Metadata Access

| Keyword             | Description |
|---------------------|-------------|
| `sp_help`, `sp_helptext` | Used to list or read metadata, such as stored procedures or views. Useful for attacker recon. |
| `sp_tables`         | Lists all tables in a database — reconnaissance indicator. |
| `information_schema` | Contains metadata about database objects like tables, columns, etc. |
| `sysobjects`, `syscolumns`, `sysdatabases`, `syslogins` | System views used to enumerate objects, users, and privileges. |
| `xp_logininfo`      | Reveals login/user mapping and privileges. Used for privilege escalation or mapping. |

---

### 3. ⚠️ Suspicious SQL Operations / Injection Primitives

| Keyword           | Description |
|-------------------|-------------|
| `UNION SELECT`    | SQL injection payload often used to extract data from different tables. |
| `SELECT * FROM`   | Mass data exfiltration indicator — querying all rows/columns. |
| `INSERT INTO`, `DROP TABLE`, `ALTER TABLE` | Indicates attempts to modify or destroy data. |
| `EXECUTE AS`      | Executes code as another user — can be abused to escalate privileges. |
| `EXEC xp_`        | Executing extended stored procedures, often dangerous (`xp_cmdshell`, etc). |
| `sp_executesql`   | Executes dynamic SQL, often seen in injection or obfuscation scenarios. |
| `OPENQUERY`       | Executes pass-through queries on linked servers — lateral movement vector. |

---

### 4. 🚪 Authentication / Brute Force Indicators

| Keyword         | Description |
|------------------|-------------|
| `Login failed`   | Generic failed login attempt; could be brute-force. |
| `18456`          | Common error code for login failures in SQL Server. |
| `sa login failed`| Specific brute-force targeting the `sa` (sysadmin) account. |
| `account locked` | Account was locked after too many failed logins. |
| `login timeout`  | Could indicate automated login attempts or DoS against SQL. |

---

### 5. 🔗 Linked Server Abuse

| Keyword               | Description |
|------------------------|-------------|
| `sp_addlinkedserver`   | Adds a linked server — used for lateral movement or pivoting. |
| `sp_addlinkedsrvlogin` | Adds a login to access the linked server — credential abuse. |
| `OPENROWSET`           | Executes queries on remote data sources — may be used for data theft. |
| `OPENDATASOURCE`       | Another method to access remote data — suspicious in unusual environments. |
| `linked_server`        | A general keyword to catch linked server references. |

---

### 6. 📤 Data Exfiltration Indicators

| Keyword        | Description |
|----------------|-------------|
| `BULK INSERT`  | Imports data from external files. Can also be abused for staging or exfil. |
| `OUTFILE`      | Writes query output to a file — may indicate local data dumping. |
| `INTO DUMPFILE`| MySQL-style data dump. Rare in SQL Server, but worth hunting if logs include cross-DB indicators. |
| `ftp`, `http`  | Protocols seen in logs or command-lines that could indicate data transfer. |

---

### 7. 🧬 Living-off-the-Land Binaries (LOLBins)

| Keyword       | Description |
|----------------|-------------|
| `powershell`  | Script execution tool — often used by attackers. |
| `certutil`    | Used to download payloads or encode/decode data. |
| `mshta`       | Executes HTA applications — can download and run malicious scripts. |
| `regsvr32`    | Registers DLLs; can be used to run code from remote sources. |
| `rundll32`    | Executes DLL exports — common in malware loading. |
| `schtasks`    | Used to create scheduled tasks — persistence method. |

---

## Additional Tips

- Monitor for `xp_cmdshell` being enabled or executed.
- Alert on excessive failed logins or brute force targeting the `sa` account.
- Investigate queries accessing metadata tables or using `EXEC xp_` commands.
- Watch for suspicious network activity to/from port 1433 (default SQL Server).
- Use time-of-day filters to flag admin activity during non-business hours.

---
