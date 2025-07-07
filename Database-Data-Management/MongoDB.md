# MongoDB Threat Hunting Overview

MongoDB is a popular NoSQL database, often used in modern web applications. Because of its default configurations (especially older versions) and REST-like access over HTTP/JSON, it's a frequent target for attackers looking to:

- Exploit misconfigurations (e.g., no authentication, public exposure)
- Enumerate collections/documents
- Abuse the MongoDB shell for command execution
- Drop or ransom databases
- Pivot through database drivers (Node.js, Python, etc.)

---

## Recommended Log Sources

| Source Type                  | Description / Use |
|-----------------------------|-------------------|
| **MongoDB Log File**        | Authentication attempts, commands executed, connections. |
| **MongoDB Audit Logs**      | (If enabled) Tracks read/write/command activity per user. |
| **System Logs (syslog/eventlog)** | OS-level changes, especially on self-hosted MongoDB. |
| **Firewall / Network Logs** | Unusual external access to MongoDB default port `27017`. |
| **Cloud Provider Logs**     | If using MongoDB Atlas, include cloud IAM/auth activity. |
| **MongoDB Atlas Activity Feed** | Tracks changes like IP whitelist modifications or DB-level events. |

---

## Suspicious Keywords

### 1. Authentication & Unauthorized Access

| Keyword             | Description |
|---------------------|-------------|
| `authentication failed` | Indicates failed login attempt — often seen in brute-force attacks. |
| `SCRAM-SHA-1`, `SCRAM-SHA-256` | Auth mechanisms — log entries with repeated attempts can indicate brute-force. |
| `unauthorized`      | A user tried to perform an action without proper permissions. |
| `login failed`      | Generic login failure message — abnormal frequency is suspicious. |

---

### 2. Enumeration / Reconnaissance

| Keyword             | Description |
|---------------------|-------------|
| `listDatabases`     | Lists all databases — common during recon or compromise. |
| `listCollections`   | Lists collections in a database — attacker trying to map structure. |
| `db.getCollectionNames()` | JavaScript shell command to list collections. |
| `db.stats()`        | Returns storage and collection-level stats. Useful for data profiling. |
| `db.currentOp()`    | Reveals currently running operations — abused for recon. |
| `db.version()`      | Reveals MongoDB version — used to assess vulnerabilities. |

---

### 3. Data Modification / Destruction

| Keyword             | Description |
|---------------------|-------------|
| `dropDatabase`      | Drops the entire database — common in ransom or destructive attacks. |
| `drop()`            | Drops a collection — targeted data destruction. |
| `remove()`          | Deletes one or many documents. Could be malicious. |
| `deleteMany()` / `deleteOne()` | API variants for document deletion — watch for mass deletions. |
| `updateMany()`      | Mass modification of data — often used maliciously to overwrite records. |

---

### 4. Remote Code Execution / System Command Abuse

| Keyword             | Description |
|---------------------|-------------|
| `runCommand`        | Used to issue database or administrative commands. Can be used maliciously. |
| `eval`              | Executes JavaScript code on the database server. Major risk for RCE if enabled. |
| `db.eval()`         | Shell method to execute arbitrary code on the server. Dangerous if not disabled. |
| `$where`            | Allows JavaScript execution in queries. Can be abused for complex injections. |

---

### 5. Data Exfiltration & Dumping

| Keyword             | Description |
|---------------------|-------------|
| `find()`            | Basic document read operation — flag high-volume or bulk queries. |
| `aggregate()`       | Used for complex queries or joins — watch for suspicious patterns. |
| `mongoexport`       | Tool to dump data to JSON or CSV — often used for exfiltration. |
| `backup`            | Look for backup activity outside maintenance windows. |
| `scp`, `ftp`, `curl`, `wget` | Look for use in shell commands if `eval()` or system abuse is possible. |

---

### 6. Network Access Patterns

| Keyword             | Description |
|---------------------|-------------|
| `27017`, `27018`, `27019` | Default MongoDB ports — look for inbound connections from suspicious IPs. |
| `remote connection` | Connection attempts from unusual geolocations or networks. |
| `bind_ip`           | Misconfigurations allowing external access (e.g., `0.0.0.0`). |

---

## Additional Tips

- Monitor for repeated failed authentication attempts (brute-force indicators).
- Alert on use of `eval`, `$where`, or `db.eval()` — all high-risk functions.
- Detect unusual data access patterns (e.g., `find()` with wildcards or no filters).
- Look for commands like `dropDatabase` and `remove()` outside maintenance hours.
- Flag unexpected remote connections, especially if bind IP is public (`0.0.0.0`).
- Regularly review audit logs if enabled — they provide the most granular user-level activity.

---

