# Active Directory Threat Hunting Overview

Active Directory (AD) is the backbone of identity and access management in Windows environments. It’s a high-value target for adversaries who aim to:

- Escalate privileges
- Move laterally
- Exfiltrate credentials or data
- Persist via account or GPO manipulation

---

## Recommended Log Sources

| Source                           | Description / Use |
|----------------------------------|-------------------|
| **Security Event Logs (Windows)** | Logon events, privilege use, account lockouts, group changes |
| **Directory Services Logs**      | Changes to AD objects, replication issues, schema modifications |
| **DNS Server Logs**              | Lookups that may indicate recon (e.g., DC discovery, SPNs) |
| **Sysmon Logs**                  | Process creation, network connections, DLL loads |
| **Firewall / VPN Logs**          | Remote connections, pivoting |
| **Audit Policy / Group Policy Logs** | GPO creation/modification |
| **LDAP / Kerberos Logs**         | Authentication and enumeration patterns |

---

## Suspicious Keywords 

### 1. Authentication & Logon Abuse

| Keyword / Event ID     | Description |
|------------------------|-------------|
| `4625`                 | Failed logon — track volume and sources to detect brute-force attacks. |
| `4624` (Type 3 or 10)  | Successful network/logon — look for unusual times or sources. |
| `4771`, `4768`, `4769` | Kerberos pre-auth and TGS events — monitor for AS-REP Roasting and overuse. |
| `4740`                 | Account lockouts — possible brute-force or DoS. |
| `NTLM`                 | Weak auth protocol — may indicate downgrade or legacy system abuse. |

---

### 2. Enumeration & Reconnaissance

| Keyword                | Description |
|------------------------|-------------|
| `dsquery`, `net group`, `net user` | Tools commonly used in recon. |
| `nltest`, `whoami`, `setspn`       | AD-specific discovery commands. |
| `ldapsearch`, `ldap://`            | LDAP queries — used in automated recon. |
| `SPN`, `ServicePrincipalName`      | SPN enumeration — possible precursor to Kerberoasting. |
| `Get-ADUser`, `Get-ADGroup`        | PowerShell AD recon — legitimate, but monitor scope and users. |
| `BloodHound`, `SharpHound`         | Tools for mapping AD — leaves distinct access patterns. |

---

### 3. Privilege Escalation

| Keyword / Event ID     | Description |
|------------------------|-------------|
| `4670`                 | Permissions on object changed — privilege escalation or persistence. |
| `4728`, `4729`         | User added/removed from privileged group (e.g., Domain Admins). |
| `4732`, `4756`         | Add to security groups — monitor sensitive groups. |
| `AdminSDHolder`        | Modification of this object can grant persistent admin rights. |
| `Golden Ticket`, `KRBTGT`, `mimikatz` | Known attack indicators for ticket forging. |
| `DCSync`, `replicate`, `Directory Replication Service` | Abuse of DC replication to dump credentials. |

---

### 4. Persistence Mechanisms

| Keyword / Event ID     | Description |
|------------------------|-------------|
| `ScheduledTask`, `schtasks.exe` | Common persistence method. |
| `GPO`, `GroupPolicy`, `gpresult` | Manipulation for persistence or lateral movement. |
| `Startup`, `Run key`   | Registry-based persistence. |
| `Remote Desktop Enabled`, `rdp-tcp` | RDP enabling without authorization. |
| `4720`, `4722`         | Account created or enabled — monitor by source and user. |
| `4738`                 | Account modified — often used to elevate privileges or hide changes. |

---

### 5. Credential Access & Dumping

| Keyword                | Description |
|------------------------|-------------|
| `lsass.exe`, `procdump`, `rundll32` | Tools used to dump memory for credentials. |
| `mimikatz`, `Invoke-Mimikatz`       | Credential theft tool — highly suspicious. |
| `sekurlsa`, `logonpasswords`        | Mimikatz modules. |
| `ntds.dit`, `SYSTEM`                | Files used to extract password hashes from DCs. |
| `sam`, `security hive`              | Windows hives for local credential dumping. |

---

### 6. Lateral Movement Indicators

| Keyword / Event ID     | Description |
|------------------------|-------------|
| `PsExec`, `WMI`, `Invoke-Command` | Remote command execution tools. |
| `WinRM`, `SMB`, `RPC`              | Lateral movement protocols. |
| `RDP`, `mstsc.exe`                 | Remote Desktop usage. |
| `RemoteInteractive`, `Type 10` logons | RDP logins — flag from unexpected sources. |
| `pass-the-hash`, `pass-the-ticket` | Credential reuse techniques — often hard to detect. |

---

### 7. Domain Controller / GPO Tampering

| Keyword / Event ID     | Description |
|------------------------|-------------|
| `Default Domain Policy`, `GPO` | Changes here affect all users — high impact. |
| `Group Policy Object Editor`, `gpedit.msc` | Admin tools used to change policies. |
| `Directory Service Changes`     | Audit log for AD object modifications. |
| `4662`                 | Special permissions assigned to an object — watch closely. |
| `Shadow Credentials`, `KeyCredentialLink` | Modern persistence via alternate auth mechanisms. |

---

## Additional Tips

- Enable **Advanced Security Audit Policies** for granular tracking.
- Monitor **event ID 4662** (object permissions) for silent privilege escalations.
- Track group membership changes in **Domain Admins**, **Enterprise Admins**, and **Backup Operators**.
- Watch for **scheduled tasks**, **service installs**, and **remote command execution** across endpoints.
- Use **Sysmon** to track `lsass.exe`, `cmd.exe`, `rundll32`, and `powershell.exe` with command-line auditing.
- Detect **Kerberoasting** by filtering event ID `4769` for service tickets requested using RC4 encryption.
- Cross-reference **user behavior** with known attack tools (e.g., Mimikatz, SharpHound, Empire).

---

