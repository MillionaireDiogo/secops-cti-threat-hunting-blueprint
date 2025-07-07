# Threat Hunting with Windows_Server Overview

This file provides threat hunting hypotheses, detection keywords, suspicious events, and incident response recommendations for Windows Server environments. Windows Servers are central to most enterprise infrastructures and are frequently targeted for privilege escalation, lateral movement, and persistence.

## Log Sources
- Windows Security Event Logs
- Windows System and Application Logs
- PowerShell Operational Logs
- Task Scheduler Logs
- RDP (Remote Desktop Protocol) logs
- Group Policy logs
- Active Directory (AD) logs (for domain controllers)
- Sysmon logs (if deployed)
- Windows Defender/AV logs

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**              | **Description / Threat Scenario**                                        |
|----------------------------------|-------------------------------------------------------------------------|
| `4625` (Failed Logon)            | Unsuccessful login attempts; brute force or password spraying.           |
| `4624` (Successful Logon)        | New or unexpected logins, especially with admin rights or from new IPs.  |
| `4648` (Logon with explicit credentials) | Use of credentials for network logons; risk of lateral movement.      |
| `4672` (Special privileges assigned) | Privilege escalation; admin rights assigned.                           |
| `4688` (Process creation)        | Monitor for suspicious process launches (cmd, powershell, rundll32, etc.).|
| `4697` (Service installed)       | New services created—may indicate persistence or malware install.         |
| `4720` (User account created)    | New local/domain user accounts created.                                  |
| `4722/4723/4724` (Account enabled/changed/unlocked) | Changes to user account status or password.                   |
| `4728/4732/4756` (User added to group) | Addition to privileged groups (Domain Admins, Local Admins, etc.).      |
| `1102` (Audit log cleared)       | Clearing of event logs—common for anti-forensic activity.                |
| `7045` (Service installed)       | New services, especially from non-standard locations.                    |
| `4104` (PowerShell script block) | Suspicious PowerShell use, especially encoded/obfuscated commands.        |
| `logon type=10`                  | Remote (RDP) logins; monitor for unusual sources.                        |
| `scheduled task created`         | Persistence or lateral movement; check task details and user context.     |
| `shadow copy created/deleted`    | Possible ransomware pre-attack or anti-forensic action.                  |
| `mimikatz` / `lsass`             | Known credential dumping activity.                                       |

---

## Windows-Specific Suspicious Operations & Events

- Multiple failed logons followed by a successful one
- Privilege escalation (user added to admin groups, special privileges assigned)
- Installation of unexpected services, drivers, or scheduled tasks
- Abnormal or mass creation of user accounts
- Clearing or tampering with Windows event logs
- Launch of PowerShell, cmd.exe, or other scripting engines with suspicious parameters
- RDP logins from unusual geographic locations or at odd hours
- Unusual file or network activity detected by Defender or AV

---

## High-Risk Behaviors & Use Cases

- Use of administrative tools (psexec, WMI, remote PowerShell) for lateral movement
- Obfuscated PowerShell or script execution
- Addition of users to high-privilege AD groups without change control
- Unexpected shadow copy deletions (possible ransomware preparation)
- Creation of new firewall or registry rules

---

## Advanced Threat Indicators

- Credential dumping from LSASS, mimikatz detection, or memory access
- Use of “living off the land” binaries (LOLBins) for persistence or movement
- Modification of security policies, audit settings, or group policy objects
- Signs of C2 or data exfiltration via unusual protocols/ports
- Use of built-in backup tools for data staging/exfiltration

---

## Response Recommendations

- Enable and monitor all Windows event and audit logs
- Alert on failed/successful logons, privilege escalation, service installs, and log clears
- Restrict admin privileges and enforce least-privilege principles
- Deploy Sysmon for detailed process and network monitoring
- Integrate with SIEM for real-time alerting and correlation
- Regularly audit user, group, and service configurations

---

## References

- [Microsoft Windows Security Auditing Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Blue Team Cheat Sheet – Windows Event IDs](https://docs.splunk.com/Documentation/Splunk/8.0.2/Security/WindowsEventCode)
- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
