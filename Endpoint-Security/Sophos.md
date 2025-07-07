# Threat Hunting with Sophos Intercept X (EDR/XDR) Overview

Sophos Intercept X with EDR/XDR provides endpoint and server visibility, supporting advanced threat hunting and forensic investigations. It allows security teams to query device telemetry, correlate across multiple data sources, and detect threats using behavioral and rule-based analytics.

Threat hunting in Sophos focuses on:
- Process execution and parent-child relationships
- Threat detections and AI classification
- Script and macro execution
- Network activity and lateral movement
- Policy violations and tampering

---

## Log Sources

| Log Source                        | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| **Threat Protection Events**      | Malware, ransomware, exploit detections, and AI verdicts                    |
| **Process Execution Logs**        | Details of executable files, command lines, hashes, and parent processes    |
| **Application Events**            | Script interpreter launches, Office macro behavior, exploit prevention      |
| **Network Events (XDR)**          | Network connections, DNS queries, lateral movement attempts                 |
| **Device Control Logs**           | USB and peripheral device access                                            |
| **Tamper Protection Logs**        | Attempts to disable or alter Sophos protection                              |
| **Web Control & App Control Logs**| Application execution and category-based web access logs                    |
| **Data Lake (XDR)**               | Unified telemetry from endpoints, servers, firewalls, and cloud workloads   |

---

## Threat Hunting Keywords

| Keyword                     | Description                                                                  |
|-----------------------------|------------------------------------------------------------------------------|
| `powershell.exe`            | Used for scripting and post-exploitation tasks                              |
| `cmd.exe`                   | Common shell used in attacks                                                |
| `wscript.exe`               | Executes VBScript files; used in phishing payloads                          |
| `cscript.exe`               | Console version of WScript, often abused by attackers                       |
| `regsvr32.exe`              | LOLBin used to execute scripts and DLLs remotely                            |
| `rundll32.exe`              | Executes DLLs; often used for fileless attacks                              |
| `mshta.exe`                 | Executes HTA applications; abused in phishing and malware delivery           |
| `explorer.exe`              | Parent of many user-launched processes; suspicious if launching scripts      |
| `svchost.exe`               | Hosts Windows services; watch for unusual child processes                    |
| `mimikatz`                  | Credential theft tool detectable via behavior or string detection            |
| `tokenvator`                | Privilege escalation tool using token impersonation                          |
| `-EncodedCommand`           | PowerShell flag for executing base64-encoded content                        |
| `IEX`                       | PowerShell expression used to dynamically execute code                      |
| `Invoke-WebRequest`         | Downloads remote content or scripts                                         |
| `curl`                      | File download tool often used in attacks                                    |
| `wget`                      | Alternative to curl; often found in malicious scripts                       |
| `schtasks.exe`              | Creates scheduled tasks (persistence mechanism)                              |
| `at.exe`                    | Legacy scheduling tool used for persistence                                 |
| `net localgroup`            | Used to enumerate or alter admin groups                                     |
| `whoami /groups`            | Checks current user privileges                                               |
| `AppData\\Roaming`          | Malware often writes payloads to this location                              |
| `Temp\\`                    | Used by malware to stage or launch payloads                                 |
| `Public\\`                  | Writable by all users; suspicious for malware staging                       |
| `NT AUTHORITY\\SYSTEM`      | Indicates execution as SYSTEM (privilege escalation)                         |
| `signedBinary`              | Legitimate signed binaries used maliciously (LOLBins)                       |
| `malicious`                 | AI classification of file or process as malicious                           |
| `suspicious`                | Behavioral detection of potentially dangerous activity                      |
| `exploit_detected`          | Detection of exploit attempts (e.g., ROP, memory corruption)                |
| `script_blocked`            | Indicates script execution was stopped by policy                            |
| `macro_execution`           | Office macro behavior detected                                               |
| `parentProcessId`           | Used for tracing process lineage and identifying anomalous launches         |
| `tamper_protection_event`   | Logs attempts to disable Sophos security components                         |
| `ransomware_detected`       | Indicates ransomware behavior (encryption patterns, shadow copy deletion)    |
| `DataLakeQuery`             | Keyword for querying across Sophos Data Lake (XDR)                          |
| `rareParentProcess`         | Suspicious parent/child process combination                                 |

---

## Additional Steps

- Use these keywords with Sophos Central’s **Live Discover**, **XDR SQL**, or your integrated SIEM
- Focus on behavioral detections, process lineage, and script execution patterns
- Use **Data Lake queries** to correlate endpoint, firewall, and cloud activity
- Build custom alerts and reports based on LOLBin usage, obfuscation, or policy evasion
- Map your hunt results to MITRE ATT&CK tactics for strategic threat coverage

