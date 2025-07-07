# Threat Hunting with CrowdStrike Falcon Overview

CrowdStrike Falcon is a cloud-native EDR platform that provides extensive telemetry across processes, file operations, and user activity. Threat hunting with Falcon involves analyzing:
- Process execution behavior
- Network activity per process
- MITRE ATT&CK-mapped detections
- Behavioral anomalies and suspicious chains
- Indicators of lateral movement, persistence, or credential theft

---

## Log Sources

| Log Source                  | Description                                                                  |
|-----------------------------|------------------------------------------------------------------------------|
| **Detection Events**        | Falcon-detected threats with severity, tactic, technique, and IOC metadata   |
| **Process Execution Logs**  | Details of command-line arguments, parent-child relationships, digital sigs  |
| **Network Activity Logs**   | Per-process DNS, IP, and port-level outbound/inbound network events          |
| **File Activity Logs**      | File creations, modifications, and execution                                 |
| **Registry Activity Logs**  | Registry changes tied to process executions                                  |
| **Sensor Health Logs**      | Agent connectivity, policy status, tamper attempts                           |
| **User Activity Logs**      | Login sessions, interactive logins, remote desktop activity                  |

---

## Threat Hunting Keywords

| Keyword                     | Description                                                                  |
|-----------------------------|------------------------------------------------------------------------------|
| `powershell.exe`            | Commonly abused for remote command execution and script payloads             |
| `cmd.exe`                   | Used for executing commands and scripts in post-compromise phases            |
| `wscript.exe`               | Executes VBScript files; often used in phishing-based attacks                |
| `cscript.exe`               | Console-based script host for executing malicious scripts                    |
| `rundll32.exe`              | Executes DLLs and is abused to launch shellcode                             |
| `regsvr32.exe`              | Used to register DLLs; abused to execute remote scripts                      |
| `mshta.exe`                 | Executes HTA files and is a common LOLBin                                     |
| `svchost.exe`               | Parent to many system services; suspicious when launching user processes      |
| `explorer.exe`              | Often hijacked to spawn malicious processes under user context               |
| `encodedcommand`            | PowerShell flag for obfuscated or base64-encoded payloads                    |
| `IEX`                       | PowerShell command used to dynamically execute strings or web content        |
| `Invoke-WebRequest`         | PowerShell function used to download files from external sources             |
| `curl`                      | Used for data exfiltration or downloading payloads                           |
| `wget`                      | Similar to curl; typically anomalous on Windows                              |
| `mimikatz`                  | Credential dumping tool used for stealing user passwords and tokens          |
| `tokenvator`                | Tool used for impersonation or privilege escalation                          |
| `bypass`                    | Related to disabling security tools or script block logging                  |
| `add-mppreference`          | PowerShell command used to modify Defender settings (AV evasion)             |
| `schtasks.exe`              | Task scheduler for persistence via scheduled task creation                   |
| `at.exe`                    | Legacy scheduler, often abused for persistence                               |
| `net localgroup`            | Modifies or enumerates administrative user groups                            |
| `whoami /groups`            | Shows user’s privilege level; often used before privilege escalation         |
| `AppData\\Roaming`          | Drop location for malware and scripts                                        |
| `Public\\`                  | Writable location, often used for staging payloads                           |
| `Temp\\`                    | Common for file drops and script staging                                     |
| `NT AUTHORITY\\SYSTEM`      | Indicates SYSTEM-level execution (privilege escalation indicator)            |
| `SignedBinary`              | Trusted binary potentially abused for malicious execution (LOLBins)          |
| `suspicious`                | Falcon detection classification indicating risky behavior                    |
| `malicious`                 | Falcon detection classification for confirmed threats                        |
| `mitreTactic`               | MITRE ATT&CK tactic (e.g., Defense Evasion, Execution) from detection logs   |
| `mitreTechnique`            | Specific technique ID or name tied to an alert or activity                   |
| `tamper`                    | Refers to attempts to disable or interfere with the Falcon agent             |
| `remote thread`             | Sign of possible code injection via thread creation across processes         |
| `process hollowing`         | A technique where a process is replaced in memory by malicious code          |

---

## Additional Steps

- Use these keywords in your SIEM (e.g., Splunk, Microsoft Sentinel, Elastic) to build queries and alerts
- Correlate Falcon telemetry with network, identity, and email logs
- Leverage CrowdStrike's MITRE ATT&CK alignment for tracking TTPs
- Create dashboards or visual process trees to identify suspicious parent-child relationships
- Consider using Falcon's **Falcon Discover**, **Threat Graph**, or **Overwatch** intel feeds for enrichment

