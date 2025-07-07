# Threat Hunting with Microsoft Defender for Endpoint (MDE) Overview

Microsoft Defender for Endpoint (MDE) is a robust EDR solution that provides deep visibility into endpoint behavior and integrates natively with the Microsoft ecosystem. It supports advanced threat hunting through its rich telemetry and integration with Microsoft 365 Defender.

Threat hunting in MDE focuses on:
- Real-time and historical endpoint telemetry
- MITRE ATT&CK-aligned detections
- Behavioral analytics
- Process trees and command-line data
- Threat intelligence enrichment

---

## Log Sources

| Log Source                        | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| **DeviceProcessEvents**           | Captures process creation, command-line arguments, parent-child links       |
| **DeviceNetworkEvents**           | Logs outbound/inbound network connections per process                       |
| **DeviceFileEvents**              | File creation, modification, and execution events                           |
| **DeviceRegistryEvents**          | Registry modifications tied to process activity                             |
| **DeviceLogonEvents**             | Logon sessions, user account activity, remote access                        |
| **DeviceImageLoadEvents**         | DLLs and modules loaded by processes                                        |
| **AlertEvidence and Alerts**      | MDE-generated detections with severity, category, and MITRE mappings        |
| **DeviceEvents**                  | Generic event data across multiple categories                               |
| **DeviceInfo**                    | Asset data, sensor health, OS, security posture                             |

---

## Threat Hunting Keywords

| Keyword                     | Description                                                                  |
|-----------------------------|------------------------------------------------------------------------------|
| `powershell.exe`            | Commonly used for script-based attacks and remote code execution             |
| `cmd.exe`                   | Native shell used in various stages of attack                               |
| `wscript.exe`               | Executes VBScripts; often abused in phishing payloads                        |
| `cscript.exe`               | Console-based script host with similar usage to wscript                      |
| `rundll32.exe`              | Executes DLLs; frequently abused for shellcode and payloads                  |
| `regsvr32.exe`              | LOLBin used for registering and executing DLLs or scripts                    |
| `mshta.exe`                 | Executes HTA (HTML Application) files; often seen in phishing                |
| `svchost.exe`               | System service host; suspicious when spawning abnormal processes             |
| `explorer.exe`              | Suspicious when used to execute scripts or malware under user context        |
| `mimikatz`                  | Credential dumping tool detected by behavior or string patterns              |
| `tokenvator`                | Tool used for impersonation or escalation via token manipulation             |
| `-EncodedCommand`           | PowerShell flag used for base64-obfuscated commands                          |
| `IEX`                       | PowerShell's `Invoke-Expression`, often used for executing remote scripts    |
| `Invoke-WebRequest`         | PowerShell function used to download files                                   |
| `curl`                      | File download and data exfiltration tool (suspicious when used by scripts)   |
| `wget`                      | Similar to curl; typically seen in file download scenarios                   |
| `schtasks.exe`              | Used to create scheduled tasks (often abused for persistence)                |
| `at.exe`                    | Legacy Windows task scheduler tool                                          |
| `net localgroup`            | Used to modify or enumerate admin groups                                     |
| `whoami /groups`            | Checks for user group membership and privileges                              |
| `AppData\\Roaming`          | Common drop location for malware in user context                             |
| `Temp\\`                    | Frequently used for staging payloads                                         |
| `Public\\`                  | Writable location often abused for persistence or staging                    |
| `NT AUTHORITY\\SYSTEM`      | Indicates SYSTEM-level execution, possibly due to escalation                 |
| `SignedBinary`              | Trusted signed binaries abused for execution (LOLBins)                       |
| `suspicious`                | Behavioral detection flag in Defender telemetry                              |
| `malicious`                 | Confirmed threat classification by Defender                                  |
| `TTPs`                      | Indicates ATT&CK tactic/technique used in an alert or detection               |
| `tamper`                    | Attempts to disable Defender features or bypass protections                  |
| `ImageLoad`                 | DLL or module load events; useful for detecting DLL injection                |
| `remote thread`             | Indicates possible cross-process injection via remote thread creation         |
| `process hollowing`         | A technique where benign processes are replaced in memory by malicious code  |
| `WMI`                       | Windows Management Instrumentation; often used for stealthy execution         |
| `ParentProcessId`           | Field used to trace suspicious parent-child execution chains                 |
| `InitiatingProcessFileName` | Useful for tracking which process initiated a network or file operatio

## Additional Steps

- Use these keywords in Microsoft Defender’s **Advanced Hunting (KQL)** portal or Microsoft Sentinel
- Correlate process behavior with command-line patterns and network destinations
- Monitor for rare parent-child relationships, LOLBin usage, and obfuscated scripts
- Integrate with Microsoft Threat Intelligence (TI) and MITRE ATT&CK dashboards
- Build hunting queries and custom alerts using **DeviceProcessEvents**, **DeviceNetworkEvents**, etc.
