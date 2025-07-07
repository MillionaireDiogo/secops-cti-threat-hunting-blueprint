# Threat Hunting with Carbon Black Overview

Threat hunting with Carbon Black focuses on high-fidelity telemetry collected from endpoints. It enables deep visibility into:
- Process execution trees
- Network connections
- Binary metadata
- File and registry modifications
- Cross-process and code injection behaviors

CB’s powerful search and response capabilities make it ideal for proactive threat detection and incident scoping.

---

## Log Sources

| Log Source               | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| **Process Logs**         | Detailed metadata on every executed process, including parent/child linkage |
| **Binary Metadata**      | Metadata about files/binaries (hash, signer, reputation)                    |
| **Network Connections**  | Outbound/inbound network activity per process                               |
| **Registry Modifications**| Registry key creation/deletion/modification                                |
| **File Modifications**   | File creation, modification, deletion events                                |
| **Cross-Process Events** | Process injection, thread creation across processes                         |
| **Sensor Health Logs**   | Agent connectivity, status, tamper events                                   |

---

## Threat Hunting Keywords

| Keyword                   | Description                                                                |
|---------------------------|----------------------------------------------------------------------------|
| `powershell.exe`          | Often used in attacks for execution of scripts and payloads                |
| `cmd.exe`                 | Frequently used in post-exploitation tasks                                 |
| `wmic.exe`                | Used for system reconnaissance and persistence                             |
| `regsvr32.exe`            | LOLBin that can execute code via COM scriptlets                            |
| `rundll32.exe`            | Used to execute DLLs and often misused for payload delivery                |
| `mshta.exe`               | Executes HTML Applications (HTAs); used for malicious scripts              |
| `svchost.exe`             | Windows system process; suspicious when launching user binaries            |
| `explorer.exe`            | Abused to spawn child processes under user context                         |
| `encodedcommand`          | PowerShell method of obfuscating payloads using base64                     |
| `IEX`                     | PowerShell `Invoke-Expression`; often used to run remote code              |
| `Invoke-WebRequest`       | PowerShell function used to download remote files                          |
| `curl`                    | Used in scripts to download payloads                                       |
| `wget`                    | Alternative to curl for file download; unusual on Windows systems          |
| `mimikatz`                | Credential dumping tool commonly used by attackers                        |
| `tokenvator`              | Privilege escalation and token manipulation tool                           |
| `bypass`                  | Keyword indicating AV/EDR evasion techniques                               |
| `add-mppreference`        | PowerShell command to modify Defender settings                             |
| `schtasks.exe`            | Used to schedule malicious tasks for persistence                           |
| `at.exe`                  | Legacy task scheduling tool, often used in attacks                         |
| `net localgroup`          | Enumeration or modification of admin groups                                |
| `whoami /groups`          | Command to check current user privileges                                   |
| `AppData\\Roaming`        | Common directory used to drop or execute payloads                          |
| `Public\\`                | Writable folder targeted by malware                                        |
| `Temp\\`                  | Temp directories used for payload staging                                  |
| `NT AUTHORITY\SYSTEM`     | Indicates execution under SYSTEM account (privilege escalation)            |
| `SignedBinary`            | Legitimate signed binaries abused in LOLBins                               |
| `injected_thread`         | Indicates potential process injection behavior                             |
| `crossproc_open`          | Cross-process operation; often a precursor to code injection               |
| `reg create`              | Registry key creation, potential persistence mechanism                     |
| `HKLM\\...\\Run`          | Registry autostart location for persistence                                |
| `suspicious`              | Binary classification by Carbon Black                                      |
| `malicious`               | Confirmed threat classification by Carbon Black                            |
| `tamper`                  | Indicates attempts to disable or interfere with CB agent                   |

---

## Additional Steps

- Use these keywords in CB's query interface or your integrated SIEM (e.g., Splunk, Sentinel, Elastic)
- Correlate with MITRE ATT&CK TTPs for context
- Investigate process trees for parent/child anomalies
- Leverage CB’s watchlists and alert feeds for enrichment
- Prioritize cross-process and injection alerts for in-depth review

