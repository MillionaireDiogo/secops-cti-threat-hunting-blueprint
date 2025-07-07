# Threat Hunting with Trend Micro Apex One / Vision One Overview

Trend Micro’s Apex One (endpoint protection) and Vision One (XDR platform) provide rich threat telemetry and detection capabilities across endpoints, email, network, and cloud. Threat hunting involves analyzing behavior-based detections, process telemetry, lateral movement indicators, and alert correlations.

Trend Micro supports:
- Endpoint behavior monitoring
- Detection of malware, ransomware, and exploit techniques
- Cross-layer detection via Vision One (XDR)

---

## Log Sources

| Log Source                          | Description                                                                 |
|-------------------------------------|-----------------------------------------------------------------------------|
| **Endpoint Detection Logs**         | Malware, ransomware, and behavior-based detections                          |
| **Behavior Monitoring Logs**        | Suspicious process and script behavior, memory injections, LOLBin use       |
| **Intrusion Prevention Logs (IPS)** | Exploit attempts and network-based attacks                                  |
| **Application Control Logs**        | Blocked or allowed application behavior                                     |
| **Firewall Logs (Apex One)**        | Inbound/outbound network connections                                        |
| **Web Reputation Logs**             | Web-based threat access and URL categorization                              |
| **Email Detection Logs (XDR)**      | Email threats including phishing, spam, malware attachments                 |
| **Vision One Alert & Incident Logs**| Correlated detections from across Trend Micro sensors (XDR-level)           |
| **Process Scan Logs**               | Executable scanning results, including hash, signature, and classification  |

---

## Threat Hunting Keywords

| Keyword                     | Description                                                                  |
|-----------------------------|------------------------------------------------------------------------------|
| `powershell.exe`            | Used for post-exploitation scripting and command execution                   |
| `cmd.exe`                   | Shell used in initial access or lateral movement                             |
| `wscript.exe`               | Executes VBScript; often seen in phishing payloads                           |
| `cscript.exe`               | Console version of WScript; abused for script execution                      |
| `regsvr32.exe`              | LOLBin that executes COM scriptlets or DLLs                                  |
| `rundll32.exe`              | Used to execute DLLs; abused for fileless malware                            |
| `mshta.exe`                 | Executes HTML Application files, typically used in phishing attacks          |
| `svchost.exe`               | Legitimate Windows process; suspicious if spawning non-system binaries       |
| `explorer.exe`              | Should be benign; anomalous if launching PowerShell or cmd                   |
| `mimikatz`                  | Known credential dumping tool                                                |
| `tokenvator`                | Tool for token manipulation or escalation                                    |
| `-EncodedCommand`           | PowerShell flag for executing obfuscated commands                            |
| `IEX`                       | PowerShell `Invoke-Expression` for executing malicious code                  |
| `Invoke-WebRequest`         | PowerShell command for downloading content from the web                      |
| `curl`                      | Often used to download payloads or exfiltrate data                           |
| `wget`                      | Similar to curl; also used for external downloads                            |
| `schtasks.exe`              | Creates scheduled tasks for persistence or delayed execution                 |
| `at.exe`                    | Legacy task scheduler commonly abused in attacks                             |
| `net localgroup`            | Enumerates or modifies administrator group membership                        |
| `whoami /groups`            | Reveals current user’s group memberships and privilege levels                |
| `AppData\\Roaming`          | Malware often writes to this user-writable location                          |
| `Temp\\`                    | Common staging ground for payloads                                           |
| `Public\\`                  | Shared writable directory often abused by malware                            |
| `NT AUTHORITY\\SYSTEM`      | Indicates high-privilege execution                                           |
| `signedBinary`              | Trusted binaries used maliciously (LOLBins)                                  |
| `suspicious_behavior`       | Trend Micro's classification for behavioral-based anomalies                   |
| `malware_detected`          | High-confidence signature or heuristic detection                             |
| `memory_injection`          | Detection of code injection into legitimate processes                        |
| `unauthorized_script`       | Custom script detected or blocked by application control                     |
| `macro_activity`            | Office macro execution behavior                                              |
| `tamper_protection`         | Attempt to disable Trend Micro agent or alter policy settings                |
| `process_hollowing`         | Execution technique where code is injected into legitimate processes         |
| `remote_thread`             | Cross-process thread injection behavior                                      |
| `autorun_registry_key`      | Registry-based persistence technique                                         |
| `parentProcessName`         | Used to trace suspicious process lineage                                     |
| `network_connection_event`  | Outbound/inbound connection attempts, including C2                            |
| `ransomware_behavior`       | Encryption pattern, shadow copy deletion, or rapid file renaming             |
| `XDR_incident_id`           | Correlated detection across endpoint, email, network (Vision One)            |

---

## Additional Steps

- Use these keywords in **Vision One's XDR search**, **Apex One SIEM export**, or native hunting interface
- Correlate endpoint behavior with network or email events using XDR
- Prioritize memory injection, LOLBin abuse, and unauthorized scripts
- Set alerts on obfuscated PowerShell or suspicious child processes
- Enrich hash data and URLs with external threat intelligence (e.g., VirusTotal, Open Threat Exchange)
- Map results to **MITRE ATT&CK** tactics for full lifecycle visibility

