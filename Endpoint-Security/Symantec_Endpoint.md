# Threat Hunting with Symantec Endpoint Security (SES/SEP) Overview

Symantec Endpoint Security (SES) is a comprehensive solution that combines prevention, detection, and response capabilities. With EDR and behavioral analysis features, SES enables threat hunters to investigate:
- Malware and suspicious behaviors
- Process execution trails
- Tampering and policy violations
- Application and device control activity

SES supports integration with SIEMs and has advanced logging when EDR features are enabled.

---

## Log Sources

| Log Source                        | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| **Application Control Logs**      | Logs application launches, anomalies, and policy violations                 |
| **System Activity Logs**          | Includes process execution, registry changes, and file activity             |
| **Device Control Logs**           | USB and external device usage                                               |
| **Intrusion Prevention Logs**     | Logs exploit attempts and network-based attacks                             |
| **Antivirus and Antimalware Logs**| Malware detections, quarantine actions, and remediation status              |
| **Tamper Protection Logs**        | Logs attempts to disable or interfere with Symantec protections             |
| **EDR (if enabled)**              | Enhanced process telemetry, detections, threat paths, and indicators        |
| **Symantec ICDx (Integrated Cyber Defense Exchange)** | Centralized event forwarding to SIEMs                     |

---

## Threat Hunting Keywords

| Keyword                     | Description                                                                  |
|-----------------------------|------------------------------------------------------------------------------|
| `powershell.exe`            | Commonly used for post-exploitation scripting and remote payloads            |
| `cmd.exe`                   | Native shell, frequently used in attack chains                              |
| `wscript.exe`               | Executes VBScript files, often used in phishing and malware staging          |
| `cscript.exe`               | Console-based script engine, similar abuse profile to wscript                |
| `rundll32.exe`              | Executes DLLs; often misused in fileless and reflective injection attacks    |
| `regsvr32.exe`              | Used for executing scriptlets and DLLs remotely (LOLBins)                    |
| `mshta.exe`                 | Executes HTML applications; common in phishing and downloaders               |
| `mimikatz`                  | Credential theft tool often flagged by behavioral heuristics                 |
| `tokenvator`                | Used for Windows token impersonation and privilege escalation                |
| `-EncodedCommand`           | PowerShell flag for executing base64-encoded payloads                        |
| `IEX`                       | PowerShell `Invoke-Expression`, used for dynamic execution                   |
| `Invoke-WebRequest`         | PowerShell cmdlet for downloading malicious content                          |
| `curl`                      | Network utility used to download or exfiltrate data                          |
| `wget`                      | Similar to curl, sometimes used in scripts                                   |
| `schtasks.exe`              | Used to establish persistence by scheduling tasks                            |
| `at.exe`                    | Legacy scheduler often abused by malware                                     |
| `net localgroup`            | Enumeration or manipulation of administrative group memberships              |
| `whoami /groups`            | Displays current user privileges                                              |
| `AppData\\Roaming`          | Common drop site for malware under user context                              |
| `Temp\\`                    | Used for payload staging and execution                                       |
| `Public\\`                  | World-writable folder often abused by malware                                |
| `NT AUTHORITY\\SYSTEM`      | Execution context indicating SYSTEM privileges                               |
| `signedBinary`              | Abuse of trusted signed binaries (LOLBins) for execution                     |
| `tamper_protection`         | Attempts to disable or bypass Symantec protections                           |
| `heuristic`                 | Behavior-based detection classification, may indicate zero-day activity       |
| `suspicious`                | Classification used by SES for potentially unwanted or anomalous behavior     |
| `malicious`                 | Confirmed detection by static or behavioral engine                           |
| `threat_path`               | EDR feature that shows the execution path of the detected threat             |
| `network_event`             | Logs related to suspicious or blocked outbound/inbound connections           |
| `parentProcessName`         | Key field to trace origin of suspicious process trees                        |
| `remote_thread`             | Behavior associated with process injection across boundaries                 |
| `dll_injection`             | Indicates suspicious dynamic library injections                              |
| `autorun_registry_key`      | Registry keys associated with persistence (e.g., Run, RunOnce)               |

---

## Additional Steps

- Use these keywords in **Symantec ICDx**, **EDR search interface**, or your connected SIEM (e.g., Splunk, Sentinel)
- Focus on behaviors such as LOLBin abuse, privilege escalation, and obfuscated script execution
- Correlate parent-child process chains for anomalous execution patterns
- Monitor `tamper protection` and `heuristic` logs for early-stage or targeted attacks
- Integrate IOC enrichment from external sources (VirusTotal, STIX, threat feeds)
- Map results to MITRE ATT&CK techniques for coverage validation

