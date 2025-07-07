# Threat Hunting with CylancePROTECT & CylanceOPTICS Overview

Cylance is an AI-driven endpoint protection platform focused on prevention-first strategies. While CylancePROTECT is focused on pre-execution malware prevention, CylanceOPTICS provides EDR-level visibility and enables threat hunting by collecting contextual telemetry.

Threat hunting with Cylance primarily involves:
- Reviewing process behavior and command-line arguments
- Investigating file execution and quarantine actions
- Analyzing threats by AI model classification
- Tracing lateral movement, persistence, and evasion techniques

---

## Log Sources

| Log Source                  | Description                                                                 |
|-----------------------------|------------------------------------------------------------------------------|
| **Threat Detection Logs**   | Logs of malware detections, file hashes, model scores, and classifications   |
| **Process Execution Logs**  | Data on process launches, parent-child relationships, command-line usage     |
| **Quarantine Events**       | Details about blocked or quarantined files                                  |
| **Script Control Logs**     | Execution of scripts (PowerShell, VBS, JS) and policy enforcement            |
| **Device Control Logs**     | Device access attempts (e.g., USB drives)                                   |
| **Sensor Health Logs**      | Agent status, tamper detection, and policy drift                             |
| **Contextual Graph (OPTICS)**| Visual/linked telemetry about process relationships and behaviors            |

---

## Threat Hunting Keywords

| Keyword                     | Description                                                                  |
|-----------------------------|------------------------------------------------------------------------------|
| `powershell.exe`            | Used for script execution and post-exploitation activity                     |
| `cmd.exe`                   | Command-line execution used in various stages of attack                      |
| `wscript.exe`               | Executes VBScript files; often abused in phishing                            |
| `cscript.exe`               | Script host for console-based execution                                      |
| `rundll32.exe`              | Executes DLLs and is frequently used in code execution attacks               |
| `regsvr32.exe`              | LOLBin used to execute remote scriptlets or COM objects                      |
| `mshta.exe`                 | Executes HTA applications; abused in malicious documents                     |
| `svchost.exe`               | Critical system binary; suspicious if launching unusual processes            |
| `explorer.exe`              | Parent of user-launched applications; may be abused in masquerading          |
| `mimikatz`                  | Credential dumping tool                                                       |
| `tokenvator`                | Tool for token manipulation and escalation                                   |
| `encodedcommand`            | PowerShell flag for base64-encoded, obfuscated scripts                       |
| `IEX`                       | PowerShell command used to execute code passed as string                     |
| `Invoke-WebRequest`         | Downloads files from external locations via PowerShell                       |
| `add-mppreference`          | PowerShell command to disable Windows Defender                               |
| `schtasks.exe`              | Used to schedule persistent or delayed execution tasks                       |
| `at.exe`                    | Legacy task scheduling tool, commonly abused                                 |
| `net localgroup`            | Adds or enumerates admin-level group members                                 |
| `whoami /groups`            | Checks privilege level of current user                                       |
| `AppData\\Roaming`          | Common malware drop location under user context                              |
| `Temp\\`                    | Frequently used for staging and executing payloads                           |
| `Public\\`                  | World-writable location often abused by malware                              |
| `NT AUTHORITY\\SYSTEM`      | Sign of execution under elevated SYSTEM privileges                           |
| `signedBinary`              | Legitimate signed binary abused for malicious use (LOLBins)                  |
| `script_control_violation`  | Indicates blocked or suspicious script execution                             |
| `quarantine_event`          | Indicates a file was blocked or removed by Cylance agent                     |
| `high_model_score`          | AI model has flagged file with high likelihood of being malicious            |
| `classified_malicious`      | Cylance model classification for known or unknown malware                    |
| `classified_suspicious`     | Heuristic or behavioral match, flagged for investigation                     |
| `policy_bypass_attempt`     | Possible attempt to evade or disable security policy                         |
| `agent_unhealthy`           | Sensor health event indicating possible tampering or failure                 |

---

## Additional Steps

- Use these keywords in CylanceOPTICS query interface or integrated SIEM (Splunk, Sentinel, etc.)
- Cross-reference Cylance model classifications with hash and reputation sources (e.g., VirusTotal)
- Investigate process ancestry for unusual parent-child relationships
- Focus on script execution and LOLBin abuse under non-admin users
- Monitor for patterns of high-model-score binaries that executed before detection/quarantine

