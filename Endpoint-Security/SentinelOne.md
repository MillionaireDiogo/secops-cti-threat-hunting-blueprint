# Threat Hunting with SentinelOne Overview

Threat hunting is a proactive approach to identify threats that may bypass traditional security mechanisms. With SentinelOne, focus areas include:
- Endpoint behavior monitoring
- Detection of TTPs (Tactics, Techniques, Procedures)
- Analysis of anomalies and correlations
- Identification of potential lateral movement, persistence, and privilege escalation

---

## Log Sources

| Log Source            | Description                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Agent Telemetry**   | Tracks process creation, network connections, file and registry activity     |
| **Threat Logs**       | Includes detections, MITRE mappings, threat classification                   |
| **Storyline Logs**    | Contextual event chains tying together related activities                    |
| **Mitigation Logs**   | Logs quarantine, process termination, rollback, etc.                         |
| **Agent Status Logs** | Reports on agent health, connectivity, and tamper attempts                   |

---

## Threat Hunting Keywords

| Keyword                  | Description                                                               |
|--------------------------|---------------------------------------------------------------------------|
| `powershell.exe`         | Common tool abused for scripting and post-exploitation                    |
| `cmd.exe`                | Native Windows shell often used in attacks                                |
| `regsvr32.exe`           | LOLBin used for code execution and bypassing controls                     |
| `rundll32.exe`           | Executes DLLs; frequently abused for executing malicious payloads         |
| `mshta.exe`              | Executes HTA files; often used in phishing payloads                       |
| `wscript.exe`            | Executes Windows Script Host files; used for automation and scripting     |
| `cscript.exe`            | Console-based script host; similar abuse patterns as `wscript.exe`        |
| `Base64`                 | Indicator of encoded payloads or obfuscated commands                      |
| `-enc`                   | PowerShell flag for encoded commands                                      |
| `IEX`                    | PowerShell `Invoke-Expression`, used to execute dynamic code              |
| `Mimikatz`               | Common tool for credential theft                                          |
| `tokenvator`             | Tool used for token manipulation and privilege escalation                 |
| `schtasks.exe`           | Used to schedule tasks, often for persistence                             |
| `net localgroup`         | Command to enumerate or alter admin group memberships                     |
| `whoami /groups`         | Reveals current user privileges                                            |
| `HKLM\\...\\Run`         | Registry path used for persistence                                        |
| `AppData\\Local\\Temp`   | Path where malware is often dropped temporarily                           |
| `Public\\`               | Writable directory often abused by malware                                |
| `Living off the Land`    | General term for abuse of legitimate binaries (LOLBins)                   |
| `EncodedCommand`         | PowerShell execution method using base64-encoded strings                  |
| `Invoke-WebRequest`      | Used in scripts to download payloads from remote servers                  |
| `New-Object`             | Used in PowerShell to create .NET objects, often abused in attacks        |
| `Add-MpPreference`       | May indicate tampering with Windows Defender settings                     |
| `Suspicious`             | SentinelOne classification indicating potential malicious behavior        |
| `Malicious`              | SentinelOne classification indicating confirmed malicious activity        |
| `mitreTactic`            | Tactic (e.g., Initial Access, Execution) mapped by SentinelOne detection  |
| `mitreTechnique`         | Specific ATT&CK technique ID associated with a threat                     |

---

## Additional Steps

- Use these keywords to construct hunting queries in your SIEM (e.g., Sentinel, Splunk)
- Map findings to MITRE ATT&CK for context
- Correlate SentinelOne telemetry with other sources like firewall, proxy, or identity logs
- Use Sigma rules to translate findings into alertable logic

