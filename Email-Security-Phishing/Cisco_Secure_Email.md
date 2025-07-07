# Cisco Secure Email Gateway Threat Hunting Overview

Cisco Secure Email Gateway (formerly ESA) is a powerful email security solution that sits at the edge of your mail flow. It helps detect and block spam, malware, phishing, and other email-based threats. Attackers often try to:

- Bypass spam and antivirus filters  
- Evade malware detection  
- Deliver phishing campaigns with embedded URLs or credential harvesters  
- Exploit misconfigurations or admin credentials  
- Use compromised mail relay for spamming or exfiltration

Threat hunting focuses on suspicious SMTP behavior, admin changes, policy tuning, high-risk attachments/URLs, and anomalous volume spikes.

---

## Recommended Log Sources

| Log Source                    | Description / Use |
|-----------------------------|--------------------|
| **Message Tracking Logs**   | Flow metadata: sender, recipient, timestamps, SMTP commands |
| **Spam/AV Scan Logs**       | Detection results and engine verdicts |
| **Attachment & URL Logs**   | Records of attachments scanned, URLs extracted and categorized |
| **Admin & Audit Logs**      | Config changes, policy updates, CLI/web GUI actions |
| **System/Event Logs**       | OS-level issues, system restarts, service failures |
| **SIEM Integration**        | Forward all logs to Splunk, ELK, Sentinel, etc., for correlation |

---

## Suspicious Keywords & Patterns (with Descriptions)

### 1. High-Risk Attachment or URL Patterns

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `.exe`, `.js`, `.scr`, `.hta`      | Executables or script attachments commonly used in malware |
| `Office .docm`, `.xlsm`, `.pptm`   | Macro-enabled Office files — often used to deliver payloads |
| `URL category: “phishing”`         | URLs flagged by ESA intelligence as phishing |
| `URL not scanned`, `URL unreachable` | Potential evasion or drop zones |
| `Attachment renamed .txt`          | Renamed executables to bypass filters |

---

### 2. Phishing & Spoofing Indicators

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `Header From != Envelope From`     | SPF/DMARC misalignment — common in spoofing |
| `Sender Reputation: Low`           | Sender flagged as suspicious by threat intel |
| `Authenticated vs. Unauthenticated senders` | Look for inbound unauthenticated emails from external domains |
| `DMARC: none/fail`, `SPF softfail` | Email authentication failures — warning signs |

---

### 3. Malware & Scanning Evasion Tactics

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `Macro-enabled document`, `OLE2 link` | Malware embedded via Office macros |
| `Base64-encoded content`, `ZIP > 10MB` | Large or encoded payload attachments |
| `Attachment archived within archive` | Double/Triple zips for filter evasion |
| `Filename with Unicode`, `Filename with spaces` | Obfuscation tactics to trick filters |

---

### 4. Volume & Volume Anomalies

| Metric / Pattern                   | Description |
|-----------------------------------|-------------|
| `Email burst from single IP`       | Sudden high-volume inbound spikes — indicator of campaigns |
| `Outbound volume surge`            | Could indicate exfiltration or spam relay abuse |
| `Multiple recipients`, `BCC clusters` | Mass-mail campaigns or phishing targeting |

---

### 5. Admin Interface & Policy Changes

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `Policy updated`, `Content filter changed` | Tuning that may weaken security |
| `TLS setting changed`            | Could affect email encryption enforcement |
| `Admin login`, `Remote service restart` | Watch for user activity outside normal hours |
| `Custom regex added`, `Custom header insert` | May be used to bypass detection or facilitate phishing |

---

## Additional Tips

- Integrate Cisco logs with your SIEM for cross-correlation with endpoints and network events.  
- Baseline normal volume and sender patterns to detect anomalies quickly.  
- Create alerts for macro-enabled attachments, double-zipped files, or base64 attachments above a volume threshold.  
- Alert on DMARC/SPF failures—especially from high-profile or internal domains.  
- Monitor admin changes, especially to mail policies, spam thresholds, or BCC handling.  
- Correlate spikes in outbound email volume with DLP or sandbox detections (via DNS, proxy, or endpoint signals).

---
