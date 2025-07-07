# 🛡️ Mimecast Threat Hunting Guide

## 📌 Overview

Mimecast is a cloud-based email security platform that provides advanced threat protection against phishing, malware, spam, and targeted attacks. It offers a range of services designed to safeguard organizations from email-borne threats, including URL Protection, Attachment Protection, Impersonation Protection, and Internal Email Protect. :contentReference[oaicite:0]{index=0}

---

## 📂 Recommended Log Sources

| Log Source                          | Description |
|-------------------------------------|-------------|
| **Message Logs**                    | Metadata on email flow, including sender, recipient, message ID, and verdicts. |
| **URL Protection Logs**             | Records of URLs clicked or blocked, categorized by risk. |
| **Attachment Protection Logs**      | Information on attachments scanned and sandbox analysis results. |
| **Impersonation Protection Logs**   | Data on detected impersonation attempts and anomalies. |
| **Internal Email Protect Logs**     | Logs of internal and outbound email traffic, including sandboxing and policy enforcement actions. |
| **Admin & Audit Logs**              | Logs detailing policy changes, user actions, and configuration modifications. |
| **Threat Remediation Logs**         | Records of malicious attachments removed from user mailboxes. :contentReference[oaicite:1]{index=1} |

---

## 🔍 Suspicious Keywords & Indicators

### 1. 📨 Suspicious Email & Sender Indicators

| Keyword / Pattern                   | Description |
|-------------------------------------|-------------|
| `SPF fail`, `DKIM fail`, `DMARC fail` | Email authentication failures that suggest spoofing or phishing. |
| `Unusual sender domain`             | Senders from rare or newly registered domains. |
| `Bulk email detected`               | Large volume mail indicating spam or campaigns. |
| `Suspicious subject`                | Subjects containing "urgent", "verify", "account update". |

### 2. 🔗 Malicious URL & Link Activity

| Keyword / Pattern                   | Description |
|-------------------------------------|-------------|
| `URL blocked`, `URL clicked`        | URLs flagged by Mimecast or clicked by users, potentially risky. |
| `URL category: phishing/malware`    | URLs categorized as malicious or suspicious. |
| `URL shortened`                     | Use of URL shorteners to mask destinations. |

### 3. 📎 Malicious Attachments & Payloads

| Keyword / Pattern                   | Description |
|-------------------------------------|-------------|
| `.exe`, `.js`, `.scr`, `.docm`      | Executable or macro-enabled attachments linked to malware. |
| `Sandbox detonation: malware detected` | Attachments flagged as malicious after sandbox analysis. |
| `Password protected archive`        | Common tactic to evade automated scanning. |

### 4. ⚙️ Admin & Configuration Anomalies

| Keyword / Pattern                   | Description |
|-------------------------------------|-------------|
| `Policy change`, `Rule update`      | Changes to email filtering or blocking rules. |
| `Admin login outside business hours` | Potential unauthorized access. |
| `New whitelist/allow rule added`    | Possible weakening of security posture. |

---

## ✅ Pro Tips

- **Correlate reporter events across users over short time frames** to identify campaigns.
- **Watch URL recency and status changes**—a good link yesterday might turn malicious today.
- **Automate ingestion of IOCs** into SIEM and sandbox tools.
- **Flag archives with password protection or nested attachments**—common evasion layers.
- **Monitor phishing lure text typology** to detect campaign themes (e.g., HR notices, password expiry).
- **Tune triage rules to escalate unknown URLs that are newly active or flagged in intelligence feeds**.

---

### 🔧 Example Detection Queries

**Splunk — Detect SPF/DKIM/DMARC Failures**  
```spl
index=mimecast sourcetype=email_logs
| search spf="fail" OR dkim="fail" OR dmarc="fail"
| stats count by sender, recipient, subject
