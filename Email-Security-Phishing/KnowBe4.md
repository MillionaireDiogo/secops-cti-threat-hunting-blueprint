# 🛡️ KnowBe4 Threat Hunting Guide

## 📌 Overview

KnowBe4 is a leading Security Awareness Training (SAT) platform that enhances organizational cyber resilience by educating employees on current security threats and best practices. It offers one of the largest and regularly updated libraries of training content in the SAT market, alongside phishing simulation campaigns. :contentReference[oaicite:0]{index=0}

KnowBe4 integrates with various security tools to provide a comprehensive approach to threat detection and response. By leveraging KnowBe4's platform, organizations can identify risky user behaviors, automate training assignments, and simulate phishing attacks to strengthen their human firewall. :contentReference[oaicite:5]{index=5}:contentReference[oaicite:6]{index=6}

---

## 📂 Recommended Log Sources & Data Feeds

| Data Source                         | Description |
|-------------------------------------|-------------|
| **KnowBe4 Security Awareness Training (KSAT) Console** | Centralized platform for managing training modules, phishing simulations, and reporting. |
| **PhishER Plus**                    | Tool for analyzing and responding to user-reported phishing emails. |
| **Defend™**                         | Email security solution that integrates with KSAT to provide threat intelligence and automate training assignments. |
| **SecurityCoach**                   | Platform that delivers real-time coaching to users based on detected risky behaviors. |
| **User Events API**                 | API that allows integration of user event data into external systems for enhanced analysis. :contentReference[oaicite:7]{index=7} |

---

## 🔍 Suspicious Keywords & Indicators (with Descriptions)

### 1. 🎣 Phishing Content & Campaign Traits

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `credential`, `secure your account` | Common phishing lures requesting login credentials. |
| `verify`, `update now`, `click here` | Call-to-action text encouraging users to interact. |
| `urgent`, `immediate action required` | Language creating a sense of urgency to prompt quick action. |
| `unusual sign-in activity`, `alert` | Attempting to bypass user caution by mimicking legitimate security alerts. |

### 2. 📌 Report Characteristics & Repetition

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `Multiple users reported`         | Correlated user reports indicating a potential widespread phishing campaign. |
| `Reported within X minutes`       | Sudden spike in reports, suggesting an active attack. |
| `Similar subject lines/URLs`      | Repeated patterns across reports, indicating a coordinated campaign. |
| `ILNs: hash`                       | Duplicate email hashes, suggesting repeated phishing attempts. |

### 3. 🧩 Payload & Attachment Evasion

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `.zip`, `.docm`, `.xlsm`, `.jar`  | Container or macro-enabled files commonly used to deliver malicious payloads. |
| `embedded HTML form`, `JS redirect` | Malicious HTML or JavaScript used in phishing attempts. |
| `password-protected archive`      | Used to evade detection by security filters. |
| `double encoded payload`, `DLL sideload` | Advanced evasion tactics to bypass security measures. |

### 4. 🔒 URL & Link-Based Threat Indicators

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `cofense.link`, `t.co`, `tinyurl` | Shortened URLs often used in phishing to obscure the destination. |
| `ipaddress/.exe`, `download.asp`  | Direct links to executable files or scripts. |
| `typo domain`                     | Misspelled or lookalike domains attempting to mimic legitimate sites. |
| `http-login.microsoft.com`        | Homograph or impersonation domains aiming to deceive users. |

### 5. 🧠 Intelligence & New Campaign Detection

| Keyword / Pattern                  | Description |
|------------------------------------|-------------|
| `Cofense Intelligence IOC match`   | Indicators of Compromise (IOCs) matching known threat intelligence. |
| `Sandbox detonation result: payload` | Dynamic analysis showing malicious behavior. |
| `URL safe/risky changed`          | Status change of URLs from safe to risky, indicating potential threats. |
| `Threat level elevated`           | Increase in threat severity, warranting immediate attention. |

---

## ✅ Pro Tips

- **Correlate reporter events across users over short time frames** to identify campaigns.
- **Watch URL recency and status changes**—a good link yesterday might turn malicious today.
- **Automate ingestion of Cofense IOCs** into SIEM and sandbox tools.
- **Flag archives with password protection or nested attachments**—common evasion layers.
- **Monitor phishing lure text typology** to detect campaign themes (e.g., HR notices, password expiry).
- **Tune triage rules to escalate unknown URLs that are newly active or flagged in intelligence feeds**.

---

### 🔧 Sample SIEM Detection Logic

**Splunk SPL - Multiple Reports within 30 Minutes**  
```spl
index=cofense event=reporter_report
| bucket _time span=30m
| stats dc(src_user) as user_count, values(subject) as subjects by url
| where user_count > 3
