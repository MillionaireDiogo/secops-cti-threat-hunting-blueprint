# Threat Hunting with DNSFilter Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for DNSFilter—a cloud-based DNS security and content filtering platform. Use these indicators to detect malware, phishing, C2, DNS tunneling, policy evasion, and risky browsing behavior.

## Log Sources
- DNS Query Logs  
- DNSFilter Security Event Logs  
- Threat/Alert Logs  
- Policy Violation Logs  
- Block/Allow List Logs  
- Admin Activity Logs  
- Integration/API Logs  

---

## DNS Query & Web Activity Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `BlockedDomain`, `BlockedRequest`     | Requests to blocked, malicious, or risky domains.        |
| `MalwareDomain`, `PhishingDomain`     | Domains associated with malware, phishing, or C2.        |
| `CommandAndControl`, `C2Domain`       | Communication with known or suspected C2 infrastructure. |
| `NewlySeenDomain`, `UncategorizedDomain`| Queries to domains not previously visited (DGA risk).  |
| `SuspiciousTLD` (e.g., .xyz, .ru, .onion) | Access to suspicious or high-risk TLDs.               |
| `DNS_Tunneling`, `TXTQueryAnomaly`    | DNS tunneling, data exfiltration, or abnormal TXT queries.|
| `UnusualQueryVolume`                  | High number of queries in short period (DGA, beaconing). |

---

## Policy & Security Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `PolicyViolation`                     | Attempted access to restricted categories or domains.    |
| `CategoryBypassAttempt`               | Attempts to circumvent content/category restrictions.    |
| `AllowListChanged`, `BlockListChanged`| Unusual changes to block/allow lists (insider risk).     |
| `SafeSearchDisabled`                  | Circumventing safety or protection features.             |

---

## Admin & Configuration Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`     | Unusual or failed admin logins.                          |
| `ConfigChange`, `PolicyChange`       | Unauthorized or unexpected changes to DNS/security config.|
| `APIKeyCreated`, `APIKeyRevoked`     | New/revoked API keys (automation abuse risk).            |
| `IntegrationAdded`                   | Addition of new integrations (data risk).                |

---

## Threat & Advanced Indicators

- Mass requests to blocked or malicious domains  
- Multiple queries to new or algorithmically generated domains  
- High DNS query volume from single device or subnet  
- Sudden changes to block/allow lists or filtering policies  
- DNS tunneling detected (beaconing, large TXT records, etc.)  
- Access to high-risk TLDs (e.g., .onion, .xyz, .ru)  
- Multiple failed admin logins in short period  
- Configuration changes outside business hours

---

**Tip:**  
Correlate DNSFilter logs with firewall, endpoint, and identity data for comprehensive detection of DNS-layer threats and policy violations.

