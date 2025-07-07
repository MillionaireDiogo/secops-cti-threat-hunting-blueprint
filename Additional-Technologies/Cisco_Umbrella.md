# Threat Hunting with Cisco_Umbrella Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Cisco Umbrella—a cloud-based DNS-layer security and secure internet gateway platform. Use these indicators to detect malicious domains, phishing, policy evasion, and suspicious network activity.

## Log Sources
- DNS Query Logs  
- Umbrella Security Event Logs  
- Proxy & Web Activity Logs  
- Policy Violation Logs  
- Admin Activity Logs  
- API/Integration Logs  
- Threat/Alert Logs  

---

## DNS & Web Activity Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `BlockedRequest`, `BlockedDomain`     | Requests to blocked or malicious domains.                |
| `MalwareDomain`, `PhishingDomain`     | Access to domains associated with malware/phishing.      |
| `CommandAndControl`, `C2Domain`       | Known C2 infrastructure contacted.                       |
| `NewDomainAccessed`, `NewlySeenDomain`| Access to domains not previously visited (DGA risk).     |
| `SuspiciousTopLevelDomain`            | Access to TLDs like `.xyz`, `.ru`, `.cn`, `.onion`.      |
| `UncategorizedDomain`                 | Access to domains without reputation or category.        |
| `DNS_Tunneling`, `UnusualTXTQuery`    | Signs of DNS tunneling or data exfiltration.             |
| `BlockedFileDownload`                 | Blocked download of risky files via web proxy.           |
| `HTTPSInspectionBypass`               | Bypassing HTTPS/SSL inspection (possible evasion).       |

---

## Policy & Security Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `PolicyViolation`                    | Violation of security or content access policies.        |
| `ContentCategoryBlocked`             | Attempts to access prohibited content categories.        |
| `SafeSearchDisabled`                 | User disables or circumvents SafeSearch/restrictions.    |
| `BypassAttempt`, `ProxyBypass`       | Attempts to circumvent proxy or DNS-layer protections.   |
| `ThreatAlert`, `MalwareDetected`     | Detected threats or suspicious activity by Umbrella.     |

---

## Authentication & Admin Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`     | Unusual or failed admin logins.                          |
| `ConfigChange`, `PolicyChange`       | Unauthorized or unexpected changes to config/policies.   |
| `APIKeyCreated`, `APIKeyRevoked`     | API key creation or revocation—monitor for abuse.        |
| `IntegrationAdded`                   | New integrations or third-party app connections.         |

---

## Integration & API Monitoring

| **Keyword / Event**            | **Description / Risk**                                 |
| ------------------------------ | ------------------------------------------------------ |
| `APITokenCreated`              | Creation of new API tokens (possible automation risk). |
| `FailedAPIAccess`              | Failed API authentication attempts.                    |
| `ThirdPartyAppAdded`           | Addition of external apps or integrations.             |
| `IntegrationError`             | Errors or failures in security integrations.           |

---

## Advanced Threat Indicators

- Repeated access to blocked/malicious domains  
- Mass queries to new or algorithmically generated domains  
- DNS tunneling detected across multiple hosts  
- Policy bypass or HTTPS inspection disabled  
- Surge in access to suspicious TLDs (e.g., `.xyz`, `.onion`)  
- Multiple failed admin logins in short period  
- Admin or API configuration changes outside business hours  
- Increase in malware, C2, or phishing alerts

---

**Tip:**  
Correlate Cisco Umbrella logs with endpoint, firewall, and identity security data for comprehensive protection against internet-borne threats.

