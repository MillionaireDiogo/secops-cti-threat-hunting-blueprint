# Threat Hunting with F5_BIG-IP_LoadBalancer Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for F5 BIG-IP—an enterprise application delivery controller (ADC), load balancer, and security platform. Use these indicators to detect exploitation attempts, unauthorized access, application abuse, DDoS, and risky configuration changes.

## Log Sources
- F5 BIG-IP Syslogs  
- LTM (Local Traffic Manager) Event Logs  
- ASM (Application Security Manager/WAF) Logs  
- APM (Access Policy Manager) Logs  
- iRules and Custom Script Logs  
- Audit and Admin Activity Logs  
- Network Traffic Logs  
- API/Integration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New IP/Location)  | Admin/user access from new/unexpected sources.           |
| `MFABypass`, `MFAEnrollmentRemoved`  | Bypassing or removing multi-factor authentication.       |
| `AccountLocked`, `AccountDisabled`   | Account lockouts or disablement due to abuse.            |
| `AdminLogin`, `AdminChange`          | Unusual admin logins or privilege escalations.           |

---

## Network, Load Balancing & Application Events

| **Keyword / Event**                    | **Description / Risk**                                   |
| -------------------------------------- | -------------------------------------------------------- |
| `PoolMemberDown`, `NodeDown`           | Critical endpoints or nodes offline.                     |
| `VIPFlapping`, `Failover`              | Frequent failover or service instability.                |
| `UnusualTrafficSpike`                  | Spikes, DDoS, or anomalous client/server traffic.        |
| `SSLHandshakeFailure`, `TLSAlert`      | SSL/TLS negotiation errors (exploit, misconfig, MITM).   |
| `HTTPFlood`, `SlowlorisDetected`       | Application DoS/DDoS attack patterns detected.           |
| `MalformedRequest`, `AppAnomaly`       | Malformed or exploitative traffic targeting applications.|

---

## Web Application Firewall (ASM) Events

| **Keyword / Event**                      | **Description / Risk**                                   |
| ---------------------------------------- | -------------------------------------------------------- |
| `WAFViolation`, `SignatureMatched`       | WAF triggered by attack signatures (SQLi, XSS, RCE, etc).|
| `MaliciousRequestBlocked`                | Requests blocked for known exploits.                     |
| `DirectoryTraversal`, `PathTraversal`    | Attempts to access unauthorized file paths.              |
| `CommandInjection`, `FileInclusion`      | Detected attempts at code or file injection.             |
| `BotDetected`                            | Automated/bot traffic identified and blocked.            |

---

## Policy & Configuration Events

| **Keyword / Event**                 | **Description / Risk**                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `ConfigChange`, `PolicyChange`      | Unauthorized or risky configuration/policy changes.      |
| `FirmwareUpdate`, `Rollback`        | Unscheduled or suspicious firmware upgrades/rollbacks.   |
| `CertificateChange`, `CertError`    | SSL/TLS certificate replaced, expired, or misconfigured. |
| `iRuleAdded`, `iRuleDeleted`        | Unexpected changes to custom iRules/scripts.             |

---

## Integration & API Monitoring

| **Keyword / Event**            | **Description / Risk**                                   |
| ------------------------------ | -------------------------------------------------------- |
| `APITokenCreated`              | New API tokens—watch for automation/integration abuse.   |
| `APITokenRevoked`              | API token revocation (confirm if legitimate).            |
| `APIAccessDenied`              | Failed API authentication attempts.                      |
| `IntegrationAdded`             | New integrations—verify source/intent.                   |

---

## Advanced Threat Indicators

- Rapid succession of config, policy, or iRule changes  
- Mass failed login attempts from single or multiple IPs  
- Frequent failover or node down events  
- Repeated WAF blocks or bot detections for the same client/source IP  
- SSL/TLS handshake failures correlated with traffic spikes  
- Admin or API actions outside of business hours  
- Disabling of WAF or logging features  
- Application attacks correlated with network anomalies

---

**Tip:**  
Correlate F5 BIG-IP logs with firewall, SIEM, and application logs for a holistic view of application delivery, load balancing, and security risk.

