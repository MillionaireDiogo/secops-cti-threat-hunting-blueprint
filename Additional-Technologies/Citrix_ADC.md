# Threat Hunting with Citrix_ADC Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Citrix ADC (Application Delivery Controller, formerly NetScaler)—a popular load balancer, application firewall, and remote access gateway. Use these indicators to detect exploitation attempts, unauthorized access, policy evasion, and risky configuration changes.

## Log Sources
- Citrix ADC Syslogs  
- Event and Audit Logs  
- Authentication Logs  
- Configuration Change Logs  
- Web Application Firewall (WAF) Logs  
- Network Traffic Logs  
- Integration/API Logs  
- SSL/TLS Inspection Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New IP/Location)  | Admin/user access from new or unexpected sources.        |
| `AccountLocked`, `AccountDisabled`   | Accounts locked or disabled due to suspicious activity.  |
| `MFABypass`, `MFAEnrollmentRemoved`  | Bypassing or removing multi-factor authentication.       |
| `AdminLogin`, `AdminChange`          | Unusual admin logins or privilege escalations.           |

---

## Network & Load Balancing Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `VirtualServerDown`, `ServiceDown`   | Critical load balancer endpoints/services offline.       |
| `VIPFlapping`, `Failover`            | Frequent failover or service disruptions.                |
| `UnusualTrafficPattern`              | Spikes, DDoS, or anomalous client/server traffic.        |
| `SSLHandshakeFailure`                | SSL/TLS negotiation errors (MITM, misconfig, exploit).   |
| `HighCPUUsage`, `ResourceExhaustion` | Possible DoS attack or abuse.                            |

---

## Web Application Firewall (WAF) Events

| **Keyword / Event**                    | **Description / Risk**                                   |
| -------------------------------------- | -------------------------------------------------------- |
| `WAFRuleTriggered`, `SignatureMatched` | WAF triggered by attack signatures (SQLi, XSS, etc.).    |
| `MaliciousRequestBlocked`              | Requests blocked for known web exploits.                 |
| `DirectoryTraversal`, `PathTraversal`  | Attempts to access unauthorized file paths.              |
| `CommandInjection`, `FileInclusion`    | Detected attempts at code or file injection.             |

---

## Policy & Configuration Events

| **Keyword / Event**                 | **Description / Risk**                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `ConfigChange`, `PolicyChange`      | Unauthorized/suspicious changes to ADC config/policies.  |
| `FirmwareUpdate`, `Rollback`        | Unscheduled firmware upgrades or downgrades.             |
| `CertificateChange`, `CertError`    | SSL/TLS certificate replaced, expired, or misconfigured. |
| `CustomRuleAdded`, `RuleDeleted`    | Unexpected rule modifications in WAF/network policies.   |

---

## Integration & API Monitoring

| **Keyword / Event**          | **Description / Risk**                                 |
| ---------------------------- | ------------------------------------------------------ |
| `APITokenCreated`            | New API tokens (watch for automation/integration abuse).|
| `APIAccessDenied`            | Multiple failed API authentication attempts.           |
| `IntegrationAdded`           | New integrations—verify source/intent.                 |

---

## Advanced Threat Indicators

- Rapid succession of config or policy changes  
- Mass failed login attempts from single or multiple IPs  
- Unexpected firmware upgrades/downgrades  
- Frequent failover or service restarts  
- Repeated WAF blocks for the same client/source IP  
- SSL/TLS handshake failures correlated with spike in traffic  
- Admin actions outside of business hours  
- Disabled logging, WAF, or critical policy features

---

**Tip:**  
Correlate Citrix ADC logs with firewall, endpoint, and SIEM data for a holistic view of application and network risk.

