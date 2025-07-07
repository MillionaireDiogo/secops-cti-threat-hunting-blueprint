# Threat Hunting with Fortinet_VPN Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Fortinet VPN (FortiGate SSL and IPSec VPN). Use these indicators to detect unauthorized access, credential abuse, policy evasion, admin abuse, and suspicious network activity.

## Log Sources
- FortiGate VPN Event Logs  
- SSL VPN and IPSec VPN Logs  
- Authentication Logs  
- Admin Activity Logs  
- Failed Login Logs  
- Device Registration Logs  
- Policy Violation Logs  
- Network Traffic Logs  
- API/Integration Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)    | VPN logins from new, unexpected devices or locations.    |
| `MFABypass`, `MFAEnrollmentRemoved`  | Bypassing or disabling multi-factor authentication.      |
| `AccountLocked`, `AccountDisabled`   | Account lockout/disable due to suspicious activity.      |
| `ConcurrentSessions`                 | Multiple simultaneous logins for a single account.       |
| `SessionDurationExceeded`            | Unusually long or persistent sessions.                   |

---

## VPN Session & Connection Events

| **Keyword / Event**                   | **Description / Risk**                                   |
| ------------------------------------- | -------------------------------------------------------- |
| `ConnectionAttempt`                   | Frequent or failed connection attempts (scanning/abuse). |
| `SessionEstablished`, `SessionEnded`  | Unusual timing/duration of VPN sessions.                 |
| `MultipleLogins`                      | Multiple logins in a short timeframe.                    |
| `SplitTunnelingEnabled`               | Potential for data exfiltration/policy evasion.          |
| `EndpointChange`                      | Device or IP changes mid-session.                        |

---

## Policy & Compliance Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `PolicyViolation`                    | Breach of VPN or network policy (e.g., unauthorized app).|
| `ComplianceCheckFailed`              | Device failed security/compliance posture check.         |
| `UnregisteredDevice`                 | Devices not in approved inventory.                       |

---

## Admin & Configuration Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`     | Unusual or failed admin logins.                          |
| `ConfigChange`, `PolicyChange`       | Unexpected configuration or policy changes.              |
| `GroupMembershipChanged`             | User privilege changes for VPN groups.                   |
| `FirmwareUpdate`, `Rollback`         | Unscheduled firmware changes (risk of exploit/backdoor). |

---

## Threat & Advanced Indicators

- VPN access from high-risk or new geographies  
- Rapid logins/logouts or multiple connection failures  
- Split-tunnel usage among high-risk users  
- Devices connecting with unsupported or outdated clients  
- Mass connection failures (potential brute force)  
- Bypassing compliance or security posture checks  
- Admin/config changes outside business hours  
- Sessions with unapproved endpoints/devices  
- Long/lost sessions with excessive data transfer

---

**Tip:**  
Correlate Fortinet VPN logs with endpoint, firewall, and identity monitoring for a holistic remote access security view.

