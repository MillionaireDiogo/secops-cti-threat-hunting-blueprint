# Threat Hunting with Exchange_Server Overview

This file covers threat hunting keywords, suspicious activity indicators, and log sources for Microsoft Exchange Server—on-premises or hybrid email and calendar infrastructure. Use these indicators to detect account compromise, privilege escalation, email abuse, phishing, and lateral movement.

## Log Sources
- Exchange Server Message Tracking Logs  
- Admin Audit Logs  
- Protocol Logs (SMTP, IMAP, POP, OWA, EWS)  
- Security Event Logs  
- Mailbox Audit Logs  
- Threat/Alert Logs  
- Policy & Compliance Logs  
- Device Registration Logs  
- Integration/API Logs  

---

## Authentication & Access Events

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed`| Multiple/repeated failed logins (possible brute force).  |
| `SuccessfulLogin` (New Device/IP)    | Access from new or unusual devices, IPs, or geolocations.|
| `MFABypass`, `MFAEnrollmentRemoved`  | Bypassing or removing multi-factor authentication.       |
| `SessionHijack`, `SessionExtended`   | Suspicious session reuse or extension.                   |
| `OAUTHGrant`, `DelegatedAccess`      | Risky OAuth/third-party access granted.                  |

---

## Email Sending & Receiving Activity

| **Keyword / Event**                  | **Description / Risk**                                   |
| ------------------------------------ | -------------------------------------------------------- |
| `BulkSend`, `MassMail`               | Large volume of outbound mail (potential spam/phishing). |
| `UnusualAttachment`, `FileTypeBlocked`| Sending/receiving risky or blocked attachments.         |
| `ExternalForwarding`, `AutoForward`  | Auto-forwarding to external domains (exfiltration risk). |
| `ReplyToExternal`, `ExternalContact` | High volume of external correspondence (risk of phishing).|
| `SpoofingDetected`                   | Attempts to impersonate domains or users.                |
| `TransportRuleChange`                | New or modified mail flow rules (possible exfiltration). |
| `MailboxExport`, `PSTExport`         | Export of mailbox or mass email data.                    |

---

## Admin & Privilege Events

| **Keyword / Event**                 | **Description / Risk**                                   |
| ----------------------------------- | -------------------------------------------------------- |
| `AdminLogin`, `FailedAdminLogin`    | Unusual or failed admin logins.                          |
| `RoleAssignmentChange`, `RoleEscalation`| Privilege escalation or assignment of risky roles.    |
| `MailboxPermissionChanged`          | New mailbox permissions (delegation, full access, etc.). |
| `AdminAuditLogCleared`              | Deleting/clearing of audit logs (covering tracks).       |

---

## Policy & Configuration Events

| **Keyword / Event**                     | **Description / Risk**                                   |
| --------------------------------------- | -------------------------------------------------------- |
| `ConfigChange`, `PolicyChange`          | Unauthorized changes to config or compliance policies.   |
| `AntiSpamBypass`, `AVBypass`            | Disabling spam or anti-virus protection.                 |
| `TransportRuleDisabled`, `RuleBypassed` | Disabling or bypassing mail flow/transport rules.        |
| `RemotePowershellEnabled`               | Opening up remote administration access (attack surface).|
| `IntegrationAdded`, `APIKeyCreated`     | New integrations, API keys, or connectors (risk review). |

---

## Threat & Advanced Indicators

- Mass outbound email in short time window  
- Creation of mail forwarding rules to external addresses  
- Attachment of risky or blocked file types  
- Multiple failed logins from unfamiliar locations  
- Surge in privilege escalation or admin actions  
- Clearing of audit logs or disabling of logging  
- Suspicious OAuth or application integrations  
- Unusual mailbox exports or PST file creations

---

**Tip:**  
Correlate Exchange logs with endpoint, DLP, and SIEM alerts for better detection of account compromise, phishing, and insider threats.

