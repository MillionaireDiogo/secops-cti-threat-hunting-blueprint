# Microsoft 365 Threat Hunting Overview

Proactive monitoring of user activity, emails, file access, and admin actions in Microsoft 365 to detect threats like phishing, data leaks, account compromise, and unauthorized changes.

## Log Sources

- Unified Audit Log (UAL)
- Azure AD Sign-In Logs  
- Microsoft Defender for Office 365 Logs

### Authentication & Identity (Azure AD Sign-in Logs)

| **Activity Type**        | **Log Keywords**                                                                 |
|--------------------------|----------------------------------------------------------------------------------|
| **Login Failure**        |  BadPassword                                                                     |
| **MFA Failure**          | MFA denied, MFA failed, MFA requirement satisfied: false                         |
| **Impossible Travel**    | Risky sign-in, Unusual location, Impossible travel                               |
| **Legacy Authentication**| ClientAppUsed: Other clients, Legacy protocol                                    |
| **Token Theft / Reuse**  | Token replay detected, Refresh token misuse                                      |
| **Suspicious IP**        | RiskLevel: high, Location: TOR, IP address                                       |
| **Consent Grant Attack** | Consent to application, Grant delegated permissions, OAuth2PermissionGrant       |

---

### Email Activity 

| **Activity Type**        | **Log Keywords**                                                                |
|--------------------------|---------------------------------------------------------------------------------|
| **Email Forwarding**     | New-InboxRule, ForwardTo, ForwardAsAttachmentTo, RedirectTo                     |
| **BEC / Suspicious Rule**| Set-InboxRule, AutoForward, MessageType: Email, Action: Redirect                |
| **Phishing**             | MalwareFilterPolicy, Phish delivered, Phish removed, ZAP                        |
| **URL Click Tracking**   | ClickedUrl                                                                      |
| **Mailbox Access**       | MailItemsAccessed, MailboxLogin, Non-Owner                                      |
| **Spoof Detection**      | SPF=fail, DKIM=fail, DMARC=fail, AuthenticationFail                             |

---
### Parsed Fields 

| **Activity Type**         | **ELog Keywords**                                              |
|---------------------------|----------------------------------------------------------------|
| `OperationName`           | `Set-Mailbox`, `Add-MailboxPermission`, `UserLoggedIn`         |
| `ResultStatus`            | `Failed`, `Success`, `PartiallySucceeded`                      |
| `ClientAppUsed`           | `IMAP`, `POP3`, `Browser`, `Mobile Apps`                       |
| `ActorIPAddress`          | Unusual IPs, TOR, geolocation outliers                         |
| `UserAgent`               | `PowerShell`, `SkyDriveSync`, `Outlook`                        |
| `Workload`                | `Exchange`, `SharePoint`, `AzureActiveDirectory`               |

