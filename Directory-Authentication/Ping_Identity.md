# 🛡️ Ping Identity Threat Hunting Guide

## 📌 Overview

[Ping Identity](https://www.pingidentity.com) provides enterprise-grade identity and access management (IAM) services including **PingFederate** (SSO, federation), **PingOne** (IDaaS), **PingAccess** (access control), and **PingDirectory** (LDAP). These systems are often the gateway to sensitive cloud and on-premise resources, making them prime targets for:

- Credential stuffing
- MFA abuse or bypass
- SSO misuse
- Session/token theft
- API key abuse
- Misconfiguration or backdoors via integration points

Effective threat hunting in Ping Identity involves collecting and analyzing identity logs to detect abnormal access patterns, API misuse, policy tampering, and privilege escalation.

---

## Recommended Log Sources

| Source                             | Description |
|------------------------------------|-------------|
| **PingFederate Server Logs**       | Authentication events, session info, errors |
| **PingOne Audit & Activity Logs**  | User activity, app access, MFA, provisioning |
| **PingAccess Audit Logs**          | Access control decisions, policy enforcement |
| **PingDirectory Access Logs**      | LDAP binds, searches, and modifications |
| **SIEM / Log Stream Integrations** | Forward logs to Splunk, ELK, Sentinel, etc. |
| **MFA Provider Logs**              | Detect MFA fatigue and abnormal flows |

---

## Suspicious Keywords & Events (with Descriptions)

### 1. Authentication Failures & Anomalies

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `AuthenticationFailure`          | General login failure — monitor volume per IP/user |
| `InvalidCredentials`, `BindFailure` | LDAP bind failures — could be brute-force |
| `AccountLockout`, `TooManyFailures` | Indicates possible password spraying |
| `GeoVelocityViolation`           | Impossible travel detection |
| `NewDeviceLogin`                 | First-time login from a new device/browser |
| `MFAChallengeFailed`             | Repeated MFA failure — potential push bombing |
| `UnknownClientID`, `UnknownApp`  | Application impersonation or misconfigured app trying to authenticate |

---

### 2. Privilege Escalation & Admin Abuse

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `RoleAssigned`, `UserPromoted`   | Elevated permissions granted — verify context |
| `UserModified`, `GroupModified`  | Group membership or user role changed |
| `AdminLogin`                     | Admin authentication — flag unfamiliar source IP or user |
| `ConfigurationChange`            | Generic system config change — monitor who/when/what |
| `DirectorySchemaModified`        | Directory schema changed — high risk if unauthorized |

---

### 3. 🧨 Session & Token Abuse

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `AccessTokenIssued`, `RefreshTokenUsed` | Monitor for excessive or out-of-policy token usage |
| `TokenReplayDetected`            | Reuse of expired/used token — possible session hijack |
| `SessionHijackDetected`          | Ping anomaly detection alert — confirm with login IP/device/user agent |
| `SSOSessionCreated`              | Single Sign-On session established — check for high-value app access |
| `SSOSessionTerminatedUnexpectedly` | Session killed without logout — investigate tampering or timeout abuse |

---

### 4. 🌐 IP / Geo / Device-Based Indicators

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `AnomalousLocation`              | Login from unusual geographic location |
| `HighRiskIP`, `SuspiciousIP`     | Matches known threat IPs or anonymizers |
| `DeviceMismatch`                 | New or different device used — check if user is traveling |
| `UserAgentAnomaly`               | Strange browser or client fingerprint (CLI tools, bots, etc.) |

---

### 5. Configuration & Policy Tampering

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `PolicyChanged`, `RuleModified`  | Access, authentication, or routing policy modified |
| `MFAConfigChanged`               | May reduce or disable MFA enforcement |
| `CertificateReplaced`            | TLS/Signing cert changed — check for unauthorized swaps |
| `APIClientSecretRotated`         | API client key changed — validate audit trail |
| `ApplicationRegistration`        | New app integration — flag suspicious or unvetted additions |

---

### 6. Provisioning, SSO, and Directory Abuse

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `UserProvisioned`, `UserDeprovisioned` | Watch for rogue provisioning to sensitive apps |
| `BulkProvisioning`               | Could be legitimate — or abuse of SCIM/API |
| `LDAPSearch`                     | Large volume or wildcards may indicate recon |
| `SSOLoginFailure`                | Failed login to federated app — check for SAML misuse |
| `SPInitiatedLogin`, `IdPInitiatedLogin` | SAML/OIDC initiation paths — monitor unexpected flows |

---

## Additional Tips

- Enable **PingOne Audit Logs** and integrate them with your SIEM.
- Monitor for repeated `AuthenticationFailure` events from a single IP across users.
- Alert on new **admin role assignments** and **API client registrations**.
- Flag changes to **SSO configurations**, **policy rules**, or **MFA settings**.
- Correlate **access token issuance** with suspicious user agents or geo shifts.
- Use `device fingerprinting` + `IP context` to catch lateral movement or token abuse.

---
