# Okta Threat Hunting Overview

[Okta](https://www.okta.com) is a leading Identity-as-a-Service (IDaaS) platform providing centralized user authentication, SSO, and MFA. As the identity gateway for many SaaS and enterprise environments, it is a high-value target for attackers seeking:

- Account takeover (ATO)
- Bypassing or abusing MFA
- Privilege escalation
- Persistence via API tokens or integrations
- Unauthorized application access

---

## Recommended Log Sources

| Source                            | Description |
|-----------------------------------|-------------|
| **Okta System Logs**              | Primary event stream for all Okta activities |
| **Okta API Logs**                 | Covers token usage, administrative actions |
| **SIEM Log Integrations**         | Forward logs to Splunk, ELK, Sentinel, etc. |
| **MFA Provider Logs**             | Helps identify MFA fatigue, push bombing, or bypass |
| **SSO Integration Logs**          | Look for SAML/OIDC session abuse in connected apps |
| **Identity Threat Detection Alerts** | Available via Okta ThreatInsight or third-party EDR/XDR |

---

## 🔍 Suspicious Keywords & Events 

### 1. Authentication Failures & Anomalies

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `user.authentication.failed`     | Generic login failure — repeated from same IP may indicate brute-force |
| `user.session.start`             | Monitor for logins from new geos/devices |
| `user.account.lock`              | Lockout from excessive login attempts |
| `user.mfa.verification_failed`   | Repeated MFA failures — may signal MFA fatigue attack |
| `security.threat.detected`       | Okta ThreatInsight detection — may include IP reputation alerts |
| `user.authentication.auth_via_mfa_rejected` | User rejected push notification — could be MFA bombing attempt |

---

### 2. 🧑‍💻 Admin & Privilege Escalation

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `user.account.privilege.grant`   | User granted admin or elevated privileges |
| `user.account.update_profile`    | Admin modifies user details — watch for unauthorized role changes |
| `group.user_membership.add`      | Addition to privileged group (e.g., Super Admins, App Admins) |
| `application.assignment.add`     | App assigned to user — flag if high-value apps (e.g., AWS, GCP, Salesforce) |
| `system.api_token.create`        | New API token created — verify legitimacy |
| `user.account.unlock`            | Admin manually unlocked a suspiciously locked account |

---

### 3. 📤 Token Abuse & API Exploitation

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `system.api_token.*`             | API token created, deleted, or used — monitor for misuse or persistence attempts |
| `system.oauth2.access_token.*`   | Monitor excessive token generation or token reuse |
| `client_credentials`             | Machine-to-machine token flow — watch for misuse |
| `refresh_token`                  | Token refresh patterns — may reveal token replay or session hijacking |
| `impersonation`                  | Admin impersonating another user — verify use case |

---

### 4. IP / Geo / Device Anomalies

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `user.authentication.suspicious` | Login flagged as suspicious due to IP/device risk |
| `geo_velocity_violation`         | Improbable travel logins — rapid jumps in geography |
| `user.session.start`             | First login from new browser/device fingerprint |
| `network.anomaly.detected`       | Detected from VPNs, proxies, or Tor — review for abuse |
| `user.agent.anomaly`             | Suspicious browser or client detected |

---

### 5. Persistence, Rules, and Integrations

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `policy.rule.update`, `policy.rule.create` | Changes to authentication, access, or MFA policies |
| `system.integrations.update`     | Third-party integrations updated — check for malicious modifications |
| `application.api.access_granted` | Unexpected access to apps via API tokens |
| `webhook.*`                      | Watch for changes to webhook URLs — may redirect sensitive data |
| `app.settings.updated`           | Review sensitive app integration settings for backdoors |

---

### 6. SSO / Application Access Abuse

| Keyword / Event Type              | Description |
|----------------------------------|-------------|
| `application.sso.login.success`  | Unusual or first-time SSO login — correlate with user behavior |
| `application.assignment.add`     | User granted access to sensitive app (e.g., admin consoles) |
| `saml.response`, `oidc.token`    | Abnormal usage of OIDC or SAML assertions — may signal session hijack |
| `session.cookie.reuse`           | Indicates potential stolen session token |

---

## Additional Tips

- **Tag privileged users and groups** for high-priority monitoring (e.g., Super Admins).
- Create alerts for **API token creation**, especially by non-automated accounts.
- Watch for **unusual grant flows** (e.g., password grant type in public apps).
- Correlate **geo and device anomalies** with critical app logins.
- Use Okta’s **System Log search filters** or export to SIEM for hunting patterns:
  ```bash
  eventType eq "user.authentication.failed" and outcome.result eq "FAILURE"
```

