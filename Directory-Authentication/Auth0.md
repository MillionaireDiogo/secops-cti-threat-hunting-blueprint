# Auth0 Threat Hunting Overview

[Auth0](https://auth0.com) is an Identity-as-a-Service (IDaaS) platform providing secure authentication and authorization for applications and APIs. As a centralized authentication provider, Auth0 is a high-value target for attackers seeking:

- Credential stuffing or brute-force logins
- Token abuse or manipulation
- MFA bypass
- Unauthorized client/app registration
- User role escalation or manipulation
- Configuration tampering (e.g., rules/hooks/flows)

---

## Recommended Log Sources

| Source                            | Description |
|-----------------------------------|-------------|
| **Auth0 Logs (via Dashboard/API)**| Primary source of user activity, errors, API usage |
| **Auth0 Log Streams**             | Forward logs to SIEMs (Splunk, ELK, Sentinel, etc.) |
| **Cloud Provider Logs**           | If hosted in AWS/Azure/GCP, collect auth flows and resource access logs |
| **MFA Provider Logs (e.g., Duo, Okta Verify)** | Helps detect MFA fatigue or bypass attempts |
| **Admin Action Logs**             | For detecting privilege abuse and configuration tampering |

---

## Suspicious Keywords & Events (with Descriptions)

### 1. Authentication Failures & Abuse

| Keyword / Event Code  | Description |
|------------------------|-------------|
| `f`                   | Failed login (wrong credentials) - repeated from same IP/user signals brute-force |
| `fp`                  | Failed password login - user exists, password incorrect |
| `fu`                  | Login failed - user does not exist (user enumeration attempts) |
| `limit_wc`, `limit_mu`| Rate-limited due to too many login attempts - brute-force indicator |
| `pwd_leak`            | Detected credential stuffing attack via breached credentials |
| `mfa_invalid_code`    | MFA code entered incorrectly - repeated failures may indicate MFA bypass attempt |
| `blocked_account`     | Account has been blocked - often post-brute-force detection |

---

### 2. Privilege Abuse & Admin Activity

| Keyword / Event Code  | Description |
|------------------------|-------------|
| `sapi`                | Auth0 Management API call - monitor for abuse of admin API tokens |
| `s`                   | Successful login - flag admin logins from unusual IPs/locations |
| `user_update`, `user_update_app_metadata` | Monitor for role/permission escalation |
| `api_operation`       | Covers token generation, deletion, client secret changes |
| `client_update`, `client_create` | New apps/clients created - may indicate unauthorized access or lateral movement |
| `rule_update`, `hook_update` | Tampering with Auth0 rules/hooks - used for persistence or token manipulation |

---

### 3. Token & Session Abuse

| Keyword / Event Code  | Description |
|------------------------|-------------|
| `token_exchange`      | OAuth 2.0 token exchange - flag suspicious use of refresh tokens |
| `refresh_token_rotation` | Watch for repeated refresh activity - could indicate token leakage |
| `access_token_reuse_detected` | Multiple uses of same token - may indicate compromise |
| `id_token_invalid_signature` | Potential token forgery attempt |
| `grant_type=password`, `grant_type=client_credentials` | Direct grant types — flag if used from unknown clients or contexts |

---

### 4. IP/Geo Anomalies & Suspicious Behavior

| Keyword / Event Code  | Description |
|------------------------|-------------|
| `suspicious_ip`        | Auth0-flagged high-risk IP (Tor, cloud proxy, etc.) |
| `geo_velocity_violation` | Impossible travel detected — rapid logins from distant locations |
| `ip_blocked`           | Auth0 blocked IP — often due to abuse or risk score |
| `new_device`           | First-time login from a new device/browser — combine with user agent and geo |
| `user_agent_anomaly`   | Suspicious client/browser — may indicate automated login attempts |

---

### 5. Configuration Changes & Persistence

| Keyword / Event Code  | Description |
|------------------------|-------------|
| `client_secret_rotation` | Rotation of app secrets — flag if unplanned or unauthorized |
| `rule_created`, `rule_deleted` | Auth0 Rules are JavaScript snippets - dangerous if modified by attacker |
| `tenant_settings_updated` | Changes to global Auth0 tenant settings - monitor for unauthorized config drift |
| `connection_updated` | Update to social, database, or enterprise identity provider - may affect login flow or trust boundaries |
| `email_template_modified` | Attackers may modify templates to phish users or redirect confirmation links |

---

## Additional Tips

- Enable and forward **Log Streams** to your SIEM for real-time hunting and alerts.
- Monitor **API access tokens** (`sapi`) and their scopes - attackers may use them to modify tenants silently.
- Cross-reference **login events** with IP reputation and device fingerprinting.
- Correlate **failed MFA attempts** with known attack windows - MFA bombing is rising.
- Track **OAuth grant types** - `client_credentials` from unknown apps is highly suspicious.
- Use **Auth0 anomaly detection** features, but build your own correlation logic for layered detection.

---

