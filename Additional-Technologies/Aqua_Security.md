# Threat Hunting with Aqua_Security Overview

This file provides threat hunting keywords, suspicious activities, and log sources for Aqua Security—a container, Kubernetes, and cloud-native security platform. Use these indicators to detect suspicious workload, container, and cloud activity, as well as policy violations.

## Log Sources
- Aqua Console Audit Logs  
- Enforcer (Agent) Logs  
- Image Scanning Logs  
- Container & Pod Runtime Logs  
- Kubernetes Audit Logs  
- Policy & Compliance Event Logs  
- Cloud Provider Integration Logs  
- API Access Logs  

---

## Authentication & Access Events

| **Keyword / Event**                   | **Description / Risk**                                      |
| ------------------------------------- | ----------------------------------------------------------- |
| `FailedLogin`, `AuthenticationFailed` | Repeated failed logins—possible brute force.                |
| `SuccessfulLogin` (New IP/Location)   | Access from unexpected locations, IPs, or new accounts.     |
| `TokenIssued`, `TokenRevoked`         | New or revoked API tokens (watch for automation abuse).     |
| `MFABypass`, `UserDisabledMFA`        | Multi-factor bypass/removal (risk of privilege abuse).      |

---

## Policy & Compliance Events

| **Keyword / Event**                  | **Description / Risk**                                       |
| ------------------------------------ | ------------------------------------------------------------ |
| `PolicyViolation`                    | Violation of security/compliance policies (critical alert).  |
| `PolicyChanged`, `PolicyDeleted`     | Unauthorized modification or removal of security policies.    |
| `RuleBypassed`, `ComplianceBypass`   | Circumvention of runtime or image security controls.          |
| `EnforcerUninstalled`                | Removal of agents/controls from nodes or clusters.           |

---

## Container & Runtime Security

| **Keyword / Event**                | **Description / Risk**                                           |
| ---------------------------------- | ---------------------------------------------------------------- |
| `ContainerStarted`, `PodCreated`   | Abnormal/unauthorized container or pod launches.                 |
| `PrivilegedContainer`, `RootUser`  | Containers running as root or with elevated privileges.          |
| `ExecShell`, `ExecInContainer`     | Interactive shell access to running containers (possible attack).|
| `ContainerEscaped`                 | Detected container breakout or escape attempt.                   |
| `UnexpectedNetworkConnection`      | Containers communicating with suspicious or external IPs.        |
| `SuspiciousProcess`                | Malware or hacking tools executed inside containers.             |
| `FileAccessViolation`              | Unauthorized file reads/writes (e.g., `/etc/shadow`).            |

---

## Image Scanning & Supply Chain Events

| **Keyword / Event**                   | **Description / Risk**                                  |
| ------------------------------------- | ------------------------------------------------------- |
| `ImageScanFailed`                     | Failed scans—may indicate evasion attempt.              |
| `CriticalVulnerability`, `Malware`    | High/critical findings in image scans.                  |
| `UntrustedRegistry`, `ImagePulled`    | Images pulled from untrusted or public registries.      |
| `ImageTampered`, `ImageModified`      | Unexpected image changes or tampering.                  |
| `UnsignedImage`, `SignatureInvalid`   | Unsigned or invalid-signed images deployed.             |

---

## Kubernetes & Orchestration Events

| **Keyword / Event**                     | **Description / Risk**                                 |
| --------------------------------------- | ------------------------------------------------------ |
| `K8sConfigChange`                       | Unusual modifications to Kubernetes configurations.    |
| `RBACChanged`, `RoleBindingChanged`     | Privilege escalation or lateral movement.              |
| `NamespaceCreated`, `NamespaceDeleted`  | Creation/deletion of namespaces (watch for staging).   |
| `ServiceAccountTokenCreated`            | New service accounts—potential persistence backdoors.  |
| `AuditLogDisabled`                      | Disabling K8s or cloud audit logs.                     |

---

## Integration & API Monitoring

| **Keyword / Event**            | **Description / Risk**                                     |
| ------------------------------ | ---------------------------------------------------------- |
| `APIKeyCreated`, `APIKeyRevoked`| API token creation/revocation (verify source/purpose).    |
| `FailedAPIAccess`              | Multiple failed API authentications (possible brute force).|
| `IntegrationAdded`             | New integrations—possible third-party data exposure.       |
| `WebhookCreated`               | Unexpected webhooks for alerting or exfiltration.          |

---

## Advanced Threat Indicators

- Mass container or pod creation/deletion in short period  
- Uninstall/removal of Aqua Enforcer agents  
- Privileged or root containers running unexpectedly  
- Lateral movement between namespaces or clusters  
- Bulk downloads from suspicious registries  
- Image scan results repeatedly suppressed or ignored  
- Container access from unknown IPs or geographies  
- Audit logging disabled or tampered

---

**Tip:**  
Correlate Aqua Security logs with cloud provider events, network flow logs, and SIEM alerts for a comprehensive view of cloud-native risk.

