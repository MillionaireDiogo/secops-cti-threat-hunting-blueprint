# Threat Hunting with Jenkins Overview

This file provides threat hunting hypotheses, detection keywords, suspicious operations, and monitoring recommendations for Jenkins CI/CD environments. Jenkins is widely used for automation, build, and deployment in DevOps pipelines, making it a valuable target for attackers.

## Log Sources
- Jenkins master and agent logs
- Jenkins build logs
- Authentication logs (login, logout, failed logins)
- User audit logs (user creation, deletion, permission changes)
- Pipeline/job configuration change logs
- Plugin management logs
- API access logs
- Web server (access/error) logs
- System logs (OS-level, network activity, file access)

---

## Threat Hunting Log Search Keywords

| **Keyword / Event**               | **Description / Threat Scenario**                                    |
|-----------------------------------|---------------------------------------------------------------------|
| `failed login`                    | Unsuccessful authentication attempts; possible brute force.          |
| `unauthorized`                    | Unauthorized actions, such as job or config access.                  |
| `user created` / `user deleted`   | Addition or removal of users, especially admins.                     |
| `role change` / `privilege`       | Changes to user roles/permissions; privilege escalation risk.         |
| `build triggered`                 | New builds, especially those not scheduled or from unknown sources.   |
| `script executed`                 | Running of Groovy scripts or shell commands—may indicate exploitation.|
| `plugin installed` / `plugin updated` | Plugin management activity; attackers may install malicious plugins.|
| `credential added` / `credential updated` | Addition or modification of credentials in Jenkins.               |
| `pipeline config changed`         | Modifications to job or pipeline definitions; possible persistence.   |
| `remote access`                   | API or remote connections to Jenkins; check for suspicious IPs.       |
| `file uploaded`                   | Unusual file uploads via Jenkins jobs or plugins.                     |
| `system groovy`                   | Use of system Groovy scripts, often abused for code execution.        |
| `webhook created` / `webhook updated` | External integrations added or changed; risk of data exfiltration. |
| `agent connected` / `agent disconnected` | New or unexpected build agents connecting to Jenkins.               |

---

## Jenkins-Specific Suspicious Operations & Events

- Multiple failed login attempts or brute-force attacks on Jenkins portal
- Addition of new users, especially with admin or high privileges
- Unauthorized plugin installations or updates (backdoors, webshells)
- Pipeline/job configuration changes not tracked in version control
- Secrets/credentials added, accessed, or exfiltrated via build logs or scripts
- Build jobs running scripts, commands, or fetching payloads from external sources
- New or unknown build agents connecting to the Jenkins master
- Unauthorized API token creation and usage

---

## High-Risk Behaviors & Use Cases

- Builds triggered outside of regular automation schedules (especially at odd hours)
- Use of system Groovy console or script approvals for unvetted code
- Unusual access to credentials or environment variables
- Privilege escalation through role or permission changes
- Modification of pipeline definitions to maintain persistence or introduce malicious steps
- Installation of unapproved or vulnerable plugins

---

## Advanced Threat Indicators

- Execution of encoded or obfuscated payloads in build steps
- Use of Jenkins to pivot to other internal systems or environments
- Automated or scripted credential extraction from Jenkins credential store
- Lateral movement via compromised build agents
- Use of Jenkins for data exfiltration (e.g., uploading build artifacts to attacker-controlled endpoints)
- Deletion or tampering with audit logs

---

## Response Recommendations

- Enable and regularly review audit, build, and authentication logs
- Restrict admin access and require strong authentication (e.g., SSO, MFA)
- Audit and control plugin installation/updates
- Use role-based access control (RBAC) and enforce least privilege
- Regularly review and rotate credentials stored in Jenkins
- Integrate Jenkins logs with SIEM for correlation with other security events

---

## References

- [Jenkins Security Best Practices](https://www.jenkins.io/doc/book/security/)
- [Jenkins Audit Trail Plugin](https://plugins.jenkins.io/audit-trail/)
- [OWASP Jenkins Security Guide](https://owasp.org/www-project-jenkins/)
