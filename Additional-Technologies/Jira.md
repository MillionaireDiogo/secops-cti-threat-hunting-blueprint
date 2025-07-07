# Threat Hunting with Jira Overview

This file provides threat hunting hypotheses, detection keywords, suspicious events, and security recommendations for Atlassian Jira environments (Cloud and Server). Jira is a critical business and ITSM tool, making it a valuable target for attackers seeking sensitive project, ticket, or workflow data.

## Log Sources
- Jira application logs (atlassian-jira.log)
- Audit logs (user actions, permission changes)
- Authentication logs (login, logout, failed attempts)
- REST API access logs
- Plugin/add-on logs
- Web server access/error logs
- Integration/webhook activity logs
- Change management and issue history logs

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**                 | **Description / Threat Scenario**                                   |
|-------------------------------------|--------------------------------------------------------------------|
| `failed login`                      | Unsuccessful login attempts; brute force or credential stuffing.   |
| `unauthorized` / `permission denied`| Unauthorized access to issues, projects, or admin functions.       |
| `user created` / `user deleted`     | Addition or removal of users, especially with admin/project roles. |
| `role changed` / `privilege granted`| Escalation of user privileges or group assignments.                |
| `API token created` / `API token used`| New API tokens; use from unusual IPs/geographies.                 |
| `project created` / `project deleted`| Project provisioning/deletion; data exfiltration or sabotage.      |
| `issue exported` / `bulk export`    | Mass ticket exports, especially to external locations.             |
| `webhook created` / `webhook updated`| Addition of webhooks for external data exfiltration.              |
| `plugin installed` / `plugin updated`| Plugin/add-on changes; risk of malicious extensions.               |
| `audit log cleared` / `audit log tampered`| Signs of log evasion or sabotage.                            |
| `email changed` / `account recovery`| Account takeovers or preparation for hijack.                       |
| `integration added`                 | New integrations that may leak or move data externally.            |
| `project permission changed`        | Broadening of project or global permissions.                       |

---

## Jira-Specific Suspicious Operations & Events

- Multiple failed admin or user logins from unknown IPs
- Sudden escalation of user privileges, especially to System Admin or Project Admin
- Unexpected project or issue deletions/exports
- Addition of webhooks or integrations pointing to untrusted domains
- Creation or modification of automation rules without change management
- Large volume of tickets exported or emailed in a short timeframe
- Plugins installed/updated by non-admin users
- Unusual API usage patterns or token creations

---

## High-Risk Behaviors & Use Cases

- Out-of-hours administrative or configuration changes
- API tokens created from external IPs or never-seen devices
- Use of Jira as a bridge for data exfiltration (via attachments, comments, exports)
- Account recovery or email address changes for high-privilege users
- Integration of Jira with untrusted third-party tools/services

---

## Advanced Threat Indicators

- Use of automated tools or scripts for mass issue manipulation or export
- Tampering with workflow or automation rules to bypass controls
- Unauthorized modifications to project permission schemes
- Disabling or tampering with audit logging settings
- Lateral movement via shared Jira groups or cross-project roles

---

## Response Recommendations

- Enable and monitor all Jira audit and authentication logs
- Regularly review user, group, and permission changes
- Enforce strong authentication (SSO, MFA) for Jira access
- Limit plugin installation and webhook creation to trusted admins
- Set alerts for privilege escalation, mass exports, and integration changes
- Integrate Jira logs with SIEM for centralized security monitoring

---

## References

- [Atlassian Jira Security Best Practices](https://confluence.atlassian.com/adminjiraserver/security-checklist-for-jira-938847837.html)
- [Jira Audit Log Documentation](https://confluence.atlassian.com/enterprise/audit-logging-962981087.html)
- [Jira Cloud Security Practices](https://support.atlassian.com/security-and-access-policies/docs/jira-cloud-security-practices/)
