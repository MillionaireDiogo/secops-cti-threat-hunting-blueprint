# Threat Hunting with GitLab Overview

# GitLab.md

## Description
This file documents threat hunting hypotheses, detection keywords, and suspicious activities relevant to GitLab environments, including CI/CD pipelines, repositories, and user management.

## Log Sources
- GitLab Audit Events
- GitLab API logs
- GitLab Runner logs
- GitLab CI/CD Pipeline logs
- Access logs
- Error logs
- Git Push/Pull logs
- Integration/Webhook logs

---

## General Suspicious Activity Keywords

- unauthorized
- failed login
- permission denied
- authentication failed
- login failed
- invalid user
- privilege escalation
- new SSH key
- personal access token
- runner registration token
- deleted repository
- force push
- branch deletion
- group/member removal
- project transfer
- changed visibility
- role change
- API abuse
- excessive API requests

---

## GitLab-Specific Suspicious Operations & Events

- `user_login_failed`
- `user_impersonated`
- `user_password_changed`
- `user_add_ssh_key`
- `user_remove_ssh_key`
- `user_add_personal_access_token`
- `user_remove_personal_access_token`
- `project_destroyed`
- `project_transfered`
- `repository_git_operation`
- `ci_pipeline_created`
- `ci_job_failed`
- `ci_job_manual`
- `ci_variable_created`
- `ci_variable_removed`
- `integration_created`
- `integration_updated`
- `webhook_created`
- `webhook_removed`

---

## High-Risk Behaviors & Use Cases

- Multiple failed logins or brute-force attempts
- Addition of SSH keys or personal access tokens by unusual users
- Sudden increase in repository deletions or force pushes
- CI/CD variables set or modified outside of regular automation
- Runners registered from unusual IPs or geographies
- Integration/webhook changes not tied to official projects
- Unexpected role changes (e.g., a user promoted to Owner/Maintainer)
- Project or group transfers to outside namespaces

---

## Advanced Threat Indicators

- Secrets or credentials committed to repositories
- Usage of tools like git-dumper, gitrob, or truffleHog detected in access logs
- Unusual or excessive cloning/pulling of repositories (potential exfiltration)
- Use of expired or compromised tokens
- Webhook endpoints set to suspicious or unknown domains

---

## Response Recommendations

- Enable and monitor all audit logs.
- Set alerts for privilege changes, SSH key or token additions, and project deletions.
- Regularly rotate and review personal access tokens and runner registration tokens.
- Implement strict approval workflows for CI/CD variable changes and integration additions.
- Restrict runner registration to trusted sources.
- Use branch protection rules and require reviews for merge requests.

---

## References

- [GitLab Security Documentation](https://docs.gitlab.com/ee/security/)
- [GitLab Audit Event Types](https://docs.gitlab.com/ee/administration/audit_event_types.html)
- [Best Practices for Securing GitLab](https://about.gitlab.com/solutions/security/)


