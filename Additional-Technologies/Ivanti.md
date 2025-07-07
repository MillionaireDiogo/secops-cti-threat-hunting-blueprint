# Threat Hunting with Ivanti Overview

This file contains threat hunting hypotheses, detection keywords, suspicious behaviors, and incident response recommendations for Ivanti solutions (ITSM, Endpoint Manager, Patch Management, and related modules).

## Log Sources
- Ivanti Endpoint Manager logs
- Ivanti ITSM (Service Manager) audit logs
- Patch Management activity logs
- Remote control session logs
- User and device inventory logs
- Change and configuration logs
- Vulnerability scan results
- Syslog/event logs forwarded to SIEM

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**                | **Description / Threat Scenario**                                              |
|------------------------------------|-------------------------------------------------------------------------------|
| `failed login`                     | Failed authentication to Ivanti console or agent.                             |
| `unauthorized`                     | Unauthorized attempts to access devices, consoles, or resources.              |
| `privilege escalation`             | Account role/permission changes, especially to admin.                         |
| `remote control started`           | Remote desktop/control session initiated; risk of unauthorized lateral movement. |
| `remote control ended`             | Session ended; correlate with unusual changes or exfil events.                |
| `patch deployed`                   | Mass patch deployment outside of maintenance windows.                         |
| `patch deployment failed`          | Patch failures, especially on critical assets.                                |
| `agent installed`                  | New endpoint agent installation; verify source and legitimacy.                |
| `agent removed`                    | Unexpected or unauthorized agent uninstallation.                              |
| `policy changed`                   | Security, patch, or config policy modified.                                   |
| `device added` / `device removed`  | Unexpected asset inventory changes.                                           |
| `vulnerability detected`           | New or high-severity vulnerabilities found.                                   |
| `scheduled task created`           | Potential persistence mechanism by attacker.                                  |
| `file transfer`                    | Unusual file movement during remote control or agent session.                 |

---

## Ivanti-Specific Suspicious Operations & Events

- Multiple failed admin logins or brute-force attempts to Ivanti portals
- Remote control sessions initiated by unexpected users/IPs
- Policy or configuration changes without proper change tickets
- Mass deployment of scripts or patches by unauthorized accounts
- Large-scale removal of agents or disabling of patch modules
- Unauthorized installation of software through Ivanti agent

---

## High-Risk Behaviors & Use Cases

- Out-of-hours patch deployments, script executions, or policy changes
- Use of Ivanti remote control on sensitive servers or executive endpoints
- Sudden increase in agent installs/removals across the environment
- Elevation of user roles to admin or security administrator
- Device or asset inventory manipulated (additions/removals without business justification)

---

## Advanced Threat Indicators

- Attackers leveraging Ivanti for lateral movement (remote control, agent deployment)
- Tampering with vulnerability or patch management to hide exploits
- Disabling or altering logs and audit policies
- Abuse of scheduled tasks or persistent scripts deployed via Ivanti
- Correlation of Ivanti agent actions with other suspicious activity (data exfil, privilege escalation)

---

## Response Recommendations

- Monitor and alert on all admin, agent, and remote-control activity
- Enforce strong authentication and least-privilege access for Ivanti console users
- Regularly audit policy, configuration, and inventory changes
- Correlate Ivanti logs with endpoint, network, and authentication data
- Use Ivanti’s built-in alerting, plus SIEM integration for comprehensive detection

---

## References

- [Ivanti Security Best Practices](https://www.ivanti.com/resources/library)
- [Ivanti Endpoint Manager Documentation](https://help.ivanti.com/iv/help/en_US/IES/2023/)
- [Ivanti Service Manager Documentation](https://help.ivanti.com/iv/help/en_US/ISM/2023/)
