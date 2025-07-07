# Threat Hunting with Nagios Overview

This file documents threat hunting hypotheses, detection keywords, suspicious behaviors, and response recommendations for Nagios monitoring environments. Nagios is widely used for IT infrastructure and service monitoring, making it a valuable target for attackers aiming to disrupt detection, gain persistence, or use Nagios for lateral movement.

## Log Sources
- Nagios Core/Log files (`/usr/local/nagios/var/nagios.log`, `/var/log/nagios/nagios.log`)
- Web interface (CGI) access logs
- Authentication and authorization logs
- Plugin execution logs
- System logs (OS-level, syslog)
- Integration and notification logs (email, SMS, webhook)

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**                 | **Description / Threat Scenario**                                 |
|-------------------------------------|------------------------------------------------------------------|
| `failed login`                      | Unsuccessful web or SSH login attempts; possible brute force.    |
| `unauthorized` / `access denied`    | Unauthorized access to Nagios web UI, configs, or monitored hosts.|
| `user created` / `user deleted`     | Addition or removal of users, especially with admin rights.      |
| `role change` / `privilege escalated`| Account privilege escalations; risk of admin takeover.           |
| `configuration changed`             | Unexpected changes to hosts, services, or notification configs.  |
| `plugin added` / `plugin removed`   | Modification of plugins; could introduce malicious code.         |
| `notification suppressed`           | Alert/notification disabled, risk of attacker hiding activity.   |
| `service check command changed`     | Commands or scripts altered; may be abused for code execution.   |
| `external command`                  | Submission of commands via external interface/API.               |
| `webhook created` / `webhook updated`| New/modified integrations, risk of data exfiltration.            |
| `log file rotated`                  | Log rotations/tampering to erase attacker footprints.            |
| `restart` / `shutdown`              | Unexpected restart/shutdown of Nagios service.                   |

---

## Nagios-Specific Suspicious Operations & Events

- Multiple failed login attempts on the Nagios web interface
- User or role changes made outside normal maintenance windows
- Addition of new monitoring plugins/scripts from untrusted sources
- Suppression or modification of notifications for critical systems/services
- Sudden or unexplained changes to host/service definitions
- Execution of custom scripts or system commands via Nagios plugins
- Log files missing, rotated, or tampered with
- Nagios server process restarted without scheduled change

---

## High-Risk Behaviors & Use Cases

- Privilege escalation: user promoted to admin or elevated role
- Use of Nagios plugins for lateral movement (command execution on monitored hosts)
- Modification of check commands to include reverse shell or data exfiltration
- Disabling or modifying alerts to critical systems/services
- Web interface accessed from rare or external IP addresses
- Integration/webhook endpoints set to suspicious domains

---

## Advanced Threat Indicators

- Malicious payloads delivered via custom plugins or check commands
- Use of Nagios server as a pivot point to other systems on the network
- Exploitation of known Nagios CVEs (e.g., web UI RCE, privilege escalation bugs)
- Attackers tampering with
