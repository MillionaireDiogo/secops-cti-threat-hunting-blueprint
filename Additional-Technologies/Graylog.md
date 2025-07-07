# Threat Hunting with Graylog Overview

This file contains threat hunting hypotheses, detection use-cases, log source details, and specific log search keywords and descriptions for Graylog deployments. Graylog is widely used for log aggregation, search, and security analytics.

## Log Sources
- Syslog (Linux, network devices)
- Windows Event Logs
- Application logs (e.g., Nginx, Apache, custom apps)
- Firewall logs
- IDS/IPS logs (e.g., Suricata, Snort)
- Cloud service logs
- Graylog server audit logs

---

## Threat Hunting Log Search Keywords 

| **Keyword / Search Term**          | **Description / Threat Scenario**                                                  |
|------------------------------------|-----------------------------------------------------------------------------------|
| `failed login`                     | Repeated failed authentication attempts; brute force or password spraying.         |
| `unauthorized`                     | Unauthorized access attempts across any data source.                              |
| `sudo` OR `root`                   | Commands run as superuser; check for privilege escalation.                        |
| `added user`                       | Monitoring creation of new accounts, especially outside standard provisioning.     |
| `deleted user`                     | User deletions that could indicate cover-up of malicious actions.                  |
| `groupadd` OR `useradd`            | User or group additions, especially with admin rights.                            |
| `AccessDenied`                     | General access denied events; could indicate attempted privilege escalation.       |
| `error` AND (`login` OR `access`)  | Failed attempts to access resources.                                              |
| `remote desktop`                   | Monitoring for RDP access, especially from unusual sources.                       |
| `NTLM`                             | NTLM authentication events; legacy and targeted by attackers.                     |
| `Mimikatz`                         | Search for known credential dumping tool signatures in logs.                      |
| `powershell` AND (`download` OR `invoke`) | Suspicious use of PowerShell to fetch payloads or run scripts.             |
| `command=` OR `cmd.exe`            | Command line executions; often leveraged in attacks.                              |
| `net user`                         | Attempts to enumerate users via command line.                                     |
| `shutdown` OR `restart`            | Unexpected shutdown or restart events.                                            |
| `file uploaded` OR `file download` | File transfers that could indicate data exfiltration or malware delivery.          |
| `DNS query`                        | Suspicious DNS queries, e.g., for known malicious domains.                        |
| `process created`                  | Process creation events; monitor for abnormal or rare processes.                  |
| `service started` OR `service stopped` | Unexpected changes to services; can be used for persistence.                 |

---

## Graylog-Specific Suspicious Operations & Events

- Unusual spike in message throughput (may indicate DoS or log flooding)
- Graylog user account privilege escalation or new admin creation
- Alert and notification tampering or disabling
- Unauthorized API token generation or use
- Graylog input changes or deletion (disrupts log collection)
- Disabling of pipeline or processing rules

---

## High-Risk Behaviors & Use Cases

- Administrative login attempts from unusual IP addresses or geographies
- Multiple failed login attempts on Graylog web UI
- Graylog role changes not following change control
- Sudden drop in log volume from critical sources (possible tampering)
- Graylog server process restarts outside maintenance windows

---

## Advanced Threat Indicators

- Attackers disabling or deleting inputs/pipelines to hide activity
- Privilege escalation within Graylog to gain broader visibility or control
- Use of Graylog’s API for bulk data extraction (potential log exfiltration)
- Use of Graylog to inject or modify logs (log manipulation)

---

## Response Recommendations

- Enable Graylog audit logging and regularly review for suspicious changes
- Set alerts for privilege escalations, account creations, and configuration changes
- Monitor and alert on failed logins and excessive API token usage
- Regularly validate log source integrity and ensure critical sources remain active
- Restrict Graylog admin and API access using network segmentation and strong authentication

---

## References

- [Graylog Security Documentation](https://docs.graylog.org/en/latest/pages/security.html)
- [Graylog Threat Hunting Queries – Graylog Community](https://community.graylog.org/)
- [Security Best Practices for Graylog](https://docs.graylog.org/en/latest/pages/best_practices.html)
