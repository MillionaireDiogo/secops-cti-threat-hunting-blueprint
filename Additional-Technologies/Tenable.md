# Threat Hunting with Tenable Overview

This file documents threat hunting hypotheses, detection keywords, suspicious events, and security best practices for Tenable vulnerability management environments (Tenable.sc, Tenable.io, Nessus). Tenable solutions are critical for vulnerability scanning, assessment, and reporting—making them targets for evasion and privilege abuse.

## Log Sources
- Tenable.sc or Tenable.io audit logs
- Nessus scanner logs
- Plugin execution and vulnerability findings logs
- User activity and authentication logs
- Scan schedule and policy change logs
- Asset inventory and discovery logs
- API access logs
- System/network logs from scanning hosts

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**               | **Description / Threat Scenario**                                   |
|-----------------------------------|--------------------------------------------------------------------|
| `failed login`                    | Unsuccessful authentication to Tenable console or API.              |
| `unauthorized`                    | Unauthorized attempts to access scans, reports, or configs.         |
| `user created` / `user deleted`   | New or removed users, especially admins.                            |
| `role changed` / `privilege escalated` | Account privilege changes; risk of admin takeover.             |
| `scan created` / `scan started`   | New or unscheduled scan jobs.                                       |
| `scan deleted` / `scan stopped`   | Scans deleted or stopped; may indicate attempt to evade detection.  |
| `policy changed`                  | Vulnerability scan policy modified; risk of evasion/backdoor.       |
| `plugin enabled` / `plugin disabled` | Enabling/disabling specific plugins (e.g., for evasion).        |
| `API token created` / `API token used` | New API tokens or unusual use (from new IPs, etc).              |
| `asset deleted` / `asset added`   | Unexpected asset inventory changes.                                 |
| `scan result exported`            | Large or unexpected data exports; risk of data exfiltration.        |
| `integration added` / `integration modified` | New or changed third-party connections.                      |
| `scan window changed`             | Modification of scan windows; can be abused to avoid detection.     |

---

## Tenable-Specific Suspicious Operations & Events

- Multiple failed admin logins or brute-force attempts to the console
- Sudden creation or removal of admin/privileged users
- Unauthorized changes to scan policies or exclusion lists
- Disabling or tampering with high-risk or compliance scan plugins
- Scheduling scans outside of regular windows, or cancelling key scans
- Mass export of vulnerability findings or scan data
- Unexpected API access, especially from new IPs or tokens
- Changes to asset inventory without change control

---

## High-Risk Behaviors & Use Cases

- Scans or plugins disabled on high-value or sensitive assets
- Role changes or privilege escalation not documented in change management
- Integration with untrusted third-party tools/services
- Credential harvesting via Nessus or Tenable API
- Scan or export of sensitive findings by unauthorized users

---

## Advanced Threat Indicators

- Use of the platform to identify vulnerable assets for lateral movement
- Suppression of compliance or critical vulnerability findings
- Correlation of Tenable activity with other signs of compromise (lateral movement, privilege escalation)
- Manipulation of scanning windows or policies to evade blue team monitoring
- Use of API for mass data extraction or integration with attacker infrastructure

---

## Response Recommendations

- Enable and monitor all audit and activity logs on Tenable platforms
- Set alerts for failed logins, privilege escalations, scan and policy changes
- Regularly review asset and user inventory for unauthorized changes
- Restrict API token creation and use strong authentication for console and API access
- Integrate Tenable logs with SIEM for unified detection and incident response
- Audit scan results and exported data for unauthorized access or exfiltration

---

## References

- [Tenable.sc Audit Logging Documentation](https://docs.tenable.com/sc/Content/AuditLogs.htm)
- [Tenable.io Logging and Activity Monitoring](https://docs.tenable.com/io/Content/Platform/ActivityLogs.htm)
- [Nessus Security Best Practices](https://docs.tenable.com/nessus/Content/SecurityBestPractices.htm)
