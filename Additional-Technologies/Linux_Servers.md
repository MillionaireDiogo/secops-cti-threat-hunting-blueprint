# Threat Hunting with Linux_Servers Overview

This file documents threat hunting hypotheses, suspicious log search keywords, behaviors, and detection use-cases for Linux servers. Linux servers are frequent targets for privilege escalation, persistence, lateral movement, and data exfiltration attacks.

## Log Sources
- `/var/log/auth.log` (Debian/Ubuntu)
- `/var/log/secure` (RHEL/CentOS/Fedora)
- `/var/log/syslog`
- `/var/log/messages`
- `/var/log/audit/audit.log`
- `/var/log/sudo.log`
- SSH daemon logs
- Web/application logs (e.g., Apache, Nginx)
- Cron logs
- User bash history files
- Custom app logs

---

## Threat Hunting Log Search Keywords 
| **Keyword / Event**                | **Description / Threat Scenario**                              |
|------------------------------------|---------------------------------------------------------------|
| `failed password` / `authentication failure` | Failed login attempts; brute force or password spraying.      |
| `accepted password` / `successful login` | New or unexpected logins, especially from external IPs.       |
| `sudo` / `su`                      | Privilege escalation events; monitor for abuse.                |
| `useradd` / `groupadd`             | Creation of new users/groups, especially with sudo privileges. |
| `userdel` / `groupdel`             | Deletion of users/groups; possible cover-up.                   |
| `passwd`                           | Password changes, especially for root/admin accounts.          |
| `root login`                       | Direct login as root (should be rare).                         |
| `ssh`                              | Remote access activity, especially from unknown IPs.           |
| `scp` / `sftp` / `rsync`           | File transfers; monitor for large or unusual uploads/downloads.|
| `crontab` / `cron`                 | Scheduled task creation; used for persistence.                 |
| `systemctl` / `service`            | Service management; may indicate attempts at persistence.      |
| `chmod` / `chown`                  | Permission/ownership changes, especially on sensitive files.   |
| `auditd` / `audit`                 | Changes to audit rules; may indicate attempts to disable logging.|
| `bash` / `sh`                      | Shell access, especially from web shells or reverse shells.    |
| `wget` / `curl` / `ftp`            | Downloading tools or payloads from external sources.           |
| `nc` / `ncat` / `netcat`           | Network utilities; often used for reverse shells/C2.           |
| `suspicious process`               | Rare/abnormal processes (crypto miners, webshells, etc).       |
| `file modified`                    | Changes to critical files (e.g., `/etc/passwd`, `/etc/shadow`).|
| `kernel exploit`                   | Indicators of privilege escalation exploits (Dirty COW, etc.). |
| `tcpdump`                          | Network capture utilities; may indicate reconnaissance.        |

---

## Linux-Specific Suspicious Operations & Events

- Multiple failed SSH logins followed by a successful one
- Addition of new users to the `sudo` or `wheel` group
- Direct root logins or `su`/`sudo` without ticketed change
- Unexpected cron jobs (especially with obfuscated commands)
- Installation of unusual software or tools (e.g., hacking tools, miners)
- Outbound connections to unknown or high-risk IPs
- Modification of startup scripts or `/etc/rc.local`
- Changes to logging/auditing configuration files
- Unusual or mass file deletions or permissions changes

---

## High-Risk Behaviors & Use Cases

- Login from rare geolocations or previously unseen IP addresses
- Execution of encoded/obfuscated shell scripts
- Network scanning (e.g., nmap, masscan) run from server
- Persistence via cron, systemd service, or rc.local
- Sudden or unexplained spike in CPU or network usage
- Files downloaded from suspicious URLs or external sources
- Data exfiltration using SCP/SFTP/rsync

---

## Advanced Threat Indicators

- Signs of rootkit or kernel-level tampering
- Credential harvesting with tools like Mimikatz (on Wine) or LaZagne
- Lateral movement attempts to other systems (SSH hopping)
- Outbound C2 connections using uncommon ports
- Removal or tampering of logs to erase attacker footprints
- Creation of backdoor accounts or SSH keys

---

## Response Recommendations

- Enable and review logging for authentication, sudo, cron, and sensitive file access
- Set up alerts for privilege escalation, root access, and user/group changes
- Regularly audit users, groups, sudoers, and SSH authorized_keys
- Use tools like auditd, OSSEC, or Wazuh for host-based intrusion detection
- Apply the principle of least privilege and enforce MFA/strong authentication for SSH
- Integrate logs with SIEM for centralized monitoring and correlation

---

## References

- [Linux Security Auditing with Auditd](https://linux.die.net/man/8/auditd)
- [Securing SSH on Linux](https://www.ssh.com/academy/ssh/security)
- [OSSEC Open Source Host-Based IDS](https://www.ossec.net/)
