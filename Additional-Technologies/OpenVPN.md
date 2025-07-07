# Threat Hunting with Netskope Overview

# OpenVPN.md

## Description
This file documents threat hunting hypotheses, detection keywords, suspicious log events, and incident response recommendations for OpenVPN environments. OpenVPN provides secure remote access, but if abused, it can be leveraged for unauthorized access, lateral movement, and data exfiltration.

## Log Sources
- OpenVPN server logs (`/var/log/openvpn.log`, `/etc/openvpn/logs/`)
- Authentication logs (PAM, RADIUS, LDAP, etc.)
- Connection logs (client connects/disconnects)
- TLS/SSL handshake and error logs
- Firewall/network logs (for VPN-assigned IPs)
- OS system logs (syslog, auth.log)
- VPN management interface logs

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**              | **Description / Threat Scenario**                                    |
|----------------------------------|---------------------------------------------------------------------|
| `AUTH_FAILED`                    | Failed authentication attempts; possible brute force.                |
| `TLS Error` / `tls-error`        | Issues in establishing secure channel; could be misconfig or attack. |
| `Connection reset`               | Abrupt session drops; investigate for DoS or misconfiguration.       |
| `Client connected`               | New client connections; check source IP and timing.                  |
| `Client disconnected`            | Unexpected disconnects; may indicate session hijack or DoS.          |
| `multiple connections`           | Same cert/key used from multiple locations; possible key sharing.    |
| `session token reused`           | Replay or hijack attempts.                                           |
| `route pushed`                   | VPN server pushing unusual or broad network routes to clients.       |
| `user-locked`                    | Accounts locked due to failed attempts or policy.                    |
| `ip-pool exhaustion`             | All IPs assigned; may indicate mass connections (DoS)                |
| `certificate revoked`            | Connection attempts with revoked certificates.                       |
| `new certificate`                | New certs issued/added; check if authorized.                         |
| `config change`                  | Changes to server/client config files; risk of misconfig or backdoor.|
| `privilege escalation`           | Admin role or user privilege changed in VPN management.              |
| `unknown user`                   | Authentication attempts for unknown accounts.                        |

---

## OpenVPN-Specific Suspicious Operations & Events

- Multiple failed authentication attempts in short succession
- VPN logins from new or geographically unusual locations
- Same certificate used by multiple clients simultaneously
- Connection of revoked or expired certificates
- Unauthorized changes to OpenVPN server or client configuration
- Mass connection attempts (potential DoS or scanning activity)
- Unexpected client connections outside normal business hours
- Unusual or broad network routes pushed to VPN clients

---

## High-Risk Behaviors & Use Cases

- Credential stuffing or brute-force attempts
- Use of stolen or shared client certificates
- VPN access from previously unseen IP addresses, countries, or continents
- Sudden spikes in concurrent VPN sessions
- Data exfiltration via VPN tunnel (large file transfers, unusual destinations)
- Admin role assignments or privilege escalation in VPN management

---

## Advanced Threat Indicators

- Use of OpenVPN as a jump point for lateral movement within the network
- Attempts to bypass split-tunneling or route all traffic through VPN
- Log tampering or deletion to cover tracks
- Attackers using OpenVPN for persistent command and control (C2)
- Connections to/from blacklisted or TOR exit node IPs

---

## Response Recommendations

- Enable detailed logging on OpenVPN servers and regularly review for anomalies
- Monitor and alert on authentication failures, config changes, and cert issues
- Enforce strong authentication (cert+password, MFA) and certificate management
- Limit VPN access to authorized devices and regularly rotate credentials/certificates
- Integrate OpenVPN logs with SIEM for correlation with endpoint and network activity
- Restrict VPN routes to least-privilege and review route pushes regularly

---

## References

- [OpenVPN Security Recommendations](https://community.openvpn.net/openvpn/wiki/SecurityRecommendations)
- [OpenVPN Log File Management](https://community.openvpn.net/openvpn/wiki/Openvpn23ManPage)
- [Best Practices for VPN Security](https://www.cisa.gov/news-events/news/vpn-security-best-practices)
