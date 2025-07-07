# Threat Hunting with Netskope Overview

This file provides threat hunting hypotheses, detection keywords, suspicious event types, and security recommendations for Netskope Cloud Security environments. Netskope CASB monitors cloud service use, enforces security policies, and protects against data loss, account compromise, and cloud-enabled threats.

## Log Sources
- Netskope API Data Protection logs
- Netskope Real-time Protection (inline) logs
- Application activity logs (Office 365, Box, Google Workspace, Slack, etc.)
- User activity logs
- Anomaly detection events
- Policy violation logs
- Threat intelligence and malware detection logs
- Network traffic logs (proxy, gateway)

---

## Threat Hunting Log Search Keywords 

| **Keyword / Event**                        | **Description / Threat Scenario**                                           |
|--------------------------------------------|----------------------------------------------------------------------------|
| `policy violation`                         | User or system actions blocked by DLP, threat, or compliance policy.       |
| `anomalous login`                          | Logins from unusual IPs, geographies, or devices.                          |
| `unauthorized app`                         | Unsanctioned app usage (Shadow IT discovery).                              |
| `malware detected`                         | Threat or malware event triggered in cloud traffic or file upload/download. |
| `data exfiltration`                        | Potential data leakage via uploads, shares, or downloads.                  |
| `file shared externally`                   | Files/folders shared with users outside organization.                      |
| `oauth app granted`                        | User grants OAuth access to a third-party cloud app; possible app abuse.   |
| `failed login`                             | Repeated authentication failures; brute force or credential stuffing.       |
| `admin activity`                           | High-risk or unexpected admin changes (policy, configuration, etc).        |
| `unusual download` / `bulk download`       | Excessive file downloads, may indicate insider threat or account takeover.  |
| `unusual upload` / `bulk upload`           | Unusual volume or frequency of file uploads to cloud services.              |
| `external collaboration`                   | New or unauthorized collaboration with external domains.                   |
| `bypass attempted`                         | Attempt to circumvent security controls (e.g., use of VPN/proxy).          |
| `session hijack`                           | Suspicious session/token activity.                                         |
| `threat intelligence match`                | Activity or traffic flagged by threat intelligence feeds.                   |
| `risky app`                                | Use of apps rated risky by Netskope or threat intel.                       |
| `inline DLP`                               | Inline DLP policy enforcement triggered.                                   |
| `unsanctioned app`                         | Attempts to access blocked or unsanctioned cloud applications.             |

---

## Netskope-Specific Suspicious Operations & Events

- Multiple anomalous login detections for a single user or app
- Excessive OAuth app grants in a short period
- Large numbers of files shared externally from cloud storage apps
- Repeated or mass downloads/uploads outside normal working hours
- DLP policy triggered on sensitive data (PII, PCI, PHI, source code)
- Sudden spikes in Shadow IT discovery (new cloud apps detected)
- Unusual admin activity, such as rapid policy or configuration changes
- Malware or threat events tied to cloud file transfers
- Attempts to disable or bypass Netskope’s inline protection

---

## High-Risk Behaviors & Use Cases

- Users granting OAuth permissions to suspicious third-party cloud apps
- Accessing cloud services from risky IPs or untrusted geographies
- File sharing with personal or non-corporate email domains
- Data downloads/uploads outside of standard business hours
- Attempts to access or register unsanctioned cloud services
- Detection of malware or ransomware in cloud file uploads

---

## Advanced Threat Indicators

- Correlation of cloud malware detections with endpoint or network alerts
- Use of cloud services for data staging/exfiltration before departure (insider threat)
- Session hijacking or token replay attempts in SaaS apps
- Use of anonymizers or proxies to mask activity
- Attackers leveraging unsanctioned apps to bypass DLP/policy controls

---

## Response Recommendations

- Monitor all policy violations, anomalous logins, and OAuth grants
- Set up alerts for mass downloads/uploads, external shares, and admin changes
- Regularly review and update sanctioned/unsanctioned app lists
- Enable inline DLP and anomaly detection for sensitive data types
- Educate users about risks of unsanctioned and third-party cloud apps
- Integrate Netskope logs with SIEM for unified security monitoring

---

## References

- [Netskope Security Cloud Documentation](https://docs.netskope.com/)
- [Netskope Threat Research Labs](https://www.netskope.com/blog/threat-labs)
- [Cloud DLP Policy Best Practices](https://docs.netskope.com/en/data-loss-prevention-dlp.html)
