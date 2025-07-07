# Real-World Security Breaches & Why Threat Hunting Matters

The following examples demonstrate that **no technology stack is immune to compromise**. Attackers have targeted almost every major class of IT, cloud, and security tool used in modern organizations. This list pairs common breach scenarios with specific technologies, proving the need for continuous threat hunting across all tools.

---

## Cloud Platforms & Infrastructure

- **AWS (S3, IAM, WAF):**  
  *Capital One Breach (2019):* Misconfigured IAM and WAF exploited for mass data exfiltration from S3.  
  *Reference:* [CSO Online - Capital One](https://www.csoonline.com/article/3441226/the-capital-one-breach-what-happened-and-what-we-can-learn-from-it.html)

- **Azure:**  
  *ChaosDB (2021):* Azure Cosmos DB vulnerability exposed thousands of customer keys.  
  *Reference:* [Wiz Blog - ChaosDB](https://www.wiz.io/blog/chaosdb-how-we-hacked-thousands-of-azure-customers-databases)

- **GCP:**  
  *Google Cloud IAM (2021):* Researchers found ways to abuse Google Cloud IAM privilege escalation paths for lateral movement.  
  *Reference:* [Unit 42 Blog - GCP IAM](https://unit42.paloaltonetworks.com/gcp-iam-privilege-escalation/)

- **Oracle Cloud:**  
  *Oracle WebLogic Servers (2020):* Vulnerabilities enabled crypto mining and lateral movement in cloud VMs.  
  *Reference:* [Oracle Security Alert](https://www.oracle.com/security-alerts/alert-cve-2020-14882.html)

---

## Identity, Directory, & SSO

- **Active Directory (AD):**  
  *NotPetya (2017):* AD abused for privilege escalation and mass lateral movement.  
  *Reference:* [US-CERT Alert](https://www.cisa.gov/news-events/alerts/2017/06/27/petya-malware)

- **Azure AD:**  
  *Nobelium/Microsoft 365 Attacks (2020):* Azure AD used as a launchpad for BEC and privilege abuse.  
  *Reference:* [Microsoft Security Blog](https://www.microsoft.com/security/blog/2021/04/15/new-nation-state-cyberattacks/)

- **Okta:**  
  *LAPSUS$ (2022):* Breach via third-party engineer compromised SSO and downstream apps.  
  *Reference:* [Okta Security Blog](https://www.okta.com/blog/2022/03/updated-okta-statement-on-lapsus-compromise/)

- **Ping Identity:**  
  *SSO Abuse (Multiple Cases):* Attackers use compromised identity providers to pivot across SaaS tools.  
  *Reference:* [Duo Blog](https://duo.com/decipher/ping-identity-users-warned-of-sso-hijacking-risk)

---

## Endpoint Security, EDR, & MDM

- **CrowdStrike, SentinelOne, Defender, Carbon Black:**  
  *SolarWinds Attack (2020):* Attackers evaded multiple EDRs using “living off the land” techniques.  
  *Reference:* [FireEye Analysis](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)

- **Intune (MDM):**  
  *Stolen Device Enrollment (2022):* Attackers used compromised MDM to enroll rogue devices.  
  *Reference:* [Microsoft MDM Abuse](https://www.microsoft.com/security/blog/2022/06/02/new-threat-actors-targeting-mdm/)

---

## Firewalls, WAFs, & Proxies

- **Palo Alto, Cisco ASA, Fortinet:**  
  *Palo Alto Firewall Zero-Day (2021):* Used for RCE and initial access.  
  *Reference:* [Unit 42 Blog](https://unit42.paloaltonetworks.com/pan-os-vulnerability/)

- **AWS WAF:**  
  *Capital One (2019):* WAF SSRF enabled further compromise in AWS.  
  *Reference:* [CSO Online](https://www.csoonline.com/article/3441226/the-capital-one-breach-what-happened-and-what-we-can-learn-from-it.html)

- **Cloudflare:**  
  *Cloudflare Leaks (2017):* Bug exposed sensitive memory, including session tokens.  
  *Reference:* [Cloudflare Blog](https://blog.cloudflare.com/incident-report-on-memory-leak-caused-by-cloudflare-parser-bug/)

---

## Email, Collaboration, & Messaging

- **Microsoft Exchange:**  
  *ProxyLogon (2021):* Multiple zero-days exploited for RCE, privilege escalation, and email theft.  
  *Reference:* [CISA Alert](https://www.cisa.gov/news-events/alerts/2021/03/03/microsoft-releases-out-band-updates-address-exchange-server-vulnerabilities)

- **Gmail & Google Workspace:**  
  *OAuth Token Phishing (2020):* Attackers gained persistent access via malicious OAuth consent.  
  *Reference:* [Google Threat Analysis](https://cloud.google.com/blog/products/identity-security/protecting-against-phishing-oauth)

- **Slack:**  
  *Slack Token Theft (2023):* OAuth tokens stolen and used for lateral movement.  
  *Reference:* [Slack Blog](https://slack.com/blog/news/slack-security-update-january-2023)

- **Zoom, Webex, Teams:**  
  *Zoom-Bombing (2020):* Attackers exploited open meetings for social engineering.  
  *Reference:* [CISA Telework Guidance](https://www.cisa.gov/news-events/news/telework-security-guidance)

---

## VPN, Remote Access, & Zero Trust

- **OpenVPN, Cisco AnyConnect:**  
  *Cisco VPN MFA Bypass (2022):* Social engineering led to VPN and internal access.  
  *Reference:* [Cisco Security Incident](https://blogs.cisco.com/security/cisco-security-incident-response-update)

- **Zscaler, Netskope:**  
  *Cloud Proxy Bypass (2022):* Attackers used proxy misconfigurations to exfiltrate data.  
  *Reference:* [Netskope Threat Labs](https://www.netskope.com/blog/threat-labs)

---

## CI/CD, DevOps, & Source Control

- **GitHub:**  
  *GitHub OAuth Token Theft (2022):* Stolen tokens abused to access private repos.  
  *Reference:* [GitHub Blog](https://github.blog/2022-04-15-security-alert-stolen-oauth-user-tokens/)

- **GitLab:**  
  *GitLab RCE Vulnerability (2021):* Attackers exploited CI/CD to gain code execution.  
  *Reference:* [GitLab Security Release](https://about.gitlab.com/releases/2021/04/14/security-release-gitlab-13-9-5-released/)

- **Jenkins:**  
  *Jenkins Plugins RCE (2019):* Malicious plugin allowed RCE in multiple Jenkins instances.  
  *Reference:* [Jenkins Security Advisory](https://www.jenkins.io/security/advisory/2019-12-17/)

- **CircleCI:**  
  *CircleCI Security Breach (2023):* Stolen secrets and tokens led to widespread compromise.  
  *Reference:* [CircleCI Blog](https://circleci.com/blog/january-4-2023-security-alert/)

---

## Database, Storage, & DLP

- **MongoDB:**  
  *MongoDB Ransomware (2017):* Internet-exposed DBs wiped and ransomed.  
  *Reference:* [Bleeping Computer](https://www.bleepingcomputer.com/news/security/mongodb-ransom-attacks-hit-thousands-of-databases/)

- **Imperva DB Security:**  
  *Imperva Breach (2019):* Attackers stole a subset of database firewall logs and data.  
  *Reference:* [Imperva Disclosure](https://www.imperva.com/blog/notice-of-data-security-incident/)

- **Symantec DLP, Forcepoint:**  
  *DLP Evasion (Multiple):* Attackers regularly test and evade DLP policies, e.g., via encrypted traffic or cloud shares.  
  *Reference:* [Gartner DLP Guidance](https://www.gartner.com/en/documents/4003625)

---

## Virtualization & Infrastructure Management

- **VMware ESXi:**  
  *ESXiArgs Ransomware (2023):* Attackers exploited vulnerabilities for mass ransomware deployment.  
  *Reference:* [CISA ESXiArgs](https://www.cisa.gov/news-events/alerts/2023/02/08/ransomware-attacks-targeting-vmware-esxi-servers)

- **Kaseya VSA:**  
  *Kaseya Supply Chain Ransomware (2021):* Compromised RMM tool used to spread ransomware.  
  *Reference:* [CISA Kaseya Incident](https://www.cisa.gov/news-events/alerts/2021/07/04/guidance-kaseya-vsa-supply-chain-ransomware-attack)

---

## Vulnerability & Patch Management

- **Tenable, Qualys, Nessus:**  
  *Tenable/Nessus Plugin Disabling (Multiple):* Attackers disable scanners or plugins to avoid detection.  
  *Reference:* [Tenable Security Blog](https://www.tenable.com/blog/tag/vulnerabilities)

- **Ivanti:**  
  *Patch Management Bypass (2021):* Vulnerabilities in endpoint management used to bypass controls.  
  *Reference:* [Ivanti Security Updates](https://forums.ivanti.com/s/article/Security-Advisory)

---

## Log & Security Analytics

- **Splunk, Graylog, QRadar:**  
  *Log Tampering (Multiple):* Attackers clear or manipulate security logs to hide activity.  
  *Reference:* [Splunk Blog](https://www.splunk.com/en_us/blog/security/siem-anti-forensics.html)

---

## API, Integration, & Admin Tools

- **ServiceNow:**  
  *API Token Abuse (2022):* Stolen tokens used for data exfiltration from ITSM platforms.  
  *Reference:* [ServiceNow Security Advisory](https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0720123)

- **CyberArk, BeyondTrust (PAM):**  
  *Privileged Access Misuse (Multiple):* Insiders or attackers use PAM tools to escalate and cover tracks.  
  *Reference:* [CyberArk Threat Research](https://www.cyberark.com/resources/threat-research-blog)

---

## Additional Technologies (Selected Cases)

- **Box/Dropbox:**  
  *Box Data Leak (2019):* Misconfigured shared links exposed sensitive data.  
  *Reference:* [KrebsOnSecurity](https://krebsonsecurity.com/2019/05/box-leaks-terabytes-of-data-via-misconfigured-links/)

- **WordPress:**  
  *Plugin Vulnerabilities (Ongoing):* Attackers exploit outdated plugins for site takeover and malware delivery.  
  *Reference:* [Wordfence Blog](https://www.wordfence.com/blog/)

- **Nagios:**  
  *Nagios RCE (2020):* Remote code execution vulnerabilities targeted monitoring servers.  
  *Reference:* [Nagios Security Advisory](https://www.nagios.com/security/)

---

## Conclusion

These cases illustrate that **attackers target every layer of the IT stack**: from cloud to endpoint, from email to CI/CD, from VPNs to log management. **No tool is "too niche" to be attacked**. Proactive, hypothesis-driven threat hunting across all platforms and technologies—such as those referenced in this project—is critical to catch sophisticated, multi-stage, and supply-chain attacks that evade traditional security controls.

