# Real-World Security Breaches & Why Threat Hunting Matters

The following examples demonstrate that **no technology stack is immune to compromise**. Attackers have targeted almost every major class of IT, cloud, and security tool used in modern organizations. This list pairs common breach scenarios with specific technologies, proving the need for continuous threat hunting across all tools.

---

- **AWS (S3, IAM, WAF):**  
  *Capital One Breach (2019):* Misconfigured EC2 and WAF infrastructure in AWS.  
  *Reference:* [Digital Library](https://dl.acm.org/doi/10.1145/3546068)

- **Azure:**  
  *ChaosDB (2021):* Azure Cosmos DB vulnerability exposed thousands of customer keys.  
  *Reference:* [Wiz Blog - ChaosDB](https://www.wiz.io/blog/chaosdb-how-we-hacked-thousands-of-azure-customers-databases)

- **GCP:**  
  *Google Cloud IAM (2021):* Researchers found ways to abuse Google Cloud IAM privilege escalation paths for lateral movement.  
  *Reference:* [StrongDM - GCP](https://www.strongdm.com/what-is/google-data-breach)

- **Active Directory (AD):**  
  *Cisco Data Breach (2025):* Leakage of Active Directory Credentials.  
  *Reference:* [Non-Human Identity Management Group](https://nhimg.org/cisco-data-breach-leaks-active-directory-credentials)

- **Azure AD:**  
  *Marks & Spencer (M&S) Ransomware Attack (2025):* Infiltrated network via social engineering, stole the NTDS.dit file (the core AD database).  
  *Reference:* [SecOps](https://specopssoft.com/blog/marks-spencer-ransomware-active-directory/)

- **Okta:**  
  *Okta (2023) :* Breach via third-party engineer compromised SSO and downstream apps.  
  *Reference:* [TechTarget News](https://www.techtarget.com/searchsecurity/news/366551082/Okta-4-customers-compromised-in-social-engineering-attacks)

- **Ivanti (MDM):**  
  *Norwegian government agencies Breach (2023):* Two critical vulnerabilities (CVE‑2023‑35078 and CVE‑2023‑35081) were exploited in Ivanti’s MDM..  
  *Reference:* [The Register](https://www.theregister.com/2023/08/03/ivanti_cisa_norway_attack?)

- **AWS WAF:**  
  *Capital One (2019):* WAF SSRF enabled further compromise in AWS.  
  *Reference:* [ACM Digital Library](https://dl.acm.org/doi/10.1145/3546068)

---
