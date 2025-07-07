
# Threat Hunting Hypothesis

This repository contains structured directories and markdown (`.md`) files designed to assist cybersecurity analysts and threat hunters in formulating threat hunting hypotheses, particularly when integrating various technologies into Security Information and Event Management (SIEM) solutions.

## Purpose

The main goal of this repository is to provide:

- **Standardized Templates:**  
  Ready-to-use markdown files to document hypotheses, detection logic, indicators of compromise (IoCs), and recommended data sources related to specific technologies.

- **Structured Approach:**  
  A clear, categorized approach to threat hunting by grouping technologies by their domain.

- **Collaborative Resource:**  
  An open-source repository encouraging contributions and collaborative enhancements from the cybersecurity community.

---

## Directory Structure

Each category is structured into directories containing markdown files named after individual technologies. Categories include:

- Additional Technologies
- Cloud Platforms & Infrastructure
- CMS Platforms
- Collaboration & Productivity
- Containers Orchestration
- Database & Data Management
- Directory & Authentication
- Email Security & Phishing
- Endpoint Security
- Firewalls & Network Security
- Identity & Access Management 
- Mobile Device Management
- Password Managers
- Virtualization
- Web & Application Firewalls

---

## Real-World Security Breaches from Cyber Threat Intelligence (CTI)

Understanding the real-world impact of security breaches is critical for justifying proactive threat hunting across all organizational technologies. The [CTI.md](./CTI.md) file compiles notable, referenced security incidents affecting cloud platforms, endpoints, IAM/SSO, VPN, collaboration, DevOps, DLP, log management, and more.

By studying these breaches sourced from public Cyber Threat Intelligence (CTI) reports and advisories, you’ll see why hypothesis-driven threat hunting is essential for detecting sophisticated, multi-stage, or supply-chain attacks that evade traditional security controls. Each case is mapped to the technologies referenced in this repository, demonstrating the value of monitoring **every layer of your technology stack**.

> **Read more:** [Real-World CTI Security Breaches & Lessons Learned →](./CTI.md)

---


## How to Use

1. **Select a Category:**  
   Navigate to the relevant technology category.

2. **Open the Markdown File:**  
   Each markdown file corresponds to a specific technology.

**Note:** These repositories provide keywords that can be utilized with the query languages of various SIEM tools, paired with specific log sources for each device, tool, or technology you're threat hunting for. Rich sets of keywords are available in each `.md` file associated with individual tools or technologies.

### Example Threat Hunting Steps

**Scenario:** Threat hunting for AWS S3 activities using Rapid7 SIEM and query language.

#### Step-by-step Threat Hunting Process in AWS (S3) Using a Hypothesis-driven Approach:

**Step 1: Define Your Hypothesis Clearly**

Clearly outline your threat-hunting hypothesis.

**Example Hypothesis:**  
*"An attacker is performing unauthorized access or enumeration attempts against sensitive S3 buckets, potentially resulting in anomalous 'AccessDenied' errors or unusual access patterns."*

**Step 2: Select Appropriate Log Sources**

Identify the AWS log sources relevant to your hypothesis, such as:

- AWS CloudTrail (API actions, bucket listing, unauthorized attempts)
- Amazon S3 Server Access Logs (Detailed object-level requests)
- AWS GuardDuty (Automated anomaly detection)

**Additional Consideration:**  
Select the log sources from AWS integrated into the SIEM (e.g., Microsoft Sentinel, Splunk).

**Step 3: Define Relevant Keywords or Indicators of Compromise (IoCs)**

Generate keywords related to the hypothesis, for example:

- `AccessDenied`
- `ListBuckets`
- `GetBucketAcl`
- `PutBucketPolicy`
- `DeleteBucketPolicy`
- Suspicious IP addresses or UserAgents

**Step 4: Select Appropriate Timeframe for Analysis**

Choose a relevant timeframe based on threat intelligence or security alerts:

- Recent anomalies: Last 7 Days
- Historical analysis: Last 30–90 Days

**Additional Consideration:**  
Adjust the timeframe based on business-critical events (e.g., recent deployments or security incidents).

**Step 5: Convert Your Hypothesis into Query Language (e.g., Rapid7 Query Language)**

```sql
where(eventName = "ListBuckets" or "GetBucketAcl" or "PutBucketPolicy" or "DeleteBucketPolicy")
groupby(sourceIPAddress)
```

**Step 6: Execute Query and Analyze the Results**

Run the query against selected log sources in Rapid7 (the specific use SIEM use case in this example), or Microsoft Sentinel, or Splunk.

**Identify:**
- Unusual IP addresses or User identities.
- Spikes in denied access attempts.
- Unexpected bucket enumeration attempts.

**Step 7: Pivot and Expand Your Investigation**
Based on initial findings, pivot to:
- Analyze additional AWS log sources (e.g., VPC Flow Logs).
- Check historical logs for correlated behavior.
- Perform IP reputation checks (e.g., via VirusTotal, AbuseIPDB).

**Step 8: Refine the Hypothesis and Iterate the Process**
Based on initial results, refine or update your hypothesis.
- Develop additional hunts focusing on discovered threats or emerging trends.
- Establish ongoing monitoring based on successful queries.

---

## Contribution
Contributions are highly encouraged! Please fork this repository, add your enhancements, and submit pull requests.

## License
This project is open-sourced under the MIT license. See the [LICENSE](LICENSE) file for details.
