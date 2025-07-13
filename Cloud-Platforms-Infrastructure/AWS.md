# AWS Threat Hunting Overview

AWS threat hunting focuses on detecting suspicious activities by analyzing CloudTrail logs, IAM actions, S3 access patterns, and API calls across services like EC2, STS, Lambda, and RDS. Key threats include unauthorized access, privilege escalation, data exfiltration, and evasion techniques such as disabling logging or modifying resource policies.

---

## Log Sources
- CloudTrail  
- CloudWatch  
- GuardDuty  
- VPC Flow Logs  
- S3 Access Logs  
- ELB/ALB/NLB Logs  
- AWS WAF Logs  
- Specific AWS-related logs in your environment

---

## Suspicious API Calls & Descriptions

### IAM & Identity
- `CreateUser` – Creates a new IAM user; may be used to establish persistence.
- `DeleteUser` – Removes an IAM user; could be used to cover tracks.
- `CreateAccessKey` – Generates access keys for IAM users; often used for unauthorized API access.
- `DeleteAccessKey` – Removes access keys; could be used to disrupt auditing.
- `UpdateAccessKey` – Changes state of existing access keys; may indicate credential rotation or misuse.
- `AttachUserPolicy` – Grants permissions to a user; common in privilege escalation.
- `DetachUserPolicy` – Removes policies from a user; may be used to evade detection.
- `PutUserPolicy` – Creates or updates an inline user policy; can grant hidden permissions.
- `AttachRolePolicy` – Binds managed policies to a role; often seen in privilege abuse.
- `PutRolePolicy` – Creates an inline policy on a role; can mask malicious permissions.
- `UpdateAssumeRolePolicy` – Modifies trust relationships; could be used to hijack role access.
- `CreatePolicy` – Adds a new IAM policy; may be backdoored for privilege abuse.
- `CreatePolicyVersion` – Creates a new version of an existing policy; may overwrite restrictive versions.
- `PassRole` – Grants permissions to assume roles; used in privilege chaining.
- `CreateLoginProfile` – Enables console login for IAM user; may indicate interactive access setup.
- `UpdateLoginProfile` – Changes login credentials for an IAM user.
- `CreateServiceSpecificCredential` – Adds credentials for specific AWS services; may be misused for lateral movement.
- `ResetServiceSpecificCredential` – Resets service-specific credentials; may indicate compromise.
- `GetLogin` – Retrieves AWS Management Console login information; may indicate reconnaissance.

### Federation & Tokens (STS)

- `AssumeRole` – Used to gain temporary access to another role; common in lateral movement.
- `AssumeRoleWithSAML` – Federation-based temporary access; may be abused in SAML misconfig attacks.
- `AssumeRoleWithWebIdentity` – Grants temporary credentials via OIDC provider.
- `GetSessionToken` – Retrieves temporary security credentials; often seen in token-based attacks.
- `GetFederationToken` – Returns temp credentials for federated users; can be used to access resources anonymously.
- `GetFederationTokens` – Duplicate or malformed variant (likely typo or alias).
- `GetRoleCredentials` – Fetches credentials for roles via AWS SSO; useful in post-auth scenarios.
- `GetCredentialsForIdentity` – Used by Cognito to get temp credentials; monitor for abuse.
- `GetOpenIdToken` – Retrieves token from Cognito; watch for identity misconfiguration.
- `GetOpenIdTokenForDeveloperIdentity` – Issues OIDC tokens for developer-authenticated identities.

### S3 & Object Storage

- `ListBucket` – Lists contents of S3 buckets; common in reconnaissance.
- `GetObject` – Retrieves objects from a bucket; may indicate data exfiltration.
- `PutObjectAcl` – Sets access permissions on an object; may make data public.
- `PutBucketAcl` – Alters bucket-level access; potential for privilege escalation or data exposure.
- `PutBucketPolicy` – Applies access policy to a bucket; monitor for policy drift.
- `GetBucketPolicy` – Retrieves current bucket policy; can be used for recon.
- `DeleteBucketPolicy` – Removes bucket policy, possibly disabling access controls.
- `DeleteObject` – Deletes an object; may be part of data destruction or obfuscation.

### Compute (EC2, Lambda, ECS)

- `RunInstances` – Launches EC2 instances; could indicate cryptojacking or lateral movement.
- `StopInstances` – Stops one or more instances; may be used to disrupt services.
- `TerminateInstances` – Permanently deletes EC2 instances; watch for sabotage.
- `DescribeInstances` – Lists details about instances; typical recon behavior.
- `CreateNetworkInterface` – May be used for covert channels or lateral movement.
- `AttachNetworkInterface` – Attaches secondary network interfaces; can be abused for stealth.
- `CreateTags` – Labels resources; may be used for obfuscation or organization by attackers.
- `ModifyInstanceAttribute` – Changes VM configs; may lower security or enable malware.
- `CreateSecurityGroup` – Used to define inbound/outbound traffic; may open backdoors.
- `AuthorizeSecurityGroupIngress` – Grants inbound access; could allow external access.
- `AuthorizeSecurityGroupEgress` – Grants outbound access; may enable exfiltration.
- `RevokeSecurityGroupEgress` – Restricts outbound traffic; may break containment.

### Lambda & Serverless

- `CreateFunction` – Deploys a new Lambda; may be used for execution or persistence.
- `UpdateFunctionCode` – Changes Lambda code; could inject malicious logic.
- `InvokeFunction` – Executes a Lambda function; may indicate active exploitation.
- `AddPermission` – Grants trigger permission to a Lambda; can expose it to public or other accounts.
- `RemovePermission` – Revokes trigger access; could be used to hide malicious functions.

### Key Management (KMS, Secrets Manager)

- `GetSecretValue` – Retrieves a secret; high-risk for credential theft or data exfiltration.
- `ScheduleKeyDeletion` – Marks a KMS key for deletion; could be part of data destruction.
- `DisableKey` – Disables encryption key; may break dependent services or secure storage.

### CloudTrail & Logging

- `PutEventSelectors` – Alters CloudTrail configuration; may reduce visibility into actions.
- `DeleteTrail` – Removes audit trails; high-fidelity indicator of evasion.
- `StopLogging` – Temporarily disables CloudTrail logging; critical detection opportunity.
- `StartLogging` – Enables logging; attackers may toggle to blend in.
- `UpdateTrail` – Changes log destination or configuration; can be used for evasion.

### Systems Manager (SSM)

- `SendCommand` – Executes shell commands on instances; often seen in remote code execution.
- `StartSession` – Opens an interactive session; may be used for lateral movement.
- `GetCommandInvocation` – Retrieves command output; can show success of malicious activity.

### Other Services

- `CreateStack` – Launches CloudFormation stacks; attackers may use to deploy infrastructure.
- `UpdateStack` – Alters existing infrastructure; can inject malicious changes.
- `StartBuild` – Executes CodeBuild projects; can be used to run arbitrary code.
- `StartPipelineExecution` – Triggers CI/CD pipelines; could be abused for code injection.
- `GetJobUnlockCode` – Unlocks device jobs (IoT); monitor for unauthorized activity.
- `RequestUploadCredentials` – Grants temporary upload rights; watch for exfiltration.
- `GetFile`, `GetCommit`, `GetDifferences` – Likely from CodeCommit; indicates repo access.
- `PollForJobs` – Used to retrieve build jobs; monitor for suspicious activity.
- `DownloadDefaultKeyPair`, `GetKeyPair`, `GetKeyPairs` – Retrieves EC2 key pairs; may be used for unauthorized access.
- `GetPasswordData` – Retrieves EC2 instance password; useful in brute-force or lateral movement.
- `DescribeChapCredentials` – Used in Storage Gateway; rarely seen, potential abuse vector.
- `ListApiKeys` – Lists API keys (API Gateway); useful in access discovery.
- `CreateApiKey` – Adds a new API key; could be used to maintain unauthorized access.
- `BatchGetItem`, `GetItem` – Accesses DynamoDB data; potential for data exfiltration.
- `DescribeDBInstances` – Details about RDS instances; typical recon behavior.
- `ModifyDBInstance` – Alters RDS settings; could weaken security.
- `DeleteDBInstance` – Deletes a database; may be part of sabotage.
- `DescribeDBClusters` – Fetches RDS cluster metadata; used in planning attacks.
- `DeleteDBCluster` – Destroys RDS clusters; likely malicious.
- `CreateDBSnapshot` – Takes database snapshot; could be used for data theft.
- `CopyDBSnapshot` – Clones snapshots; may be exfiltration step.
- `ExportDBSnapshotToS3` – Dumps RDS snapshot to S3; classic data theft tactic.
- `RestoreDBInstanceFromDBSnapshot` – Spins up DB from snapshot; might clone production data.
- `ModifyDBClusterParameterGroup` – Alters DB config; may reduce security.
- `CreateIdentityPool` – Used in Cognito; may be involved in auth misconfiguration.
- `UpdateIdentityPool`, `SetIdentityPoolRoles` – Can modify or escalate privileges.
- `CreateUserPoolClient` – Adds an app client to Cognito; could be used for abuse.
- `AdminCreateUser`, `AdminSetUserPassword` – Used to establish accounts or backdoor user access.
- `AccessDenied` – A failed action due to lack of permission; useful signal for detection.

---

## AWS GuardDuty Keywords
- Recon:EC2/PortProbeUnprotectedPort  
- UnauthorizedAccess  
- CryptoCurrency  
- Backdoor  
- BruteForce  
- Trojan  
- MaliciousIPCaller  
- PenTest  
- Exfiltration  

---

## AWS Config Keywords
- ConfigRuleCompliance  
- configurationChange  
- configurationItemDiff  
- ResourceDeletion  
- NonCompliant  
- ResourceCreation  

---

## VPC Flow Logs Keywords
- REJECT  
- DENY  
- FAIL  
- port scanning  
- unusual port numbers like 4444, 1337, 31337, 6667  
- SSH brute force attempts (port 22)  
- unusual outbound connections (e.g., IPs 0.0.0.0, 255.255.255.255, unexpected external IP ranges)  

---

## AWS ELB/ALB Keywords
- HTTP Status Codes: 401, 403, 404, 500, 503  
- Methods: POST, PUT, DELETE  
- sqlmap  
- suspicious User-Agent strings (`curl`, `wget`, `python-requests`, `nmap`)  
- `../` (directory traversal attempts)  
- `%3Cscript%3E` (XSS attempts)  

---

## Route53 DNS Keywords
**Suspicious DNS lookups:**  
- `*.onion`  
- `*.xyz`  
- `*.ru`  
- `*.cn`  
- known malicious domains (e.g., `pastebin.com`, `ghostbin.co`, `zerobin.net`)  
- DNS tunneling indicators (`dnscat`, `iodine`, `dns2tcp`)  

---

## AWS WAF Logs Keywords
- **SQL Injection indicators:** (`SELECT`, `DROP`, `DELETE FROM`, `OR 1=1`, `UNION`)  
- **XSS attempts:** (`<script>`, `%3Cscript%3E`)  
- **File inclusion attempts:** (`etc/passwd`, `boot.ini`)  
- **Command injection attempts:** (`nc`, `netcat`, `bash -i`, `sh -i`, `curl`)  

---

## Advanced Indicators for Threat Actors
- Cobalt Strike  
- PowerShell  
- mimikatz  
- Empire  
- Metasploit  
- Meterpreter  
- Lateral Movement  
- Persistence  
- Reconnaissance  
- Command and Control (C2)  

---
