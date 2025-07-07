# Azure Threat Hunting Overview

This document provides a curated list of suspicious Azure API calls, operations, and keywords used for threat hunting across core services such as Azure AD, Storage, Compute, Key Vault, and IAM. It includes relevant log sources (Activity Logs, Audit Logs, Diagnostics, etc.) to support detection of unauthorized access, privilege escalation, persistence mechanisms, and data exfiltration within Azure environments.

---

## Log Sources
- Azure Activity Logs	  
- Azure AD Audit Logs	  
- Azure Diagnostics Logs	  
- Key Vault Logs	 
- Storage Account Logs	  
- Azure Monitor / Log Analytics
- Azure AD Sign-in Logs	 
- Specific Azure-related logs in your environment


### Identity & Access (Azure AD, RBAC, OAuth)

| **Keyword / Operation**                                                      | **Description / Risk**                                       |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `AddMemberToGroup`                                                           | Adding users to privileged groups (e.g., Global Admin).      |
| `UpdatePassword`, `ResetPassword`                                            | Account hijack, especially on privileged users.              |
| `AddDirectoryRoleMember`, `RemoveDirectoryRoleMember`                        | Privilege escalation or role backdooring.                    |
| `Consent to App`, `GrantConsent`                                             | OAuth consent phishing or token abuse.                       |
| `CreateServicePrincipal`, `UpdateServicePrincipal`, `DeleteServicePrincipal` | Creation or tampering of service principals for persistence. |
| `UpdateApplication`, `AddKey`, `AddPassword`                                 | Modifying app credentials, often for abuse.                  |
| `Login with Legacy Protocol`, `ClientAuthMethod=Basic`                       | Use of insecure or deprecated auth (e.g., IMAP, POP3).       |
| `Sign-ins from unfamiliar locations`                                         | Geographic anomalies.                                        |

---

### Azure Storage (Blob, File, Table)

| **Keyword / Operation**                         | **Description / Risk**                                                            |
| ----------------------------------------------- | --------------------------------------------------------------------------------- |
| `ListKeys`, `RegenerateKey`                     | Access to storage account keys – often used for lateral movement or exfiltration. |
| `SetBlobServiceProperties`                      | Modifying CORS or logging settings to hide activity.                              |
| `PutBlob`, `DeleteBlob`, `ListBlobs`, `GetBlob` | Suspicious data staging, deletion, or recon.                                      |
| `SetContainerACL`, `SetContainerMetadata`       | Making containers public or changing access behavior.                             |

---

### Azure IAM (RBAC)

| **Keyword / Operation**                           | **Description / Risk**                                    |
| ------------------------------------------------- | --------------------------------------------------------- |
| `Microsoft.Authorization/roleAssignments/write`   | Assigning roles, potentially maliciously.                 |
| `Microsoft.Authorization/roleDefinitions/write`   | Creating or altering custom roles.                        |
| `ElevateAccess` (via Azure Portal or REST API)    | Global administrator privilege escalation.                |
| `Microsoft.Authorization/policyAssignments/write` | Potential abuse of policies to control security settings. |

---

### Azure Compute / Automation

| **Keyword / Operation**                                            | **Description / Risk**                                               |
| ------------------------------------------------------------------ | -------------------------------------------------------------------- |
| `RunCommand`, `ExecuteCommand`, `Invoke-AzVMRunCommand`            | Remote code execution within VMs.                                    |
| `CreateVirtualMachine`, `StartVirtualMachine`, `CreateVMExtension` | Abnormal VM creation or abuse for crypto-mining or lateral movement. |
| `Deploy Script`, `AutomationAccount/jobstreams`                    | Hidden or automated payload deployment.                              |
| `InstallExtension`, `CustomScriptExtension`                        | Often used for malicious persistence.                                |

---

### Key Vault / Secrets Management

| **Keyword / Operation**              | **Description / Risk**                            |
| ------------------------------------ | ------------------------------------------------- |
| `GetSecret`, `ListSecrets`           | Secrets access — monitor frequency and source IP. |
| `PurgeDeletedSecret`, `DeleteSecret` | Covering tracks or breaking dependencies.         |
| `BackupSecret`, `RestoreSecret`      | Possible exfiltration or tampering.               |

---

### Logging & Monitoring (Azure Monitor / Defender)

| **Keyword / Operation**                                | **Description / Risk**                     |
| ------------------------------------------------------ | ------------------------------------------ |
| `DeleteDiagnosticSettings`, `UpdateDiagnosticSettings` | Disabling logs — high-risk.                |
| `Microsoft.Security/alerts/delete`                     | Alert suppression or log tampering.        |
| `Disable Azure Defender plan`                          | Attempt to bypass native threat detection. |

---

### Token & Session Abuse (Azure AD / OAuth)

| **Keyword / Event**                                  | **Description / Risk**                                  |
| ---------------------------------------------------- | ------------------------------------------------------- |
| `RefreshTokenIssued`, `AccessTokenIssued`, `ConsentGranted` | Watch for excessive or unexpected tokens issued.        |
| `AppOnlyTokenIssued`                                 | Service principal issuing tokens without user context.  |
| `MFABypass`, `MFA registration reset`                | Bypassing MFA or resetting strong auth.                 |

---

## Notable Azure Security Incidents

| **#** | **Incident**                           | **Summary**                                                                                                              | **Key Failures**                                                         | **Impact**                                             | **Source**                                              |
| ----- | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------ | ------------------------------------------------------ | ------------------------------------------------------- |
| **1** | **ChaosDB (Aug 2021)**                 | Chain of flaws in Azure Cosmos DB’s notebook feature allowed attackers to access primary keys of thousands of databases. | No DevOps defenses or audit on notebook/container interactions.          | Full read/write/delete access to customer data.        | Wiz & SC Media ([reddit.com][1], [en.wikipedia.org][2]) |
| **2** | **OMIGOD (Sept 2021)**                 | Remote code execution and root escalation via unpatched OMI agent in Linux VMs.                                          | Lack of monitoring e.g., for unauthorized `RunCommand`.                   | Potential root-level compromise across many tenants.   | Wiz & Reddit                                            |
| **3** | **ACS “ACSESSED” (Aug 2022)**          | Flaw in Azure Cognitive Search “Allow access from portal” leaked network perimeter.                                      | No network/audit alerts for cross‑tenant access.                         | Data-plane leakage across tenants.                     | SecurityWeek                                            |
| **4** | **Azure Exec Account Hack (Feb 2024)** | Phishing-led takeover of mid/senior executive Azure accounts, exposing hundreds.                                         | Weak credential & token monitoring, no detection of user-risk anomalies. | Sensitive executive data accessed.                     | BusinessUpturn & Teiss                                  |
| **5** | **Azure Support DB Leak (Dec 2019)**   | Misconfigured NSG allowed external access to Microsoft support analytics DB.                                             | No internal log/audit on NSG changes or DB exposures.                    | Customer support data of potentially millions exposed. | Reddit                                                  |


