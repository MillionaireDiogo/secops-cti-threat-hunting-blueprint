#  GCP Threat Hunting Overview

GCP threat hunting involves proactively analyzing Cloud Audit Logs, Data Access events, and service-specific telemetry to detect malicious or anomalous activities such as unauthorized access, privilege escalation, persistence mechanisms, and data exfiltration. By monitoring API calls, IAM changes, storage interactions, and serverless activity, defenders can uncover stealthy attacker behavior across Google Cloud environments.

---

## Log Sources
- Cloud Audit Logs – Admin Activity  
- Cloud Audit Logs – Data Access  
- VPC Flow Logs  
- Cloud Functions / Cloud Run / Scheduler Logs  
- Monitoring & Logging Config Audit (Log Sink Events)	 
- Specific AWS-related logs in your environment


## 🔍 GCP Threat Hunting – Suspicious API Activities & Descriptions

## 🕵️ Reconnaissance & Discovery

| **API Call** | **Description** |
|--------------|-----------------|
| `compute.instances.list` | Lists all VM instances, commonly used to enumerate compute resources. |
| `compute.firewalls.list` | Reveals firewall rules, potentially exposing network paths or weak filtering. |
| `compute.networks.list` | Displays VPC networks, aiding attackers in mapping the cloud environment. |
| `compute.subnetworks.list` | Shows subnet ranges and regions, helpful for lateral movement planning. |
| `iam.roles.list` | Enumerates IAM roles, often used to identify privilege escalation paths. |
| `iam.serviceAccounts.list` | Lists service accounts, which may be targeted for abuse or impersonation. |
| `resourcemanager.projects.getIamPolicy` | Retrieves project-level IAM bindings, useful for understanding access control. |
| `resourcemanager.folders.getIamPolicy` | Lists IAM settings on folders, exposing broader org-level permissions. |
| `resourcemanager.organizations.getIamPolicy` | Audits org-wide permissions, often a target for full privilege mapping. |
| `container.clusters.list` | Reveals GKE clusters, which could lead to container takeover. |
| `container.nodes.list` | Lists GKE node pools or VMs; used for deeper infrastructure recon. |
| `container.namespaces.list` | Enumerates Kubernetes namespaces; useful for identifying workloads or privileges. |

---

## 🔐 Credential Crime & Privilege Escalation

| **API Call** | **Description** |
|--------------|-----------------|
| `iam.serviceAccountKeys.create` | Creates new SA keys, commonly used for persistence or backdoor access. |
| `iam.serviceAccountKeys.delete` | Deletes keys to cover tracks or disable access. |
| `iam.serviceAccounts.create` | Adds a new service account; may serve as a persistent identity. |
| `iam.serviceAccounts.delete` | Removes a service account, potentially disrupting audit trails. |
| `iam.serviceAccounts.signJwt` | Signs custom JWTs for unauthorized authentication to GCP services. |
| `iam.serviceAccounts.signBlob` | Used to cryptographically sign arbitrary blobs, can be misused for spoofing. |
| `iam.serviceAccounts.generateAccessToken` | Grants OAuth tokens for impersonation; very high-risk for abuse. |
| `resourcemanager.projects.setIamPolicy` | Alters project-level permissions, enabling full control if abused. |
| `resourcemanager.folders.setIamPolicy` | Modifies folder IAM policies, enabling cross-project access. |
| `resourcemanager.organizations.setIamPolicy` | Changes org-wide permissions—massive privilege escalation vector. |
| `compute.instances.setServiceAccount` | Attaches a different SA to a VM, enabling lateral movement or token abuse. |
| `compute.instances.attachDisk` | Mounts persistent disks to other instances, potentially for stealthy data access. |

---

## 🚨 Defense Evasion & Persistence

| **API Call** | **Description** |
|--------------|-----------------|
| `logging.sinks.create` | Creates a sink to divert or duplicate logs; may aid stealth. |
| `logging.sinks.delete` | Deletes log sinks to prevent forwarding to SIEM or security tooling. |
| `logging.sinks.update` | Modifies sink targets or filters, possibly to exclude malicious actions. |
| `logging.settings.get` | Views global log settings—recon for logging configuration. |
| `monitoring.alertPolicies.create` | Adds fake or noisy alerts to drown out real activity. |
| `monitoring.alertPolicies.delete` | Removes detection mechanisms, degrading visibility. |
| `monitoring.notificationChannel.create` | Sets up alternate alert channels for attacker monitoring. |
| `monitoring.notificationChannel.delete` | Deletes alert channels to prevent detection response. |
| `cloudfunctions.functions.create` | Deploys serverless functions, often used for covert payload execution. |
| `cloudfunctions.functions.delete` | Removes malicious or noisy functions post-execution. |
| `cloudrun.services.create` | Creates container-based service, which may run malicious workloads. |
| `cloudrun.services.delete` | Deletes Cloud Run services, potentially cleaning up malicious usage. |
| `composer.environments.create` | Spins up Composer DAG environments, which can run arbitrary Python code. |
| `composer.environments.delete` | Deletes Composer environments after abuse to reduce forensic trace. |
| `scheduler.jobs.create` | Schedules jobs for persistence (e.g., recurring data exfil). |
| `scheduler.jobs.delete` | Deletes scheduled jobs to hide malicious persistence. |

---

## 📤 Data Exfiltration / Destruction

| **API Call** | **Description** |
|--------------|-----------------|
| `storage.buckets.getIamPolicy` | Reveals who can access GCS buckets—useful for exfil planning. |
| `storage.buckets.delete` | Deletes buckets, potentially destroying exfil evidence or data. |
| `storage.objects.get` | Retrieves objects from buckets; primary method of data exfiltration. |
| `storage.objects.list` | Lists objects; used to identify sensitive or valuable data. |
| `storage.objects.delete` | Erases stored data, possibly as part of destructive attacks. |
| `bigquery.jobs.create` | Executes BigQuery jobs—may include extraction queries for data theft. |
| `bigquery.tables.get` | Retrieves table schema or metadata—useful for planning exfiltration. |
| `bigquery.tables.list` | Lists tables in datasets; often used for recon of valuable data. |
| `bigquery.tables.delete` | Deletes tables, either to destroy or sabotage datasets. |
| `pubsub.subscriptions.pull` | Reads messages from topics; can be abused to tap into sensitive comms. |
