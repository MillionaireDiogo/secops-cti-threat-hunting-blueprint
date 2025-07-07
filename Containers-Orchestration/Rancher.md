# Rancher Threat Hunting Overview

Rancher manages Kubernetes clusters and adds management layers that require monitoring for unauthorized UI/API access, token misuse, and privilege escalation. Watch for resource enumeration, suspicious container execs, unusual pod changes, and network scans indicating lateral movement. Look for configuration tampering like altered role bindings or persistent workloads to maintain access. Detect log manipulation for evasion and monitor secret access, unusual volume mounts, or untrusted container images as signs of data theft or backdoors.

---

## Key Log Sources
- Rancher Server logs  
- Kubernetes audit logs (from managed clusters)  
- Rancher API server audit logs  
- Container runtime logs (docker/containerd)  
- Network flow logs (if integrated)

---

| **Category**            | **Activity**           | **Keywords / Indicators**                                   | **Description / Detection Focus**                           |
|------------------------|-----------------------|------------------------------------------------------------|-------------------------------------------------------------|
| Access & Authentication | Unauthorized login     | login failed, POST /v3-public/localProviders/local*, 401, invalid token | Failed attempts via Rancher UI/API or brute force           |
|                        | Privilege escalation   | CreateGlobalRoleBinding, EditClusterRoleTemplateBinding, admin=true | Gaining elevated access via misconfigured roles or bindings |
|                        | API token abuse        | v3/token, Bearer, GET /v3/user, POST /v3/token              | Suspicious token creation or reuse — API access from external IPs |
|                        | External access        | login from new IP, unusual login, new user-agent            | Unexpected access via Rancher Web UI/API                     |

---

| **Category**             | **Activity**             | **Keywords / Indicators**                                        | **Description / Detection Focus**                          |
|--------------------------|--------------------------|-----------------------------------------------------------------|------------------------------------------------------------|
| Recon & Enumeration    | Cluster inventory        | GET /v3/clusters, oc get clusters, GET /v3/nodes, GET /v3/projects | Recon of attached clusters, nodes, and workloads            |
|                          | Project/namespace mapping | GET /v3/projects, GET /v3/namespaces, GET /v3/workloads          | Discovery of application layout and access scope            |
|                          | RBAC review              | GET /v3/roleTemplates, globalRoleBindings, clusterRoleBindings    | Role enumeration or abuse of custom RBAC setups             |

---

| **Category**                  | **Activity**          | **Keywords / Indicators**                                         | **Description / Detection Focus**                            |
|-------------------------------|----------------------|------------------------------------------------------------------|--------------------------------------------------------------|
|Execution & Lateral Movement | Remote shell access   | kubectl exec, rke2-exec.sh, docker exec, oc rsh, POST /exec      | Remote command execution within managed workloads             |
|                               | Host escape attempts  | privileged=true, hostPath, hostNetwork, CAP_SYS_ADMIN, mount /host | Privileged container abuse to reach host OS or Rancher node  |
|                               | Pod manipulation     | PATCH /workloads, oc apply, kubectl patch, new initContainer      | Injecting malicious containers or altering deployment configs |
|                               | CRD abuse            | kubectl apply -f crd.yaml, CustomResourceDefinition, rancher.cattle.io | Creating or modifying Rancher-managed CRDs for persistence or misuse |

---

| **Category**                        | **Activity**           | **Keywords / Indicators**                                             | **Description / Detection Focus**                          |
|------------------------------------|-----------------------|----------------------------------------------------------------------|------------------------------------------------------------|
| Persistence & Infrastructure Manipulation | Deploy malicious app  | POST /v3/workloads, curl, wget, reverse shell, sleep &&              | New workloads designed for remote control or beaconing     |
|                                    | Add cluster           | POST /v3/clusters, import cluster, EKS, AKS, RKE2                    | Abusing Rancher to import rogue or attacker-controlled clusters |
|                                    | Malicious Helm charts | POST /v3/catalog.cattle.io.clusterrepos, helm install, rancher-charts | Using chart repos to deliver backdoored applications        |
|                                    | Webhook abuse         | Create webhook, triggered webhook, automation scripts, CI/CD          | Malicious integration with pipelines or CI tasks            |

---

| **Category**                  | **Activity**          | **Keywords / Indicators**                                         | **Description / Detection Focus**                       |
|-------------------------------|----------------------|------------------------------------------------------------------|---------------------------------------------------------|
| Defense Evasion & Anti-Forensics | Delete logs           | DELETE /v3/logs, rm -rf /var/log/rancher, logrotate abuse        | Attempt to wipe or rotate Rancher server logs           |
|                               | API stealth           | low-rate API calls, non-browser user-agent, scripted API access  | Abuse of Rancher API via headless/scripted clients       |
|                               | Temporary container use| create → delete within seconds, job, sleep && rm -rf             | Short-lived pods used for data access or execution       |
|                               | Bypass audit          | auditLog: disabled, auditLevel: none, disable monitoring         | Modifying Rancher/K8s audit policies to hide activity    |

---

| **Category**                  | **Activity**              | **Keywords / Indicators**                                     | **Description / Detection Focus**                        |
|-------------------------------|---------------------------|--------------------------------------------------------------|----------------------------------------------------------|
| Data Exfiltration & Registry Abuse | Secrets access             | GET /v3/secrets, kubectl get secrets, base64 -d              | Reading Rancher-managed secrets or Kubernetes secrets     |
|                               | Image pull from rogue registry | image: attacker.io/malicious, quay.io, docker pull, POST /v3/images | Running or pulling untrusted container images             |
|                               | Registry token abuse       | registry.cattle.io, create dockercredential, POST /v3/dockerCredential | Abusing Rancher registry credentials or integrations      |
|                               | Exfil via pods            | nc, curl, wget, POST /api/exfil, reverse shell from pod       | Data sent out of cluster from compromised container       |

---

### Additional Tips for Rancher Threat Hunting

- Track changes to global or cluster-level roles (`CreateGlobalRoleBinding`, admin edits).
- Hunt for new Helm chart installs or repositories not approved by security.
- Watch for short-lived or privileged workloads — especially those with `hostPath`, `hostNetwork`, or added capabilities.
- Correlate API requests from new IPs or unusual user-agents with token usage.
- Monitor access to multiple clusters from a single compromised Rancher account.
