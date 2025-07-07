# ☸️ Kubernetes Threat Hunting Overview

Kubernetes threat hunting involves proactively analyzing activity within clusters to detect signs of compromise, misconfiguration, or abuse. Focus areas include unauthorized access to the API server, exploitation of exposed services, abuse of RBAC permissions, suspicious pod behavior, container escapes, and lateral movement across nodes. Monitoring audit logs, network activity, and runtime events helps identify early indicators of attack within the container orchestration environment.

---

## 📄 Key Log Sources
- Kubernetes API Server Audit Logs
- Container Runtime Logs (e.g., containerd, CRI-O)
- Kubelet Logs 
- Cloud Provider Logs (e.g., GKE, EKS, AKS)

---

## Kubernetes Threat Hunting Keywords & Descriptions

### Access & Authentication

| **Activity**            | **Keywords / Indicators**                                                                              | **Description / What to Look For**                            |
|-------------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| Unauthorized access     | `kubectl exec`, `kubectl proxy`, `kubeconfig`, `ServiceAccount token`, `kubelet`                      | Abused tools to access workloads or API                        |
| Privilege escalation    | `ClusterRoleBinding`, `RoleBinding`, `create clusterrolebinding`, `use of wildcard (*)`, `kube-system`| Attackers escalating privileges via misconfigured RBAC         |
| Service account abuse   | `automountServiceAccountToken=true`, `default service account used`                                   | Unauthorized token use or broad access by default SA           |
| API server access       | `kubectl --token`, `curl https://kubernetes.default.svc`, `kube-apiserver`                            | Direct API calls from pods (often via curl or custom scripts)  |

---

### Discovery & Reconnaissance

| **Activity**              | **Keywords / Indicators**                                           | **Description / What to Look For**               |
|---------------------------|---------------------------------------------------------------------|--------------------------------------------------|
| Pod and service discovery | `kubectl get pods`, `kubectl get services`, `GET /api/v1/pods`     | Enumeration of resources                         |
| Namespace discovery       | `kubectl get namespaces`, `GET /api/v1/namespaces`                 | Reconnaissance of cluster organization           |
| Node and role info        | `kubectl get nodes`, `GET /api/v1/nodes`, `kubelet access`          | Identifying roles/privileges of nodes            |

---

### Execution & Lateral Movement

| **Activity**              | **Keywords / Indicators**                                                      | **Description / What to Look For**             |
|---------------------------|--------------------------------------------------------------------------------|------------------------------------------------|
| Command execution in pod  | `kubectl exec`, `POST /exec`, `/bin/bash -c`, `sh -i`                          | Remote shell access to containers              |
| Container escape attempt  | `hostPath mount`, `/proc`, `/dev`, `privileged: true`, `CAP_SYS_ADMIN`        | Attempts to access host resources              |
| Node compromise           | `hostNetwork: true`, `hostPID: true`, `hostIPC: true`                          | Pod with host-level visibility                 |
| Network access            | `kubectl port-forward`, `netcat`, `socat`, `curl`, `nmap`                      | Tools used for lateral movement or scanning    |

---

### Persistence

| **Activity**             | **Keywords / Indicators**                                                | **Description / What to Look For**                 |
|--------------------------|---------------------------------------------------------------------------|----------------------------------------------------|
| Malicious CronJobs       | `kubectl create cronjob`, `POST /apis/batch/v1/cronjobs`                  | Attackers installing cronjobs for re-access        |
| Deployment manipulation  | `kubectl patch`, `kubectl apply`, `update deployment`, `initContainer`   | Adding containers or init tasks with malicious code|
| New container/image      | `docker pull`, `kubectl run`, `image: attacker/image`                     | Unauthorized image or suspicious registry use      |

---

###  Defense Evasion

| **Activity**            | **Keywords / Indicators**                                                      | **Description / What to Look For**                |
|-------------------------|----------------------------------------------------------------------------------|---------------------------------------------------|
| Log deletion            | `rm -rf /var/log`, `unset HISTFILE`, `auditPolicy=none`                         | Attempts to hide activity or reduce logging       |
| Disable audit logging   | `auditPolicy: null`, `empty audit policy`, `disable admission controller`       | Disabling or bypassing security tools             |
| Delete resources        | `kubectl delete`, `DELETE /api/v1/pods`, `DELETE /deployments`                  | Rapid deletion of resources to cover tracks       |


---

### Data Exfiltration & Impact

| **Activity**               | **Keywords / Indicators**                                               | **Description / What to Look For**               |
|----------------------------|-------------------------------------------------------------------------|--------------------------------------------------|
| Secrets access             | `kubectl get secrets`, `GET /api/v1/secrets`, `base64 -d`               | Attempts to read or decode secrets               |
| Persistent Volume misuse   | `mountPath: /mnt`, `hostPath`, `PVC access from pod`                    | Abusing storage to steal or modify data          |
| External communication     | `curl http://malicious.com`, `wget`, `nc <IP>`                          | Calls to external C2 infrastructure              |
