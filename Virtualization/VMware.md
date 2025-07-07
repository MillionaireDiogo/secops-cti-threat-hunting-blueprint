# Threat Hunting with VMware vSphere / ESXi Overview

VMware vSphere/ESXi is a widely used virtualization platform hosting multiple VMs on physical servers. Threat hunting in VMware logs focuses on detecting unauthorized VM lifecycle events, suspicious access, resource anomalies, and potential hypervisor compromise.

---

## 2. Log Sources

| Log Source                | Description                                                           |
|--------------------------|-----------------------------------------------------------------------|
| **vCenter Server Logs**   | Management server logs with VM lifecycle, configuration, and admin activity |
| **ESXi Host Logs**        | Host-level logs including system events, security, and resource usage  |
| **VMware Security Logs**  | Authentication, authorization, and privilege-related events           |
| **VM Logs**               | Individual VM guest OS logs (if integrated)                          |
| **Audit Logs**            | Changes to roles, permissions, and configurations                     |

---

## 3. Threat Hunting Categories & Keywords

### A. VM Lifecycle & Configuration Events

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `vm_power_on`            | VM power-on events — monitor for unexpected startups              |
| `vm_power_off`           | VM shutdown or power-off events                                   |
| `vm_suspend`             | VM suspension events — possible tampering                        |
| `vm_clone`               | VM cloning — suspicious cloning for lateral movement or backup   |
| `vm_snapshot`            | Creation or deletion of VM snapshots                              |

---

### B. Access & Authentication Events

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `login_success`          | Successful logins to vCenter or ESXi hosts                        |
| `login_failure`          | Failed login attempts — brute force or credential guessing       |
| `role_change`            | Changes in user roles or permissions                              |
| `unauthorized_access`    | Access denied or unauthorized resource attempts                   |

---

### C. Resource & Performance Anomalies

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `cpu_spike`              | Sudden CPU usage spikes on hosts or VMs                          |
| `memory_spike`           | Unusual memory consumption                                        |
| `disk_io_spike`          | Unexpected disk read/write activity                               |

---

### D. Security & Privilege Events

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `privilege_escalation`   | Administrative privilege changes or elevation                     |
| `security_alert`         | Alerts triggered by integrated security tools                    |
| `config_change`          | Changes to host or vCenter configuration                          |
| `vm_escape_attempt`      | Indicators of VM escape or hypervisor compromise (if logged)     |

---

## 4. Additional Recommendation

1. Monitor VM lifecycle events for unexpected power-on, cloning, or snapshot activity.  
2. Track authentication attempts, focusing on failures and privilege escalations.  
3. Analyze resource usage spikes for possible crypto-mining or DoS attacks.  
4. Audit configuration and role changes on vCenter and ESXi hosts.  
5. Investigate alerts from integrated security tools or hypervisor anomalies.  

---

