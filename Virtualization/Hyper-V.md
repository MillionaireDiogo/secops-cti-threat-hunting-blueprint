# Threat Hunting with Microsoft Hyper-V Overview

Microsoft Hyper-V is a virtualization platform hosting multiple VMs on a single physical host. Threat hunting in Hyper-V logs focuses on detecting unauthorized VM access, suspicious VM lifecycle events, resource misuse, and potential hypervisor attacks.

---

## 2. Log Sources

| Log Source                  | Description                                                           |
|----------------------------|-----------------------------------------------------------------------|
| **Hyper-V-VMMS Logs**      | Virtual Machine Management Service events (start, stop, pause VMs)   |
| **Hyper-V-Worker Logs**    | VM worker process events, VM state changes, crashes                  |
| **Hyper-V-Compute Logs**   | Hypervisor compute events, resource allocation, and errors           |
| **Security Event Logs**    | Host OS security events including login, privilege use, and audits   |
| **System Event Logs**      | Host system errors, warnings, and informational events               |

---

## 3. Threat Hunting Categories & Keywords

### A. VM Lifecycle & Access Events

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `vm_start`               | VM start events — unexpected or off-hours VM starts               |
| `vm_stop`                | VM shutdown events — unexpected or forced shutdowns               |
| `vm_pause`               | VM paused or suspended events — possible tampering                |
| `vm_creation`            | New VM creation — check for unauthorized VMs                      |
| `vm_deletion`            | VM deletion — possible cleanup of evidence                         |

---

### B. Resource & Performance Anomalies

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `cpu_usage`              | Unusual CPU spikes on host or VMs                                |
| `memory_usage`           | Sudden memory consumption increases                             |
| `disk_io`                | Unexpected disk read/write activity                              |

---

### C. Security & Privilege Events

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `failed_login`           | Failed host or Hyper-V service authentication attempts            |
| `privilege_escalation`   | Use of admin privileges on host                                    |
| `vm_escape_attempt`      | Indicators of hypervisor escape attempts (if logged)              |
| `hypervisor_errors`      | Errors or warnings from Hyper-V indicating potential tampering    |

---

### D. Configuration Changes

| Keyword/Field             | Description                                                       |
|--------------------------|-------------------------------------------------------------------|
| `vm_configuration_change`| Modifications to VM settings or snapshots                         |
| `host_configuration_change`| Changes to Hyper-V host settings                                |
| `snapshot_creation`      | Creation of VM snapshots — possible attempt to preserve state    |
| `snapshot_deletion`      | Snapshot deletions — potential evidence tampering                |

---

## 4. Additional Recommendation

1. Monitor unexpected VM start/stop/pause events outside of business hours.  
2. Detect unauthorized creation or deletion of VMs and snapshots.  
3. Investigate resource usage spikes for potential crypto-mining or DoS attacks.  
4. Track failed login attempts and privilege escalations on the Hyper-V host.  
5. Audit configuration changes for suspicious modifications or tampering.  

---

