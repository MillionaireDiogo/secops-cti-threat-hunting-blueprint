# Threat Hunting with SailPoint Identity Governance (IGA) Overview

SailPoint IGA manages and governs user identities, access rights, and entitlements across systems. Threat hunting in SailPoint logs helps detect inappropriate access grants, segregation of duties violations, anomalous user behavior, and potential insider threats.

---

## 2. Log Sources

| Log Source               | Description                                                           |
|-------------------------|-----------------------------------------------------------------------|
| **Access Request Logs**  | User access requests, approvals, and denials                         |
| **Provisioning Logs**    | Creation, modification, or removal of user accounts and entitlements |
| **Certification Logs**   | Access review and certification activities                           |
| **Policy Violation Logs**| Violations of governance policies (e.g., SoD conflicts)             |
| **Authentication Logs**  | User login and authentication attempts                              |
| **Audit Logs**           | Changes to SailPoint configuration, roles, and policies             |

---

## 3. Threat Hunting Categories 

### A. Access & Entitlement Anomalies

| Keyword/Field             | Description                                                           |
|--------------------------|-----------------------------------------------------------------------|
| `access_request`          | New access requests — monitor for unusual or excessive requests       |
| `provisioning_event`      | Account or entitlement creations/modifications                        |
| `access_denied`           | Denied access requests — possible unauthorized attempts               |
| `role_assignment`         | Role or group assignments — watch for high-risk roles                 |
| `entitlement_grant`       | Granting of sensitive entitlements                                    |

---

### B. Policy Violations & Segregation of Duties (SoD)

| Keyword/Field             | Description                                                           |
|--------------------------|-----------------------------------------------------------------------|
| `policy_violation`        | SoD violations or other policy breaches                              |
| `risk_score`              | Elevated risk scores on user or access                                |
| `certification_failure`   | Failed access review certifications                                  |

---

### C. Authentication & User Activity

| Keyword/Field             | Description                                                           |
|--------------------------|-----------------------------------------------------------------------|
| `login_success`           | Successful user authentications                                      |
| `login_failure`           | Failed authentication attempts — brute force indicator               |
| `unusual_login_time`      | Logins outside typical hours                                         |
| `multiple_failed_logins`  | Multiple failures indicating possible credential attacks             |

---

### D. Configuration & Governance Changes

| Keyword/Field             | Description                                                           |
|--------------------------|-----------------------------------------------------------------------|
| `policy_change`           | Modifications to governance policies                                |
| `role_change`             | Changes in role definitions or assignments                           |
| `admin_access`            | Elevated administrative activities                                  |

---

## 4. Additional Recommendations

1. Monitor unusual or excessive access requests and entitlement grants.  
2. Detect SoD policy violations and high-risk access certifications.  
3. Track failed authentication attempts and unusual login times.  
4. Audit configuration, role, and policy changes for suspicious activity.  
5. Investigate alerts related to risk score spikes or certification failures.  

---
