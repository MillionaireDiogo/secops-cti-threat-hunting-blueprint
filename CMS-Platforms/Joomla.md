# Joomla Threat Hunting Overview

Joomla threat hunting is the proactive search for malicious activity and vulnerabilities in Joomla websites. It focuses on detecting suspicious logins, exploitation of vulnerable extensions, web shells, SQL injections, and other attack indicators to prevent breaches and protect site integrity.

## Log Sources
- Web Server Logs (Apache/Nginx)  
- PHP Error Logs	  
- WordPress Logs (if logging plugin enabled)  
- Database Logs (MySQL)	


## 🛡️ Joomla Threat Hunting Keywords (by Category)

### 1. Login & Authentication Abuse

| **Keyword**                     | **Description**                                |
|-------------------------------|------------------------------------------------|
| `/administrator/index.php`    | Admin login panel                              |
| `task=login`                  | Admin login attempt (POST)                     |
| `task=logout`                 | Sudden logout (session hijack possible)       |
| `task=registration`          | Abuse of user registration                    |
| `option=com_users`           | User controller activity                      |
| `login_failed` / `invalid token` | Failed logins or CSRF attempt             |

---

### 2. Extension / Component Exploits

| **Keyword**                          | **Description**                                 |
|-------------------------------------|-------------------------------------------------|
| `option=com_`                       | Joomla component access                         |
| `com_joomlaupdate`                  | Exploit or manipulation of update process       |
| `com_rsform`                        | RCE-prone component in older versions           |
| `com_fabrik`                        | Known for SQLi vulnerabilities                  |
| `com_jce`                           | Popular editor—often targeted                   |
| `task=upload`                       | File upload (RCE risk)                          |
| `index.php?option=com_ + .php`      | Remote file inclusion attempt                   |
| `.php?cmd=` / `?shell=`             | Shell execution attempts                        |

---

### 3. Indicators of Web Shells or RCE

| **Keyword**                 | **Description**                                 |
|----------------------------|--------------------------------------------------|
| `eval(`                    | Obfuscated/malicious PHP execution               |
| `base64_decode(`           | Often used in malware                           |
| `system(` / `exec(`        | Command execution                               |
| `tmp/sess_` or `/cache/`   | Unusual script execution from temp dirs         |
| `.php with POST method`    | Suspicious file upload/interaction               |

---

### 4. SQL Injection / XSS Indicators

| **Keyword**                 | **Description**                                  |
|----------------------------|--------------------------------------------------|
| `UNION SELECT`             | SQL injection                                   |
| `OR 1=1`                   | Basic SQLi test                                 |
| `<script>` / `javascript:` | XSS attempts                                    |
| `%3Cscript%3E`             | Encoded XSS                                     |
| `order by` in GET params   | SQLi trick to discover table layout             |

---

### 5. Post-Exploitation / Persistence

| **Keyword**                 | **Description**                                  |
|----------------------------|--------------------------------------------------|
| `define('_JEXEC'`          | Modified entry point of Joomla files             |
| `.user.ini` or `.htaccess` | Hidden backdoors or privilege hacks              |
| `new superuser or user added` | Check logs for privilege escalation          |

---

## 🔥 Bonus: High-Risk Components to Watch

| **Component**           | **Known Risk Type**              |
|-------------------------|----------------------------------|
| `com_jce`               | File upload to RCE               |
| `com_rsform`            | Arbitrary file write             |
| `com_fabrik`            | SQL Injection                    |
| `com_joomlaupdate`      | Update tampering                 |
| `com_contenthistory`    | Info leak + RCE                  |

---

## Joomla Security Breaches Summary

| **Incident**                  | **Issue**                                                        | **Impact**                                                                                  | **Source(s)**                        |
|-------------------------------|-----------------------------------------------------------------|---------------------------------------------------------------------------------------------|------------------------------------|
| 2020 JRD Data Leak            | Unencrypted AWS S3 backup of resources.joomla.org exposed by third party | ~2,700 user records leaked (names, encrypted passwords); password resets recommended       | community.joomla.org, reddit.com    |
| 2019–2020 KashmirBlack Botnet | Exploited outdated Joomla components via RCE, file uploads, SQLi | Large-scale site compromises, crypto-mining, web shell implants                            | medium.com, reddit.com              |
| 2015 SQL Injection (CVE series) | SQLi flaws in Joomla 3.2–3.4.4 allowed arbitrary DB access       | Admin account creation, data theft, manipulation; patched in Joomla 3.4.5                  | thehackernews.com, securityweek.com|
| 2014–2015 Multiple CVEs       | XSS, CSRF, RCE, and privilege escalation via insecure input and file handling | Full site compromise possible: defacement, account hijack, shell upload                   | medium.com, securityweek.com       |

