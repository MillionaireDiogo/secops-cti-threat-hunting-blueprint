# WordPress Threat Hunting Overview

Threat hunting in WordPress environments focuses on identifying signs of brute force login attempts, plugin or theme vulnerabilities, web shell behavior, and exploitation of core features like XML-RPC, admin-ajax, and the REST API. By monitoring specific URL patterns, function calls, and suspicious parameters, defenders can detect early indicators of compromise and lateral movement in WordPress-based websites.

---

## Log Sources
- Web Server Logs (Apache/Nginx)  
- PHP Error Logs	  
- WordPress Logs (if logging plugin enabled)  
- Database Logs (MySQL)	 

---

## WordPress-Specific Threat Hunting Keywords (Grouped)

### 1. Login & Brute Force Indicators

| **Keyword**                         | **Context**                              |
|-------------------------------------|------------------------------------------|
| `/wp-login.php`                     | Login page access                        |
| `/xmlrpc.php`                       | Brute force / pingback abuse             |
| `login_failed`                      | Failed login attempts                    |
| `admin`                             | Targeted username enumeration            |
| `author=`                           | Author ID enumeration                    |
| `wp-login.php?action=lostpassword`  | Password reset abuse                     |

---

### 2. Plugin & Theme Exploits

| **Keyword**                         | **Context**                              |
|-------------------------------------|------------------------------------------|
| `/wp-content/plugins/`             | Plugin enumeration or exploitation       |
| `/wp-content/themes/`              | Theme enumeration or LFI attempts        |
| `revslider` / `wp-file-manager`    | Known vulnerable plugin names            |
| `file_upload` / `file_put_contents`| RCE / Upload indicators                  |
| `shell.php` / `cmd.php`            | Common webshell names                    |
| `.php?` in GET requests            | Remote PHP execution attempts            |

---

### 3. Post Exploitation / Web Shell Behavior

| **Keyword**                         | **Context**                              |
|-------------------------------------|------------------------------------------|
| `base64_decode`                    | Often used in obfuscated malware         |
| `eval(`                           | Code execution, commonly abused          |
| `assert(` / `system(` / `exec(`    | Command execution in injected code       |
| `wp-admin/` + unusual params       | Admin abuse or plugin config changes     |

---

### 4. SQL Injection / XSS

| **Keyword**                         | **Context**                              |
|-------------------------------------|------------------------------------------|
| `UNION SELECT`                     | SQL injection                            |
| `OR 1=1`                           | Basic SQLi test                          |
| `<script>` / `javascript:`         | XSS attempt                              |
| `%3Cscript%3E`                     | Encoded XSS                              |

---

### 5. WordPress Core Abuse

| **Keyword**                         | **Context**                              |
|-------------------------------------|------------------------------------------|
| `/wp-cron.php`                     | Used in some attack chains (e.g., auto-post spam) |
| `wp_ajax` / `admin-ajax.php`       | Used for DoS, injection, plugin abuse    |
| `wp-json` / REST API abuse         | Enumeration or exploitation              |


## Notable WordPress Breaches from Plugin or Theme Exploits
| Breach Case              | Vulnerability Type                          | Affected Component                | Impact                                                    | Source                                                                                                                |
|--------------------------|---------------------------------------------|-----------------------------------|------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| **Mossack Fonseca**      | Unauthenticated file upload (RevSlider)    | RevSlider plugin ≤3.0.95          | Shell upload → 2.6 TB data leak (Panama Papers)            | [Wordfence](https://www.wordfence.com/blog/2016/04/mossack-fonseca-breach-vulnerable-slider-revolution/)             |
| **AccessPress Backdoor** | Supply-chain backdoor injection             | 93 themes & plugins               | Mass site infection, malware redirection                   | [BleepingComputer](https://www.bleepingcomputer.com/news/security/over-90-wordpress-themes-plugins-backdoored-in-supply-chain-attack/) |
| **GiveWP RCE (CVE‑2025‑0912)** | PHP object deserialization (unauth) | GiveWP Donation Plugin <3.20.0    | RCE → server takeover, financial/campaign data exposure    | [Reddit (r/netsec)](https://www.reddit.com/r/netsec/comments/ez6oon/)                                                 |
