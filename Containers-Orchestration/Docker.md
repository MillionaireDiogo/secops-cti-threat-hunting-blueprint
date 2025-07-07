# Docker Threat Hunting Overview

Docker threat hunting involves proactively detecting suspicious activity within containerized environments. Key focus areas include unauthorized container creation, privilege escalation, exposed Docker APIs, image tampering, and lateral movement via containers. Monitoring behavior patterns and access events helps identify potential exploitation or misconfigurations early.

## 📄 Key Log Source
- **Docker Daemon Logs**
  - Location: `/var/log/docker.log` (or via `journalctl -u docker.service`)
  - Contains information about container lifecycle events (start, stop, exec), API calls, errors, and daemon activity.

---

## Docker Threat Hunting Keywords & Descriptions

### Container Access & Privilege Escalation

| **Keyword / Command**       | **Short Description**                                                              |
|-----------------------------|-------------------------------------------------------------------------------------|
| `docker exec`               | Executes a command inside a running container.                                     |
| `docker exec -it`           | Interactive terminal access — potential for lateral movement.                      |
| `docker run --privileged`   | Starts container with full host privileges — major security risk.                  |
| `--cap-add=ALL`             | Grants all Linux capabilities — often unnecessary and dangerous.                   |
| `--device /dev`             | Provides access to host devices (e.g., disks, USB).                                |
| `--mount type=bind`         | Mounts host directories — may expose sensitive files.                              |
| `docker cp`                 | Copies files between host and container — possible data exfiltration.              |
| `nsenter`                   | Enters other namespaces — used to escape containers.                               |
| `chroot /mnt`               | Changes root directory — sandbox escape or filesystem pivot.                       |
| `mount -o bind`             | Re-mounts host paths — may expose host filesystem.                                 |
| `host PID namespace`        | Shares host process namespace — attacker can view/manipulate host processes.       |
| `privileged container`      | Indicates container with extended system access.                                   |

---

### Docker Daemon Abuse / Configuration

| **Keyword / Command**                  | **Short Description**                                                                      |
|----------------------------------------|---------------------------------------------------------------------------------------------|
| `dockerd -H tcp://0.0.0.0`             | Starts Docker API on a network-exposed socket — high risk if unsecured.                    |
| `exposed Docker API`                   | Generic term for unsecured API endpoints — abused for RCE.                                 |
| `unauthenticated access`               | Docker API accessed without auth — full control to attacker.                               |
| `remote Docker socket`                 | TCP/IP Docker API — increases attack surface vs local Unix socket.                         |
| `tcp://localhost:2375`                 | Default unauthenticated Docker socket — should be disabled.                                |
| `unix:///var/run/docker.sock`          | Unix socket used to manage Docker — frequent post-exploitation target.                     |
| `curl --unix-socket /var/run/docker.sock` | Curl-based Docker API access — often used by attackers.                               |

---

### Suspicious Process Execution Inside Containers

| **Keyword / Command**                  | **Short Description**                                                                      |
|----------------------------------------|---------------------------------------------------------------------------------------------|
| `curl`, `wget`, `bash`, `nc`, `nmap`   | Common tools for downloading payloads or lateral movement.                                 |
| `base64 -d`, `echo <payload> | base64` | Obfuscation and decoding of malicious scripts.                                              |
| `chmod +x`, `./reverse.sh`, `./shell`  | Execution of potential reverse shells or malware.                                           |
| `socat TCP`, `reverse shell`           | Reverse shell commands — used for remote access.                                            |
| `crontab`, `at`, `systemd`             | Persistence mechanisms in containers or host.                                               |
| `sh -i`, `/bin/bash -c`, `/dev/tcp/`   | Shell spawning methods — often seen in exploitation.                                        |
| `apk add`, `apt-get install`, `yum install` | Installation of tools inside running container — potential compromise.                  |

---

### Image Manipulation / Backdooring

| **Keyword / Command**                 | **Short Description**                                                                       |
|---------------------------------------|----------------------------------------------------------------------------------------------|
| `docker commit`                       | Saves current container state — could include malicious changes.                            |
| `docker build`                        | Builds image from Dockerfile — monitor for risky commands.                                  |
| `docker tag`                          | Renames/tags image — may disguise malicious image.                                          |
| `docker push`                         | Uploads image — could exfiltrate backdoored containers.                                     |
| `custom image with malware`           | Backdoored containers disguised as legitimate base images.                                  |
| `alpine`, `busybox`                   | Minimal images — often used for size or obfuscation.                                        |
| `Dockerfile with ADD`, `RUN curl`, `COPY` | Dangerous instructions — may download and run remote code.                             |

---

### Lateral Movement & Persistence

| **Keyword / Command**                 | **Short Description**                                                                       |
|---------------------------------------|----------------------------------------------------------------------------------------------|
| `docker network connect`              | Adds container to networks — potential lateral movement.                                    |
| `port forwarding`                     | Exposes internal services — monitor for risky ports.                                        |
| `bridge mode misused`                 | Common default — may enable unintended network access.                                      |
| `bind to 0.0.0.0`                     | Makes container service accessible to all interfaces — high risk.                           |
| `new container from unknown image`    | Use of unverified or malicious images — often backdoored.                                   |
| `systemd service using Docker`        | Non-standard Docker usage in system services — possible persistence method.                 |
| `volume mount to /etc/, /root/, /var/run/...` | Mounting sensitive host dirs — used to access or alter host data.                    |

---

### Defense Evasion & Anti-Forensics

| **Keyword / Command**                | **Short Description**                                                                       |
|--------------------------------------|----------------------------------------------------------------------------------------------|
| `rm -rf /var/log`                    | Deletes logs — strong indicator of cleanup by attacker.                                     |
| `history -c`                         | Clears shell command history — evasion tactic.                                               |
| `unset HISTFILE`                     | Disables shell history logging — anti-forensics method.                                     |
| `nohup` or `& disown`                | Detaches background processes — persistence or evasion.                                     |
| `containerd-shim anomalies`          | Unusual behavior or restarts — may signal tampering.                                        |
| `temporary containers removed quickly` | Fast container spin-up/down — often used in smash-and-grab attacks.                       |

---

