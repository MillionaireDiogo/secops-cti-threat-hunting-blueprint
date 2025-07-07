# Google Workspace Threat Hunting Description

Proactive detection of malicious activity across Gmail, Drive, Admin, and user actions in Google Workspace to identify threats like phishing, data exfiltration, account compromise, and unauthorized access.

---

## Key Log Sources for Google Workspace Threat Hunting

- Gmail Log Events (Admin Audit Logs)
- Google Drive Audit Logs
- Admin Audit Logs  
- Captures changes to user accounts, roles, privileges, and critical administrative actions.
- Login and Security Logs  

---

## Google Workspace-Specific Threat Hunting Keywords 
### Gmail Log Actions (from Admin audit logs)

- **MESSAGE_SENT:** User sent an email message.
- **MESSAGE_MARKED_SPAM:** Email marked as spam by the user.
- **MESSAGE_REPORTED_PHISHING:** Email reported as a phishing attempt.
- **ATTACHMENT_DOWNLOADED:** Email attachment downloaded.
- **LINK_CLICKED:** Link within an email was clicked.
- **FILTER_CREATED:** Email filter/rule was created.
- **FILTER_CHANGED:** Email filter/rule was modified.

### Google Drive Threat Hunting Keywords

- **Public sharing:** File or folder shared publicly.
- **Anyone with the link:** File accessible by anyone possessing the link.
- **Shared outside domain:** File shared with users outside the organization’s domain.
- **Suspicious file name:** File named unusually or with suspicious patterns.
- **Unusual file download volume:** Higher than normal download activity.
- **Multiple file downloads:** Numerous files downloaded in a short period.
- **Unauthorized access:** Access by users without proper permissions.
- **Data exfiltration:** Potential large-scale data theft or leakage.
- **External collaborator added:** Non-domain user granted access.

### Drive Log Actions

- **create:** New file or folder created.
- **edit:** File or folder content modified.
- **delete:** File or folder removed.
- **move:** File or folder relocated within Drive.
- **add_to_folder:** File added to a folder.
- **permission_change:** Sharing or access permissions updated.
- **download:** File downloaded locally.
- **preview:** File previewed without download.
- **share:** File or folder shared with others.
- **copy:** File duplicated or copied.

### Google Admin Audit Logs Keywords

- **User suspended:** User account suspended.
- **Role assigned:** User assigned a new admin or custom role.
- **Super Admin privileges:** Super Admin rights granted or modified.
- **Login challenge:** Additional verification requested during login.
- **Failed login:** Unsuccessful login attempt.
- **Suspicious login:** Login attempt from an unusual location or device.
- **MFA bypass:** Multi-factor authentication was bypassed.
- **2-step verification disabled:** Two-step verification turned off.
- **Admin password reset:** Admin user password was reset.

### Admin Actions

- **UPDATE_USER:** User account details updated.
- **DELETE_USER:** User account deleted.
- **RESET_PASSWORD:** User password reset initiated.
- **UPDATE_APPLICATION:** Application settings or configurations updated.
- **SUSPEND_USER:** User account suspended.
- **GRANT_ROLE:** Role or privilege granted to a user.
- **CHANGE_RECOVERY_OPTIONS:** Account recovery options modified.
