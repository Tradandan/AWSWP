# Security Policy

## Disclaimer of Responsibility

This project is provided "as is," and the responsibility for ensuring security lies with the **end user**. The maintainers of this project are not liable for any vulnerabilities, misuse, or damages arising from its use.

By using this project, you acknowledge and agree that:
- It is your responsibility to verify the security of this project in your environment.
- The maintainers are not responsible for addressing or resolving vulnerabilities.

---

## User Responsibilities

As a user, you are responsible for:
1. **Securing Your Environment**:
   - Ensure your systems, network, and configurations are secure.
   - Follow industry best practices for deploying and maintaining software.

2. **Monitoring Dependencies**:
   - Regularly review the dependencies used in this project for known vulnerabilities.
   - Update to the latest versions where applicable.

3. **Identifying and Reporting Issues**:
   - If you discover a potential issue, you may report it by opening a GitHub issue or discussing it with the community.
   - The responsibility for fixing vulnerabilities lies with the community or your own team.

4. **Understanding and Applying Patches**:
   - Apply patches or updates provided by the GitHub community or your team.
   - Regularly monitor the repository for updates.

---

## Reporting a Vulnerability

If you wish to report a vulnerability:
- Open an issue on the repository and describe the concern.
- Avoid sharing sensitive information publicly.
- The resolution of the vulnerability will rely on contributions from the GitHub community.

---

## Security Guidance for Users

- Use the project at your own risk.
- Test the project thoroughly in your environment before deploying it to production.
- Follow secure coding and deployment practices.

For guidance, refer to resources such as the [OWASP website](https://owasp.org/) or GitHub's [Security Best Practices](https://docs.github.com/en/code-security).

---

## Acknowledgments

We thank the community for their contributions and collaboration to improve this project. The security and reliability of the project depend on collective efforts.

# Security Advisory: Potential Misconfiguration Vulnerability in WordPress Automation Scripts

## Summary
A potential vulnerability has been identified in the WordPress automation scripts (`wp-full-control.sh.x`, `wp-rds.sh.x`, and `uni.sh.x`). Improper handling of sensitive configurations, such as database credentials or permissions, may expose systems to unauthorized access or data leaks.

This advisory applies to all versions of the scripts currently available in the repository. Users are strongly advised to review and secure their deployments.

---

## Affected Versions
The following scripts and versions are affected:
- `wp-full-control.sh.x`: All versions
- `wp-rds.sh.x`: All versions
- `uni.sh.x`: All versions

---

## Severity
**High**

---

## Impact
1. **Misconfigured Database Credentials**: If default credentials are left unchanged, attackers may gain access to your database.
2. **Improper File Permissions**: Inadequately secured files (e.g., `wp-config.php`) may allow unauthorized access to sensitive information.
3. **Publicly Accessible Scripts**: If the scripts are exposed on a publicly accessible server, attackers may manipulate or exploit them.

---

## Resolution
We recommend users take the following actions to mitigate potential risks:

### Update to Secure Credentials
1. Change all default database credentials to strong, unique passwords.
2. Use the included additional script to securely update database credentials post-installation.

### Secure File Permissions
1. Ensure the WordPress configuration file (`wp-config.php`) is restricted to the web server:
   ```bash
   sudo chmod 600 /var/www/html/wp-config.php
   ```
2. Remove or restrict access to unnecessary files or directories.

### Secure Access to the Scripts
1. Do not expose `.sh.x` files in publicly accessible directories.
2. Use server-level access controls (e.g., firewalls, IP restrictions).

---

## Mitigation
If you are unable to apply the recommended resolution immediately:
- Restrict access to the EC2 instance running the scripts using Security Groups.
- Remove or rename any unnecessary files that could expose sensitive information.
- Regularly monitor logs for unauthorized access attempts.

---

## Technical Details
The issue arises from:
- Use of default credentials during WordPress setup.
- Publicly accessible automation scripts without proper access control.
- Insecure file and folder permissions after script execution.

Attackers could exploit these weaknesses by:
1. Guessing or accessing default credentials to compromise the database.
2. Accessing sensitive configuration files if file permissions are not set correctly.
3. Running exposed scripts to manipulate server configurations.

---

## References
- GitHub Repository: [https://github.com/Tradandan/cndan](https://github.com/Tradandan/cndan)
- OWASP Security Guidelines: [https://owasp.org](https://owasp.org)

---

## Acknowledgments
We appreciate the GitHub community for their collaboration in identifying and addressing security issues.


# Security Tips for WordPress Automation Project

This document outlines advanced security recommendations for securing your WordPress automation project, scripts, and infrastructure.

---

## **1. Secure the Server Environment**

### Restrict SSH Access
- Disable password-based login and use SSH keys for authentication.
- Limit SSH access to specific trusted IP addresses using Security Groups or firewall rules.
- Change the default SSH port to a non-standard port.

### Apply Principle of Least Privilege
- Use a non-root user for routine operations. Grant administrative privileges only when necessary.

### Firewall Configuration
- Restrict access to HTTP (port 80), HTTPS (port 443), and SSH (custom port). Block all other incoming connections.

### Disable Unnecessary Services
- Stop and disable unused services to reduce the attack surface.

### Enable Regular Updates
- Automate updates for the server and installed packages.

---

## **2. Strengthen WordPress Security**

### Restrict Access to Sensitive Files
- Restrict access to critical files like `wp-config.php`.
- Use file permissions: `chmod 600` and `chown apache:apache`.

### Move `wp-config.php` Out of the Root Directory
- Move `wp-config.php` one directory above the root directory.

### Use Strong Salts and Keys
- Replace default keys and salts in `wp-config.php` with unique, strong values from [WordPress Secret Key Generator](https://api.wordpress.org/secret-key/1.1/salt/).

### Limit Plugin and Theme Installations
- Install only plugins and themes from trusted sources.

### Disable Directory Browsing
- Prevent attackers from listing directory contents by adding this to `.htaccess`:
  ```
  Options -Indexes
  ```

---

## **3. Database Security**

### Use Strong Database Passwords
- Always use a strong, randomly generated password for the database user.

### Restrict Database Access
- Allow database access only from the WordPress server.

### Remove Default MySQL Accounts
- Remove unnecessary default accounts in MySQL.

### Regular Database Backups
- Automate daily backups using `mysqldump` or WordPress plugins.

### Enable Database Encryption
- For RDS, enable encryption at rest and SSL/TLS connections for data in transit.

---

## **4. Protect Automation Scripts**

### Encrypt the Scripts
- Use tools like `shc` to obfuscate shell scripts.

### Restrict Execution Permissions
- Ensure only authorized users can execute your scripts: `chmod 700`.

### Validate Inputs
- Sanitize and validate user-provided inputs.

### Log Script Activity
- Maintain logs of script activity for debugging and monitoring.

---

## **5. Monitor and Detect Threats**

### Enable Logging
- Configure logging for Apache, MySQL, and scripts.

### Install Intrusion Detection System (IDS)
- Use tools like `Fail2Ban` or `OSSEC` to detect and block suspicious activity.

### Monitor File Changes
- Use `Tripwire` to monitor for unauthorized file changes.

### Use Web Application Firewall (WAF)
- Deploy a WAF (e.g., AWS WAF or Cloudflare) to protect against web vulnerabilities.

---

## **6. Encrypt Data in Transit**

### Install SSL/TLS Certificates
- Use `Let’s Encrypt` to enable HTTPS.

### Force HTTPS
- Redirect all traffic to HTTPS by updating your `.htaccess` file.

---

## **7. Advanced AWS-Specific Security**

### Enable IAM Roles
- Use IAM roles for EC2 instances to securely access AWS services.

### Encrypt RDS and EBS
- Enable encryption for RDS instances and EBS volumes.

### Use CloudTrail and GuardDuty
- Enable CloudTrail to log API calls and GuardDuty to detect potential threats.

### Use Security Groups and NACLs
- Define strict inbound and outbound rules for both Security Groups and Network ACLs.

### Enable Auto-Recovery
- Use EC2 Auto-Recovery to reboot the instance automatically in case of failure.

---

## **8. Educate and Train Users**

### Avoid Hardcoding Secrets
- Store sensitive credentials in environment variables or AWS Secrets Manager.

### Regularly Audit Security
- Conduct regular security audits of scripts, configurations, and infrastructure.

### Educate Users
- Train users to follow best practices, such as using strong passwords and avoiding shared credentials.

---

These measures, when implemented, can significantly enhance the security of your WordPress automation project and its infrastructure.

v
