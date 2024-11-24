# User Data Script for wp-full-control.sh.x

This README explains how to use the provided user data script to automate the full local setup of WordPress and phpMyAdmin on an EC2 instance.

## Script Overview
The script will:
1. Install Git on the EC2 instance.
2. Clone the GitHub repository containing the `wp-full-control.sh.x` script.
3. Make the script executable.
4. Execute the script to set up WordPress with a self-hosted MySQL database and phpMyAdmin.

## How to Use
1. **Copy the User Data Script**:
   - Copy the content of the `wp_full_control_user_data.sh` script.

2. **Launch an EC2 Instance**:
   - Go to the AWS Management Console.
   - Click **Launch Instance** and select an AMI (e.g., Amazon Linux 2).
   - Configure instance details and scroll down to **Advanced Details**.
   - Paste the user data script into the **User Data** field.

3. **Set Up Security Groups**:
   - Ensure the security group allows HTTP (port 80) and HTTPS (port 443).

4. **Launch and Verify**:
   - Start the instance and check the logs in **Monitor and Troubleshoot** > **Get System Log**.
   - Access WordPress and phpMyAdmin via the instance's public IP.

5. **Optional Cleanup**:
   - If needed, remove the repository and any sensitive files:
     ```bash
     rm -rf /home/ec2-user/cndan
     ```

---

## Notes
- This script sets up a local MySQL database and phpMyAdmin for WordPress.
- Ideal for testing and development purposes.

