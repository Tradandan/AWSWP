#!/bin/bash
# Install Git
sudo yum install -y git

# Clone the GitHub repository
git clone https://github.com/Tradandan/cndan.git /home/ec2-user/cndan

# Navigate to the repository
cd /home/ec2-user/cndan

# Ensure the script is executable
chmod +x wp-rds.sh.x

# Run the wp-rds.sh.x script
./wp-rds.sh.x
