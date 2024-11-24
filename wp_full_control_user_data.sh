#!/bin/bash
# Install Git
sudo yum install -y git

# Clone the GitHub repository
git clone https://github.com/Tradandan/cndan.git /home/ec2-user/cndan

# Navigate to the repository
cd /home/ec2-user/cndan

# Ensure the script is executable
chmod +x wp-full-control.sh.x

# Run the wp-full-control.sh.x script
./wp-full-control.sh.x
