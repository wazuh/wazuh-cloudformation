#!/bin/bash
# Install Wazuh agent using Cloudformation template
# Support for Debian/Ubuntu
touch /tmp/log
echo "Starting process." > /tmp/log
agent_name=$(cat /tmp/wazuh_cf_settings | grep '^agent_name:' | cut -d' ' -f2)
ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
elb_wazuh_dns=$(cat /tmp/wazuh_cf_settings | grep '^ElbWazuhDNS:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
wazuh_registration_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhRegistrationPassword:' | cut -d' ' -f2)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
manager_config='/var/ossec/etc/ossec.conf'
# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Add SSH user
adduser ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
service sshd restart

# Adding Wazuh repository
curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_pre_release.list
# Install Wazuh agent
apt-get update
apt-get install curl apt-transport-https lsb-release -y
echo "Installed dependencies." > /tmp/log

# Install Wazuh agent
apt-get install wazuh-agent -y
echo "Installed Wazuh agent." > /tmp/log

# Add registration password
echo "${wazuh_registration_password}" > /var/ossec/etc/authd.pass
echo "Set registration password." > /tmp/log
echo "Registering agent..." > /tmp/log

# Setting Wazuh NLB DNS name
sed -i 's:MANAGER_IP:'${elb_wazuh_dns}':g' ${manager_config}

# Change manager protocol to tcp, to be used by Amazon ELB
sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}

# Register agent using authd
/var/ossec/bin/agent-auth -m ${master_ip} -A Ubuntu < /tmp/log
echo "Agent registered." > /tmp/log

# Enable and restart the Wazuh agent
systemctl enable wazuh-agent
systemctl restart wazuh-agent
echo "Agent restarted." > /tmp/log
