#!/bin/bash
# Install Wazuh agent using Cloudformation template
# Support for Amazon Linux
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

# Adding Wazuh repository
curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_pre_release.list

# Install Wazuh agent
apt-get update
apt-get install curl apt-transport-https lsb-release -y


# Install Wazuh agent
apt-get update
apt-get install wazuh-agent -y

# Add registration password
echo "${wazuh_registration_password}" > /var/ossec/etc/authd.pass

# Register agent using authd
/var/ossec/bin/agent-auth -m ${master_ip} -A ubuntu-ag
sed -i 's:MANAGER_IP:'${elb_wazuh_dns}
# Enable and restart the Wazuh agent

systemctl enable wazuh-agent
systemctl restart wazuh-agent