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
EnvironmentType=$(cat /tmp/wazuh_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)
manager_config='/var/ossec/etc/ossec.conf'

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Installing dependencies
apt-get install curl apt-transport-https lsb-release -y
echo "Installed dependencies." > /tmp/log

# Add SSH user
useradd ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd

if [ ! -f /usr/bin/python ]; then ln -s /usr/bin/python3 /usr/bin/python; fi

# Adding Wazuh repository
if [[ ${EnvironmentType} == 'staging' ]]
then
    curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_pre_release.list
elif [[ ${EnvironmentType} == 'production' ]]
then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
elif [[ ${EnvironmentType} == 'devel' ]]
then
    curl -s https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/apt/ unstable main" | tee -a /etc/apt/sources.list.d/wazuh_staging.list
else
	echo 'no repo' >> /tmp/stage
fi

# Install Wazuh agent
apt-get update

# Install Wazuh agent
apt-get install wazuh-agent -y
echo "Installed Wazuh agent." > /tmp/log

# Add registration password
echo "${wazuh_registration_password}" > /var/ossec/etc/authd.pass
echo "Set registration password." > /tmp/log
echo "Registering agent..." > /tmp/log

# Register agent using authd
/var/ossec/bin/agent-auth -m ${master_ip} -A Debian < /tmp/log
echo "Agent registered." > /tmp/log

sed -i 's:MANAGER_IP:'${elb_wazuh_dns}':g' /var/ossec/etc/ossec.conf
sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}

# Enable and restart the Wazuh agent

systemctl enable wazuh-agent
systemctl restart wazuh-agent
echo "Agent restarted." > /tmp/log
