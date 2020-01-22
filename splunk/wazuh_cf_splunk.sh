#!/bin/bash
# Install Splunk using Cloudformation template
# Support for Splunk

ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
splunk_port="8000"
splunk_username=$(cat /tmp/wazuh_cf_settings | grep '^SplunkUsername:' | cut -d' ' -f2)
splunk_password=$(cat /tmp/wazuh_cf_settings | grep '^SplunkPassword:' | cut -d' ' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2  | cut -d' ' -f1)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
wazuh_api_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiPort:' | cut -d' ' -f2)
TAG="v3.11.2"
APP_TAG="v3.11.2-7.3.4"
# Creating SSH user
adduser ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd

# Install net-tools, wget, git
yum install net-tools wget git curl -y -q

# download splunk
wget -O splunk-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=7.2.3&product=splunk&filename=splunk-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm&wget=true' &> /dev/null

# install splunk
yum install splunk-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm -y &> /dev/null

# add admin user
echo "[user_info]" > /opt/splunk/etc/system/local/user-seed.conf
echo "USERNAME = $splunk_username" >> /opt/splunk/etc/system/local/user-seed.conf
echo "PASSWORD = $splunk_password" >> /opt/splunk/etc/system/local/user-seed.conf

# fetching configuration files
curl -so /opt/splunk/etc/system/local/inputs.conf https://raw.githubusercontent.com/wazuh/wazuh/${TAG}/extensions/splunk/peer-inputs.conf &> /dev/null
curl -so /opt/splunk/etc/system/local/indexes.conf https://raw.githubusercontent.com/wazuh/wazuh/${TAG}/extensions/splunk/peer-indexes.conf &> /dev/null

# clone app
git clone -b $APP_TAG --single-branch git://github.com/wazuh/wazuh-splunk.git &> /dev/null

# install app
cp -R ./wazuh-splunk/SplunkAppForWazuh/ /opt/splunk/etc/apps/

# restart splunk
/opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt &> /dev/null

# curl -XPOST http://${eth0_ip}:${splunk_port}/custom/SplunkAppForWazuh/manager/add_api?url=${wazuh_master_ip}&portapi=${wazuh_api_port}&userapi=${wazuh_api_user}&passapi=${wazuh_api_password}