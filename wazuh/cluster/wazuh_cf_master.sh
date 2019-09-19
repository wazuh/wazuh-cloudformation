#!/bin/bash
# Install Wazuh master instance using Cloudformation template
# Support for Amazon Linux
touch /tmp/deploy.log
echo "Starting process." > /tmp/deploy.log

ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
wazuh_server_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhServerPort:' | cut -d' ' -f2)
wazuh_registration_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhRegistrationPort:' | cut -d' ' -f2)
wazuh_registration_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhRegistrationPassword:' | cut -d' ' -f2)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
wazuh_api_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiPort:' | cut -d' ' -f2)
wazuh_cluster_key=$(cat /tmp/wazuh_cf_settings | grep '^WazuhClusterKey:' | cut -d' ' -f2)
elb_elastic=$(cat /tmp/wazuh_cf_settings | grep '^ElbElasticDNS:' | cut -d' ' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet' | head -1 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f2)
splunk_username=$(cat /tmp/wazuh_cf_settings | grep '^SplunkUsername:' | cut -d' ' -f2)
splunk_password=$(cat /tmp/wazuh_cf_settings | grep '^SplunkPassword:' | cut -d' ' -f2)
splunk_ip=$(cat /tmp/wazuh_cf_settings | grep '^SplunkIP:' | cut -d' ' -f2)
WindowsPublicIp=$(cat /tmp/wazuh_cf_settings | grep '^WindowsPublicIp:' | cut -d' ' -f2)
VirusTotalKey=$(cat /tmp/wazuh_cf_settings | grep '^VirusTotalKey:' | cut -d' ' -f2)
AwsSecretKey=$(cat /tmp/wazuh_cf_settings | grep '^AwsSecretKey:' | cut -d' ' -f2)
AwsAccessKey=$(cat /tmp/wazuh_cf_settings | grep '^AwsAccessKey:' | cut -d' ' -f2)
SlackHook=$(cat /tmp/wazuh_cf_settings | grep '^SlackHook:' | cut -d' ' -f2)
EnvironmentType=$(cat /tmp/wazuh_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)
TAG='v3.10.0'

echo "Added env vars." >> /tmp/deploy.log

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Creating SSH user
adduser ${ssh_username}
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
systemctl restart sshd

echo "Created SSH user." >> /tmp/deploy.log

if [[ ${EnvironmentType} == 'staging' ]]
then
	# Adding Wazuh pre_release repository
	echo -e '[wazuh_pre_release]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh_pre.repo
elif [[ ${EnvironmentType} == 'production' ]]
then
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
elif [[ ${EnvironmentType} == 'devel' ]]
then
	echo -e '[wazuh_staging]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/staging/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh_staging.repo
else
	echo 'no repo' >> /tmp/stage
fi

# Configuring Elastic repository
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-${elastic_major_version}.x]
name=Elasticsearch repository for ${elastic_major_version}.x packages
baseurl=https://artifacts.elastic.co/packages/${elastic_major_version}.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Installing wazuh-manager
yum -y install wazuh-manager
chkconfig --add wazuh-manager
