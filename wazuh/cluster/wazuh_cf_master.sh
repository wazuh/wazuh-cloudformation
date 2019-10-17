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
elastic_ip=$(cat /tmp/wazuh_cf_settings | grep '^ElasticIp:' | cut -d' ' -f2)
TAG='v3.10.2'

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

# Configuring Filebeat-oss repository
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-oss-${elastic_version}-x86_64.rpm
rpm -vi filebeat-oss-${elastic_version}-x86_64.rpm

# Installing wazuh-manager
yum -y install wazuh-manager
chkconfig --add wazuh-manager

# Configuring Filebeat
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
elastic_minor_version=$(echo ${elastic_version} | cut -d'.' -f2)
elastic_patch_version=$(echo ${elastic_version} | cut -d'.' -f3)

# Install Filebeat module
curl -s "https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz" | tar -xvz -C /usr/share/filebeat/module

# Get Filebeat configuration file
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/${TAG}/extensions/filebeat/7.x/filebeat.yml

# Elasticsearch template
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/${TAG}/extensions/elasticsearch/7.x/wazuh-template.json

# File permissions
chmod go-w /etc/filebeat/filebeat.yml
chmod go-w /etc/filebeat/wazuh-template.json

# Point to Elasticsearch cluster
sed -i "s|'http://YOUR_ELASTIC_SERVER_IP:9200'|'$elastic_ip'|" /etc/filebeat/filebeat.yml

systemctl restart filebeat