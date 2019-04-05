#!/bin/bash
# Install Wazuh master instance using Cloudformation template
# Support for Amazon Linux
touch /tmp/log
echo "Starting process." > /tmp/log

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
elb_logstash=$(cat /tmp/wazuh_cf_settings | grep '^ElbLogstashDNS:' | cut -d' ' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet' | head -1 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f2)
splunk_username=$(cat /tmp/wazuh_cf_settings | grep '^KibanaUsername:' | cut -d' ' -f2)
splunk_password=$(cat /tmp/wazuh_cf_settings | grep '^KibanaPassword:' | cut -d' ' -f2)
splunk_ip=$(cat /tmp/wazuh_cf_settings | grep '^SplunkIP:' | cut -d' ' -f2)
WindowsPublicIp=$(cat /tmp/wazuh_cf_settings | grep '^WindowsPublicIp:' | cut -d' ' -f2)

echo "Added env vars." >> /tmp/log

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
service sshd restart

echo "Created SSH user." >> /tmp/log

# Adding Wazuh repository
echo -e '[wazuh_pre_release]\ngpgcheck=1\ngpgkey=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/pre-release/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh_pre.repo
# Configuring Elastic repository
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
cat > /etc/yum.repos.d/elastic.repo << EOF
[elasticsearch-6.x]
name=Elasticsearch repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Installing wazuh-manager
yum -y install wazuh-manager
chkconfig --add wazuh-manager
manager_config="/var/ossec/etc/ossec.conf"

# Enable registration service (only for master node)
/var/ossec/bin/ossec-control enable auth

### Use case 1: IP reputation

wget https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset
wget https://wazuh.com/resources/iplist-to-cdblist.py -O /var/ossec/etc/lists/iplist-to-cdblist.py
# Add Windows public IP to the list
echo ${WindowsPublicIp} >> /var/ossec/etc/lists/alienvault_reputation.ipset
python iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault

# Delete ipset and python script
rm -rf /var/ossec/etc/lists/alienvault_reputation.ipset
rm -rf /var/ossec/etc/lists/iplist-to-cdblist.py

echo "Updated CDB list ,added Windows agent IP." >> /tmp/log

# Change manager protocol to tcp, to be used by Amazon ELB
sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}

# Set manager port for agent communications
sed -i "s/<port>1514<\/port>/<port>${wazuh_server_port}<\/port>/" ${manager_config}

# Configuring registration service 
sed -i '/<auth>/,/<\/auth>/d' ${manager_config}

cat >> ${manager_config} << EOF
<ossec_config>
  <auth>
    <disabled>no</disabled>
    <port>${wazuh_registration_port}</port>
    <use_source_ip>no</use_source_ip>
    <force_insert>yes</force_insert>
    <force_time>0</force_time>
    <purge>yes</purge>
    <use_password>yes</use_password>
    <limit_maxagents>yes</limit_maxagents>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <!-- <ssl_agent_ca></ssl_agent_ca> -->
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>
</ossec_config>
EOF

# Setting password for agents registration
echo "${wazuh_registration_password}" > /var/ossec/etc/authd.pass
echo "Set registration password." > /tmp/log

# Installing Python Cryptography module for the cluster
pip install cryptography

# Configuring cluster section
sed -i '/<cluster>/,/<\/cluster>/d' ${manager_config}

cat >> ${manager_config} << EOF
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>wazuh-master</node_name>
    <node_type>master</node_type>
    <key>${wazuh_cluster_key}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>${eth0_ip}</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
</ossec_config>
EOF

# Disabling agent components and cleaning configuration file
sed -i '/<rootcheck>/,/<\/rootcheck>/d' ${manager_config}
sed -i '/<wodle name="open-scap">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="cis-cat">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="osquery">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="syscollector">/,/<\/wodle>/d' ${manager_config}
sed -i '/<syscheck>/,/<\/syscheck>/d' ${manager_config}
sed -i '/<localfile>/,/<\/localfile>/d' ${manager_config}
sed -i '/<!--.*-->/d' ${manager_config}
sed -i '/<!--/,/-->/d' ${manager_config}
sed -i '/^$/d' ${manager_config}

# Restart wazuh-manager
service wazuh-manager restart
echo "Restarted Wazuh manager." >> /tmp/log

# Installing NodeJS
curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
yum -y install nodejs
echo "Installed NODEJS." >> /tmp/log

# Installing wazuh-api
yum -y install wazuh-api
chkconfig --add wazuh-api
echo "Installed Wazuh API." >> /tmp/log

# Configuring Wazuh API user and password
cd /var/ossec/api/configuration/auth
node htpasswd -b -c user ${wazuh_api_user} ${wazuh_api_password}

# Enable Wazuh API SSL and configure listening port
api_ssl_dir="/var/ossec/api/configuration/ssl"
openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
sed -i "s/config.https = \"no\";/config.https = \"yes\";/" /var/ossec/api/configuration/config.js
sed -i "s/config.port = \"55000\";/config.port = \"${wazuh_api_port}\";/" /var/ossec/api/configuration/config.js
echo "Setting port and SSL to Wazuh API." >> /tmp/log

# Restart wazuh-api
service wazuh-api restart
echo "Restarted Wazuh API." >> /tmp/log

# Installing Filebeat
yum -y install filebeat-${elastic_version}
chkconfig --add filebeat
echo "Installed Filebeat." >> /tmp/log

# Configuring Filebeat
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/3.9/extensions/filebeat/filebeat.yml
sed -i "s/YOUR_ELASTIC_SERVER_IP/${elb_logstash}/" /etc/filebeat/filebeat.yml
service filebeat restart
echo "Restarted Filebeat." >> /tmp/log

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo

# Setting up Splunk Forwarder
yum -y install wget
# download splunkforwarder
echo 'Downloading Splunk Forwarder...'
wget -O splunkforwarder-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=7.2.3&product=universalforwarder&filename=splunkforwarder-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm&wget=true' &> /dev/null

# install splunkforwarder
echo 'Installing Splunk Forwarder...'
yum install splunkforwarder-7.2.3-06d57c595b80-linux-2.6-x86_64.rpm -y -q &> /dev/null

echo "Setting up Splunk forwarder..."
# props.conf
curl -so /opt/splunkforwarder/etc/system/local/props.conf https://raw.githubusercontent.com/wazuh/wazuh/3.9/extensions/splunk/props.conf

# inputs.conf
curl -so /opt/splunkforwarder/etc/system/local/inputs.conf https://raw.githubusercontent.com/wazuh/wazuh/3.9/extensions/splunk/inputs.conf

# set hostname
sed -i "s:MANAGER_HOSTNAME:$(hostname):g" /opt/splunkforwarder/etc/system/local/inputs.conf

touch /opt/splunkforwarder/etc/system/local/user-seed.conf

# create credential file
touch /opt/splunk/etc/system/local/user-seed.conf

# add admin user
cat > /opt/splunk/etc/system/local/user-seed.conf <<\EOF
[user_info]
USERNAME = ${splunk_username}
PASSWORD = ${splunk_password}
EOF

echo "Starting Splunk..."
# accept license
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --auto-ports --no-prompt &> /dev/null

# forward to index
/opt/splunkforwarder/bin/splunk add forward-server ${splunk_ip}:9997 -auth admin:changeme &> /dev/null

# restart service
/opt/splunkforwarder/bin/splunk restart &> /dev/null
echo "Done with Splunk." >> /tmp/log
