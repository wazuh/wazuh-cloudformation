#!/bin/bash
# Install Wazuh master instance using Cloudformation template
# Support for Amazon Linux

set -exf

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
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2  | cut -d' ' -f1)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Adding Wazuh repository
wazuh_major_version=$(echo ${wazuh_version} | cut -d'.' -f1)
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/${wazuh_major_version}.x/yum/
protect=1
EOF

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
yum -y install wazuh-manager-${wazuh_version}
chkconfig --add wazuh-manager
manager_config="/var/ossec/etc/ossec.conf"

# Enable registration service (only for master node)
/var/ossec/bin/ossec-control enable auth

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

# Installing NodeJS
curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
yum -y install nodejs

# Installing wazuh-api
yum -y install wazuh-api-${wazuh_version}
chkconfig --add wazuh-api

# Configuring Wazuh API user and password
cd /var/ossec/api/configuration/auth
node htpasswd -b -c user ${wazuh_api_user} ${wazuh_api_password}

# Enable Wazuh API SSL and configure listening port
api_ssl_dir="/var/ossec/api/configuration/ssl"
openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
sed -i "s/config.https = \"no\";/config.https = \"yes\";/" /var/ossec/api/configuration/config.js
sed -i "s/config.port = \"55000\";/config.port = \"${wazuh_api_port}\";/" /var/ossec/api/configuration/config.js

# Restart wazuh-api
service wazuh-api restart

# Installing Filebeat
yum -y install filebeat
chkconfig --add filebeat

# Configuring Filebeat
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/v${wazuh_version}/extensions/filebeat/filebeat.yml
sed -i "s/YOUR_ELASTIC_SERVER_IP/${elb_logstash}/" /etc/filebeat/filebeat.yml
service filebeat start

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo
