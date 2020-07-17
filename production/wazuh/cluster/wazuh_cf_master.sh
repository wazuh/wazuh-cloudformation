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
InstallType=$(cat /tmp/wazuh_cf_settings | grep '^InstallType:' | cut -d' ' -f2)
branch=$(cat /tmp/wazuh_cf_settings | grep '^Branch:' | cut -d' ' -f2)
api_branch=$(cat /tmp/wazuh_cf_settings | grep '^ApiBranch:' | cut -d' ' -f2)
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
elastic_minor_version=$(echo ${elastic_version} | cut -d'.' -f2)
elastic_patch_version=$(echo ${elastic_version} | cut -d'.' -f3)

TAG="v$wazuh_version"

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

if [[ ${InstallType} == 'packages' ]]
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
elif [[ ${InstallType} == 'sources' ]]
then

  # Compile Wazuh manager from sources
  BRANCH=$branch

  yum install make gcc policycoreutils-python automake autoconf libtool -y
  curl -Ls https://github.com/wazuh/wazuh/archive/$BRANCH.tar.gz | tar zx
  rm -f $BRANCH.tar.gz
  cd wazuh-$BRANCH/src
  make TARGET=agent DEBUG=1 -j8

  USER_LANGUAGE="en" \
  USER_NO_STOP="y" \
  USER_INSTALL_TYPE="server" \
  USER_DIR="/var/ossec" \
  USER_ENABLE_EMAIL="n" \
  USER_ENABLE_SYSCHECK="y" \
  USER_ENABLE_ROOTCHECK="y" \
  USER_ENABLE_OPENSCAP="n" \
  USER_WHITE_LIST="n" \
  USER_ENABLE_SYSLOG="n" \
  USER_ENABLE_AUTHD="y" \
  USER_AUTO_START="y" \
  THREADS=2 \
  ../install.sh
  echo "Compiled wazuh" >> /tmp/deploy.log

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

curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
# Installing NodeJS
yum -y install nodejs
echo "Installed NodeJS." >> /tmp/deploy.log

if [[ ${InstallType} != 'sources' ]]
then

  # Installing wazuh-manager
  yum -y install wazuh-manager-$wazuh_version
  chkconfig --add wazuh-manager
  # Installing wazuh-api
  yum -y install wazuh-api
  chkconfig --add wazuh-api
  echo "Installed Wazuh API." >> /tmp/deploy.log
else
  API_BRANCH=$api_branch
  npm config set user 0
  curl -LO https://github.com/wazuh/wazuh-api/archive/$API_BRANCH.zip
  unzip $API_BRANCH.zip
  rm -f $API_BRANCH.zip
  cd wazuh-api-$API_BRANCH
  ./install_api.sh
fi

manager_config="/var/ossec/etc/ossec.conf"
local_rules="/var/ossec/etc/rules/local_rules.xml"
# Enable registration service (only for master node)

echo "Installed wazuh manager package" >> /tmp/deploy.log


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
echo "Set registration password." >> /tmp/deploy.log

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
sed -i '/<wodle name="open-scap">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="cis-cat">/,/<\/wodle>/d' ${manager_config}
sed -i '/<ruleset>/,/<\/ruleset>/d' ${manager_config}
sed -i '/<wodle name="syscollector">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="vulnerability-detector">/,/<\/wodle>/d' ${manager_config}
sed -i '/<localfile>/,/<\/localfile>/d' ${manager_config}
sed -i '/<!--.*-->/d' ${manager_config}
sed -i '/<!--/,/-->/d' ${manager_config}
sed -i '/^$/d' ${manager_config}

# Restart wazuh-manager
systemctl restart wazuh-manager
systemctl enable wazuh-manager
echo "Restarted Wazuh manager." >> /tmp/deploy.log

# Configuring Wazuh API user and password
cd /var/ossec/api/configuration/auth
node htpasswd -b -c user ${wazuh_api_user} ${wazuh_api_password}

# Enable Wazuh API SSL and configure listening port
api_ssl_dir="/var/ossec/api/configuration/ssl"
openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
sed -i "s/config.https = \"no\";/config.https = \"yes\";/" /var/ossec/api/configuration/config.js
sed -i "s/config.port = \"55000\";/config.port = \"${wazuh_api_port}\";/" /var/ossec/api/configuration/config.js
echo "Setting port and SSL to Wazuh API." >> /tmp/deploy.log

# Restart wazuh-api
systemctl restart wazuh-api
echo "Restarted Wazuh API." >> /tmp/deploy.log

# Installing Filebeat
yum -y install filebeat-${elastic_version}
echo "Installed Filebeat" >> /tmp/log

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
sed -i "s|'http://YOUR_ELASTIC_SERVER_IP:9200'|'10.0.2.123','10.0.2.124','10.0.2.125'|" /etc/filebeat/filebeat.yml

amazon-linux-extras install epel -y
yum install -y sshpass
chmod go-w /etc/filebeat/wazuh-template.json
echo "output.elasticsearch.username: "elastic"" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.password: "$ssh_password"" >> /etc/filebeat/filebeat.yml
mkdir -p /etc/filebeat/certs/ca
amazon-linux-extras install epel -y
yum install -y sshpass
sleep 500
echo $ssh_password >> pass
sshpass -f pass scp -o "StrictHostKeyChecking=no" wazuh@10.0.2.124:/home/wazuh/certs.zip /home/wazuh/
rm pass -f
cp /home/wazuh/certs.zip .
unzip certs.zip
cp ca/ca.crt /etc/filebeat/certs/ca
cp wazuh-manager/wazuh-manager.crt /etc/filebeat/certs
cp wazuh-manager/wazuh-manager.key /etc/filebeat/certs
chmod 770 -R /etc/filebeat/certs
echo "output.elasticsearch.protocol: https" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.ssl.certificate: "/etc/filebeat/certs/wazuh-manager.crt"" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.ssl.key: "/etc/filebeat/certs/wazuh-manager.key"" >> /etc/filebeat/filebeat.yml
echo "output.elasticsearch.ssl.certificate_authorities: ["/etc/filebeat/certs/ca/ca.crt"]" >> /etc/filebeat/filebeat.yml
systemctl enable filebeat
systemctl daemon-reload
systemctl restart filebeat
echo "Restarted Filebeat." >> /tmp/deploy.log


# Load template in Easticsearch
echo "Loading template..." >> /tmp/deploy.log
until curl -XGET "https://10.0.2.123:9200" -k -u elastic:${ssh_password}; do
    sleep 5
    echo "Elasticsearch not ready yet..." >> /tmp/deploy.log
done

filebeat setup --index-management -E setup.template.json.enabled=false

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
