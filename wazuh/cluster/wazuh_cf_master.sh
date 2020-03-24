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
TAG='v3.12.4'

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
elif [[ ${EnvironmentType} == 'sources' ]]
then

  # Compile Wazuh manager from sources
  BRANCH="3.12"

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

if [[ ${EnvironmentType} != 'sources' ]]
then

  # Installing wazuh-manager
  yum -y install wazuh-manager
  chkconfig --add wazuh-manager
  # Installing wazuh-api
  yum -y install wazuh-api
  chkconfig --add wazuh-api
  echo "Installed Wazuh API." >> /tmp/deploy.log
else
  API_BRANCH="3.12"
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

### Use case 1: IP reputation
echo "Fetching AlienVault reputation IPset" >> /tmp/deploy.log

wget https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset -O /tmp/alienvault_reputation.ipset
wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py
# Add Windows public IP to the list
echo ${WindowsPublicIp} >> /tmp/alienvault_reputation.ipset
python /tmp/iplist-to-cdblist.py /tmp/alienvault_reputation.ipset /tmp/blacklist-alienvault
# Delete ipset and python script
rm -rf /tmp/alienvault_reputation.ipset
rm -rf /tmp/iplist-to-cdblist.py
cp /tmp/blacklist-alienvault /var/ossec/etc/lists/
chown ossec:ossec /var/ossec/etc/lists/blacklist-alienvault
chmod 660 /var/ossec/etc/lists/blacklist-alienvault
/var/ossec/bin/ossec-makelists
echo "Updated CDB list ,added Windows agent IP." >> /tmp/deploy.log

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

# Add ruleset and lists
cat >> ${manager_config} << EOF
<ossec_config>
  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/blacklist-alienvault</list>
    <!-- User-defined ruleset -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>
</ossec_config>
EOF

# Use case: Open-SCAP configuration

# Install dependencies
yum -y install openscap-scanner

# Configure wodles
cat >> ${manager_config} << EOF
<ossec_config>
  <wodle name="open-scap">
    <disabled>no</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
    <content type="xccdf" path="ssg-rhel-7-ds.xml">
      <profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
      <profile>xccdf_org.ssgproject.content_profile_common</profile>
    </content>
    <content type="xccdf" path="cve-redhat-7-ds.xml"/>
  </wodle>
</ossec_config>
EOF

# Add VirusTotal integration if key already set
if [ "x${VirusTotalKey}" != "x" ]; then
cat >> ${manager_config} << EOF
<ossec_config>
  <integration>
      <name>virustotal</name>
      <api_key>${VirusTotalKey}</api_key>
      <rule_id>100200</rule_id>
      <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
fi

cat >> ${local_rules} << EOF
<group name="syscheck,">
  <rule id="100200" level="7">
    <if_sid>550,553,554</if_sid>
    <field name="file">\S*/virus|\S*\\\\virus</field>
    <description>File modified or created in /virus directory.</description>
  </rule>
</group>
<group name="ossec,">
  <rule id="100050" level="0">
    <if_sid>530</if_sid>
    <match>^ossec: output: 'process list'</match>
    <description>List of running processes.</description>
    <group>process_monitor,</group>
  </rule>
  <rule id="100051" level="7" ignore="900">
    <if_sid>100050</if_sid>
    <match>nc -l</match>
    <description>Netcat listening for incoming connections.</description>
    <group>process_monitor,</group>
  </rule>
</group>
<group name="attack,">
  <rule id="100100" level="10">
    <if_group>web|attack|attacks</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
    <description>IP address found in AlienVault reputation database.</description>
  </rule>
</group>
EOF

# Slack integration
if [ "x${SlackHook}" != "x" ]; then
cat >> ${manager_config} << EOF
<ossec_config>
  <integration>
    <name>slack</name>
    <hook_url>${SlackHook}</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
fi

# AWS integration if key already set
if [ "x${AwsAccessKey}" != "x" ]; then
cat >> ${manager_config} << EOF
<ossec_config>
  <wodle name="aws-s3">
    <disabled>no</disabled>
    <remove_from_bucket>no</remove_from_bucket>
    <interval>30m</interval>
    <run_on_start>yes</run_on_start>
    <skip_on_error>no</skip_on_error>
    <bucket type="cloudtrail">
      <name>wazuh-cloudtrail</name>
      <access_key>${AwsAccessKey}</access_key>
      <secret_key>${AwsSecretKey}</secret_key>
      <only_logs_after>2019-MAR-24</only_logs_after>
    </bucket>
    <bucket type="guardduty">
      <name>wazuh-aws-wodle</name>
      <path>guardduty</path>
      <access_key>${AwsAccessKey}</access_key>
      <secret_key>${AwsSecretKey}</secret_key>
      <only_logs_after>2019-MAR-24</only_logs_after>
    </bucket>
    <bucket type="custom">
      <name>wazuh-aws-wodle</name>
      <path>macie</path>
      <access_key>${AwsAccessKey}</access_key>
      <secret_key>${AwsSecretKey}</secret_key>
      <only_logs_after>2019-MAR-24</only_logs_after>
    </bucket>
    <bucket type="vpcflow">
      <name>wazuh-aws-wodle</name>
      <path>vpc</path>
      <access_key>${AwsAccessKey}</access_key>
      <secret_key>${AwsSecretKey}</secret_key>
      <only_logs_after>2019-MAR-24</only_logs_after>
    </bucket>
    <service type="inspector">
      <access_key>${AwsAccessKey}</access_key>
      <secret_key>${AwsSecretKey}</secret_key>
    </service>
  </wodle>
</ossec_config>
EOF
fi

the_uid=$(id -u wazuh)

# Audit rules
cat >> /etc/audit/rules.d/audit.rules << EOF
-a exit,always -F euid=${the_uid} -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F euid=${the_uid} -F arch=b64 -S execve -k audit-wazuh-c
EOF

auditctl -D
auditctl -R /etc/audit/rules.d/audit.rules
systemctl restart auditd
# Localfiles
cat >> ${manager_config} << EOF
<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <alias>process list</alias>
    <command>ps -e -o pid,uname,command</command>
    <frequency>30</frequency>
  </localfile>
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <expect>srcip</expect>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100100</rules_id>
    <timeout>60</timeout>
  </active-response>
</ossec_config>
EOF

# Vuln detector
cat >> ${manager_config} << EOF
<ossec_config>
  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>12m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <feed name="ubuntu-18">
      <disabled>no</disabled>
      <update_interval>1h</update_interval>
    </feed>
    <feed name="redhat">
      <disabled>no</disabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </feed>
    <feed name="debian-9">
      <disabled>no</disabled>
      <update_interval>1h</update_interval>
    </feed>
  </wodle>
</ossec_config>
EOF

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
curl -so /opt/splunkforwarder/etc/system/local/props.conf https://raw.githubusercontent.com/wazuh/wazuh/${TAG}/extensions/splunk/props.conf

# inputs.conf
curl -so /opt/splunkforwarder/etc/system/local/inputs.conf https://raw.githubusercontent.com/wazuh/wazuh/${TAG}/extensions/splunk/inputs.conf

# set hostname
sed -i "s:MANAGER_HOSTNAME:$(hostname):g" /opt/splunkforwarder/etc/system/local/inputs.conf

# create credential file
touch /opt/splunkforwarder/etc/system/local/user-seed.conf

# add admin user
echo "[user_info]" > /opt/splunkforwarder/etc/system/local/user-seed.conf
echo "USERNAME = $splunk_username" >> /opt/splunkforwarder/etc/system/local/user-seed.conf
echo "PASSWORD = $splunk_password" >> /opt/splunkforwarder/etc/system/local/user-seed.conf

echo "Starting Splunk..."
# accept license
/opt/splunkforwarder/bin/splunk start --accept-license --answer-yes --auto-ports --no-prompt &> /dev/null

# forward to index
/opt/splunkforwarder/bin/splunk add forward-server ${splunk_ip}:9997 -auth $splunk_username:$splunk_password &> /dev/null

# restart service
/opt/splunkforwarder/bin/splunk restart &> /dev/null
echo "Done with Splunk." >> /tmp/deploy.log

# Creating groups
/var/ossec/bin/agent_groups -a -g apache -q
/var/ossec/bin/agent_groups -a -g redhat -q
/var/ossec/bin/agent_groups -a -g windows -q
/var/ossec/bin/agent_groups -a -g mysql -q

# Give time to the instances dependencies to be properly installed
sleep 360

# Write RHEL7 shared config
redhat_conf='/var/ossec/etc/shared/redhat/agent.conf'
sed -i '/<agent_config>/,/<\/agent_config>/d' ${redhat_conf}
cat >> ${redhat_conf} << EOF
<agent_config>
<wodle name="docker-listener">
  <interval>10m</interval>
  <attempts>5</attempts>
  <run_on_start>yes</run_on_start>
  <disabled>no</disabled>
</wodle>

	<syscheck>
		<disabled>no</disabled>
		<frequency>43200</frequency>
		<scan_on_start>yes</scan_on_start>
		<!-- Files/directories to monitor -->
		<directories check_all="yes" whodata="yes">/usr/bin,/usr/sbin</directories>
		<directories check_all="yes" whodata="yes">/bin,/sbin,/boot</directories>
		<directories check_all="yes" report_changes="yes" whodata="yes" tags="cron">/etc/cron*</directories>
		<directories check_all="yes" report_changes="yes" whodata="yes" recursion_level="2">/home,/root</directories>
		<directories check_all="yes" report_changes="yes" whodata="yes" tags="tmp" restrict="!.tmp$">/tmp</directories>
		<!-- Files/directories to ignore -->
		<ignore>/etc/mtab</ignore>
		<ignore>/etc/hosts.deny</ignore>
		<ignore>/etc/mail/statistics</ignore>
		<ignore>/etc/random-seed</ignore>
		<ignore>/etc/random.seed</ignore>
		<ignore>/etc/adjtime</ignore>
		<ignore>/etc/httpd/logs</ignore>
		<ignore>/etc/utmpx</ignore>
		<ignore>/etc/wtmpx</ignore>
		<ignore>/etc/cups/certs</ignore>
		<ignore>/etc/dumpdates</ignore>
		<ignore>/etc/svc/volatile</ignore>
		<!-- File extensions ignored -->
		<ignore type="sregex">.log$|.tmp$|.swp$|.viminfo$</ignore>
		<!-- Check the file, but never compute the diff -->
		<nodiff>/etc/ssl/private.key</nodiff>
		<!-- NFS files -->
		<skip_nfs>yes</skip_nfs>
	</syscheck>
	<!-- Policy monitoring -->
	<!-- OpenSCAP integration -->
	<wodle name="open-scap">
		<disabled>no</disabled>
		<timeout>1800</timeout>
		<interval>1d</interval>
		<scan-on-start>yes</scan-on-start>
		<content type="xccdf" path="ssg-rhel-7-ds.xml">
			<profile>xccdf_org.ssgproject.content_profile_pci-dss</profile>
			<profile>xccdf_org.ssgproject.content_profile_common</profile>
		</content>
		<content type="xccdf" path="cve-redhat-7-ds.xml"/>
	</wodle>
	<!-- System inventory -->
	<wodle name="syscollector">
		<disabled>no</disabled>
		<interval>1h</interval>
		<scan_on_start>yes</scan_on_start>
		<hardware>yes</hardware>
		<os>yes</os>
		<network>yes</network>
		<packages>yes</packages>
		<ports>yes</ports>
		<processes>yes</processes>
	</wodle>
	<wodle name="osquery">
		<disabled>no</disabled>
		<run_daemon>yes</run_daemon>
		<bin_path>/usr/bin</bin_path>
		<log_path>/var/log/osquery/osqueryd.results.log</log_path>
		<config_path>/etc/osquery/osquery.conf</config_path>
		<add_labels>no</add_labels>
	</wodle>
	<!-- Log analysis -->
	<localfile>
		<log_format>command</log_format>
		<command>df -P</command>
		<frequency>360</frequency>
	</localfile>
	<localfile>
		<log_format>full_command</log_format>
		<command>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]\+\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 == \3 == \4 \5/' | sort -k 4 -g | sed 's/ == \(.*\) ==/:\1/' | sed 1,2d</command>
		<alias>netstat listening ports</alias>
		<frequency>360</frequency>
	</localfile>
	<localfile>
		<log_format>full_command</log_format>
		<command>last -n 20</command>
		<frequency>360</frequency>
	</localfile>
	<localfile>
		<log_format>apache</log_format>
		<location>/var/log/httpd/error_log*</location>
	</localfile>
	<localfile>
		<log_format>apache</log_format>
		<location>/var/log/httpd/access_log*</location>
	</localfile>
	<localfile>
		<log_format>audit</log_format>
		<location>/var/log/audit/audit.log</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/ossec/logs/active-responses.log</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/messages</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/secure</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/maillog</location>
	</localfile>
	<localfile>
		<log_format>syslog</log_format>
		<location>/var/log/suricata/eve.json</location>
	</localfile>
	<localfile>
		<log_format>full_command</log_format>
		<alias>process list</alias>
		<command>ps -e -o pid,uname,command</command>
		<frequency>30</frequency>
	</localfile>
</agent_config>
EOF

# Write Windows shared config
windows_conf='/var/ossec/etc/shared/windows/agent.conf'
sed -i '/<agent_config>/,/<\/agent_config>/d' ${windows_conf}
cat >> ${windows_conf} << EOF
<agent_config>
	<wodle name="syscollector">
		<disabled>no</disabled>
		<interval>1h</interval>
		<scan_on_start>yes</scan_on_start>
		<hardware>yes</hardware>
		<os>yes</os>
		<packages>yes</packages>
	</wodle>
	<wodle name="osquery">
		<disabled>no</disabled>
		<run_daemon>yes</run_daemon>
		<bin_path>C:\ProgramData\osquery\osqueryd</bin_path>
		<log_path>C:\ProgramData\osquery\log\osqueryd.results.log</log_path>
		<config_path>C:\ProgramData\osquery\osquery.conf</config_path>
		<add_labels>no</add_labels>
	</wodle>
	<localfile>
		<location>C:\inetpub\logs\LogFiles\W3SVC1\u_ex%y%m%d.log</location>
		<log_format>iis</log_format>
	</localfile>
	<syscheck>
		<scan_on_start>yes</scan_on_start>
		<directories check_all="yes" report_changes="yes" whodata="yes">C:\Santiago</directories>
	</syscheck>
</agent_config>
EOF

# Write apache shared config
apache_conf='/var/ossec/etc/shared/apache/agent.conf'
sed -i '/<agent_config>/,/<\/agent_config>/d' ${apache_conf}
cat >> ${apache_conf} << EOF
<agent_config>
	<syscheck>
		<disabled>no</disabled>
		<frequency>43200</frequency>
		<scan_on_start>yes</scan_on_start>
		<!-- Files/directories to monitor -->
		<directories check_all="yes" report_changes="yes" whodata="yes" tags="apache,web,httpd" restrict=".conf$">/etc/httpd</directories>
		<!-- File extensions ignored -->
		<ignore type="sregex">.log$|.tmp$|.swp$|.viminfo$</ignore>
	</syscheck>
</agent_config>
EOF

# Write mysql shared config
mysql_conf='/var/ossec/etc/shared/mysql/agent.conf'
sed -i '/<agent_config>/,/<\/agent_config>/d' ${mysql_conf}
cat >> ${mysql_conf} << EOF
<agent_config>
	<syscheck>
		<directories check_all="yes" report_changes="yes" whodata="yes" tags="visa" recursion_level="2" restrict=".conf$">/var/lib/mysql</directories>
	</syscheck>
</agent_config>
EOF

# Attach agents to groups
rhel_id=`/var/ossec/bin/manage_agents -l | grep RHEL | cut -d':' -f2 | cut -d ',' -f1`
windows_id=`/var/ossec/bin/manage_agents -l | grep Win | cut -d':' -f2 | cut -d ',' -f1`

/var/ossec/bin/agent_groups -a -g redhat -i ${rhel_id} -q
/var/ossec/bin/agent_groups -a -g mysql -i ${rhel_id} -q
/var/ossec/bin/agent_groups -a -g apache -i ${rhel_id} -q
/var/ossec/bin/agent_groups -a -g windows -i ${windows_id} -q