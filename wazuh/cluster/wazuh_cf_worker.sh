#!/bin/bash
# Install Wazuh worker instance using Cloudformation template
# Support for Amazon Linux
touch /tmp/log
echo "Starting process." >> /tmp/log

ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
wazuh_server_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhServerPort:' | cut -d' ' -f2)
wazuh_cluster_key=$(cat /tmp/wazuh_cf_settings | grep '^WazuhClusterKey:' | cut -d' ' -f2)
wazuh_master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
elb_elasticsearch=$(cat /tmp/wazuh_cf_settings | grep '^ElbElasticDNS:' | cut -d' ' -f2)
VirusTotalKey=$(cat /tmp/wazuh_cf_settings | grep '^VirusTotalKey:' | cut -d' ' -f2)
AwsSecretKey=$(cat /tmp/wazuh_cf_settings | grep '^AwsSecretKey:' | cut -d' ' -f2)
AwsAccessKey=$(cat /tmp/wazuh_cf_settings | grep '^AwsAccessKey:' | cut -d' ' -f2)
SlackHook=$(cat /tmp/wazuh_cf_settings | grep '^SlackHook:' | cut -d' ' -f2)
EnvironmentType=$(cat /tmp/wazuh_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)

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
manager_config="/var/ossec/etc/ossec.conf"
# Install dependencies
yum -y install openscap-scanner

echo "Installed wazuh manager package" >> /tmp/log

# Change manager protocol to tcp, to be used by Amazon ELB
sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}

# Set manager ports for agents communication
sed -i "s/<port>1514<\/port>/<port>${wazuh_server_port}<\/port>/" ${manager_config}

# Installing Python Cryptography module for the cluster
pip install cryptography
echo "Installed cryptography with pip" >> /tmp/log

# Configuring cluster section
sed -i '/<cluster>/,/<\/cluster>/d' ${manager_config}

cat >> ${manager_config} << EOF
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>wazuh-worker</node_name>
    <node_type>worker</node_type>
    <key>${wazuh_cluster_key}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>${wazuh_master_ip}</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
</ossec_config>
EOF

# Restart for receiving cluster data
service wazuh-manager restart
# Wait for cluster information to be received (rules,lists...)
sleep 60

# Disabling agent components and cleaning configuration file
sed -i '/<wodle name="open-scap">/,/<\/wodle>/d' ${manager_config}
sed -i '/<wodle name="cis-cat">/,/<\/wodle>/d' ${manager_config}
sed -i '/<ruleset>/,/<\/ruleset>/d' ${manager_config}
sed -i '/<auth>/,/<\/auth>/d' ${manager_config}
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


# Slack integration
if [ "x${SlackHook}" != "x" ]; then
cat >> ${manager_config} << EOF
<ossec_config>
  <integration>
    <name>slack</name>
    <hook_url>${SlackHook}</hook_url>
    <level>10</level>
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
      <access_key>XXXX</access_key>
      <secret_key>XXXX</secret_key>
      <only_logs_after>2019-MAR-24</only_logs_after>
    </bucket>
    <service type="inspector">
      <access_key>XXXX</access_key>
      <secret_key>XXXX</secret_key>
    </service>
  </wodle>
</ossec_config>
EOF
fi

UID=$(id -u `whoami`)

# Audit rules
cat >> /etc/audit/rules.d/audit.rules << EOF
-a exit,always -F euid=0 -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F euid=0 -F arch=b64 -S execve -k audit-wazuh-c
-a exit,always -F euid=1003 -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F euid=1003 -F arch=b64 -S execve -k audit-wazuh-c
-a exit,always -F euid=1002 -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F euid=1002 -F arch=b64 -S execve -k audit-wazuh-c
-a exit,always -F euid=1003 -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F euid=1003 -F arch=b64 -S execve -k audit-wazuh-c
-a exit,always -F euid=${UID} -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F euid=${UID} -F arch=b64 -S execve -k audit-wazuh-c
EOF

auditctl -D
auditctl -R /etc/audit/rules.d/audit.rules
systemctl restart audit

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


echo "Cluster configuration" >> /tmp/log

# Restart wazuh-manager
service wazuh-manager restart

# Installing Filebeat
yum -y install filebeat
chkconfig --add filebeat
echo "Installed Filebeat" >> /tmp/log

# Configuring Filebeat
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
elastic_minor_version=$(echo ${elastic_version} | cut -d'.' -f2)
elastic_patch_version=$(echo ${elastic_version} | cut -d'.' -f3)
curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/v$wazuh_major.$wazuh_minor.$wazuh_patch/extensions/filebeat/7.x/filebeat.yml

# Filebeat configuration
curl -so /etc/filebeat/wazuh-template.json "https://raw.githubusercontent.com/wazuh/wazuh/$wazuh_version/extensions/elasticsearch/7.x/wazuh-template.json"

# File permissions
chmod go-w /etc/filebeat/filebeat.yml
chmod go-w /etc/filebeat/wazuh-template.json
sed -i "s/YOUR_ELASTIC_SERVER_IP/${elb_elasticsearch}/" /etc/filebeat/filebeat.yml
service filebeat start
echo "Started Filebeat" >> /tmp/log
echo "Done" >> /tmp/log