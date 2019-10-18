#!/bin/bash
# Install Wazuh worker instance using Cloudformation template
# Support for Amazon Linux
touch /tmp/log
echo "Starting process." >> /tmp/log

load_env_vars(){
	elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
	wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
	wazuh_server_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhServerPort:' | cut -d' ' -f2)
	wazuh_cluster_key=$(cat /tmp/wazuh_cf_settings | grep '^WazuhClusterKey:' | cut -d' ' -f2)
	wazuh_master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
	EnvironmentType=$(cat /tmp/wazuh_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)
	TAG="v$wazuh_version"
}

get_repo(){
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
}

install_manager(){
	# Installing wazuh-manager
	yum -y install wazuh-manager
	chkconfig --add wazuh-manager
	manager_config="/var/ossec/etc/ossec.conf"
	echo "Installed wazuh manager package" >> /tmp/log
}

config_manager(){
	# Change manager protocol to tcp, to be used by Amazon ELB
	sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}
	# Set manager ports for agents communication
	sed -i "s/<port>1514<\/port>/<port>${wazuh_server_port}<\/port>/" ${manager_config}
}

config_cluster(){
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
	systemctl restart wazuh-manager
}

install_filebeat(){
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
}

main(){
	# Check if running as root
	if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root"
	exit 1
	fi
	load_env_vars
	get_repo
	install_manager
	config_manager
	config_cluster
	install_filebeat
}

main