#!/bin/bash
# Install Kibana instance using Cloudformation template
# Support for Amazon Linux

echo "Starting process." >> /tmp/deploy.log

check_root(){
    echo "Checking root." >> /tmp/deploy.log
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "NOT running as root. Exiting" >> /tmp/deploy.log
        echo "This script must be run as root"
        exit 1
    fi
    echo "Running as root." >> /tmp/deploy.log
}

import_elasticsearch_repo(){
# Configuring Elastic repository
rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch

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
echo "Added Elasticsearch repo." >> /tmp/deploy.log
}

# Installing ELK coordinating only mode
install_elasticsearch(){
    echo "Installing Elasticsearch." >> /tmp/deploy.log
    # Installing Elasticsearch
    yum -y install elasticsearch-7.4.2
    chkconfig --add elasticsearch
    echo "Installed Elasticsearch." >> /tmp/deploy.log
}
start_elasticsearch(){
    systemctl start elasticsearch.service
}

# Install Wazuh master

add_wazuh_repo(){
cat > /etc/yum.repos.d/wazuh.repo <<\EOF
[wazuh_repo]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/3.x/yum/
protect=1
EOF
}

install_wazuh_manager(){
  # Installing wazuh-manager
  yum -y install wazuh-manager
  chkconfig --add wazuh-manager
}

configure_manager(){
  manager_config="/var/ossec/etc/ossec.conf"
  eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet' | head -1 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f2)
  sed -i "s/<protocol>udp<\/protocol>/<protocol>tcp<\/protocol>/" ${manager_config}
  sed -i '/<cluster>/,/<\/cluster>/d' ${manager_config}

cat >> ${manager_config} << EOF
<ossec_config>
  <cluster>
    <name>wazuh</name>
    <node_name>wazuh-master</node_name>
    <node_type>master</node_type>
    <key>abcdefghijklmnopqrstuvwxyz012345</key>
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
}

restart_manager(){
  systemctl restart wazuh-manager
}

set_up_filebeat(){
  TAG='v3.10.2'
  # Installing Filebeat
  yum -y install filebeat-7.4.2
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
  sed -i "s|'http://YOUR_ELASTIC_SERVER_IP:9200'|'http://10.0.0.15'|" /etc/filebeat/filebeat.yml
}

restart_filebeat(){
  systemctl restart filebeat
}

main(){
  check_root
  create_ssh_user
  import_elasticsearch_repo
  install_elasticsearch
  configuring_elasticsearch
  start_elasticsearch
  restart_manager
  set_up_filebeat
  restart_filebeat
}

main