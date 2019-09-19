#!/bin/bash
# Install Elastic data node using Cloudformation template

touch /tmp/deploy.log

echo "Elasticsearch: Starting process." > /tmp/deploy.log
ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet' | head -1 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f2)
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
node_name=$(cat /tmp/wazuh_cf_settings | grep '^NodeName:' | cut -d' ' -f2)
TAG="v3.10.0"
echo "Added env vars." >> /tmp/deploy.log

check_root(){
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "NOT running as root. Exiting" >> /tmp/deploy.log
        echo "This script must be run as root"
        exit 1
    fi
    echo "Running as root." >> /tmp/deploy.log
}

create_ssh_user(){
    # Creating SSH user
    if ! id -u ${ssh_username} > /dev/null 2>&1; then adduser ${ssh_username}; fi
    echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
    usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
    echo "Created SSH user." >> /tmp/deploy.log

    sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
    systemctl restart sshd
    echo "Started SSH service." >> /tmp/deploy.log
}

import_elk_repo(){
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

install_elasticsearch(){
    echo "Installing Elasticsearch." >> /tmp/deploy.log
    # Installing Elasticsearch
    yum -y install elasticsearch-${elastic_version}
    chkconfig --add elasticsearch
    echo "Installed Elasticsearch." >> /tmp/deploy.log
}

configuring_elasticsearch(){
echo "Configuring elasticsearch." >> /tmp/deploy.log

# Creating data and logs directories
mkdir -p /mnt/ephemeral/elasticsearch/lib
mkdir -p /mnt/ephemeral/elasticsearch/log
chown -R elasticsearch:elasticsearch /mnt/ephemeral/elasticsearch
echo "Created volumes in ephemeral." >> /tmp/deploy.log

cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: "wazuh_elastic"
node.name: "environment-$node_name"
node.master: true
path.data: /mnt/ephemeral/elasticsearch/lib
path.logs: /mnt/ephemeral/elasticsearch/log
network.host: 0.0.0.0
cluster.initial_master_nodes: 
  - "localhost"
EOF

# Calculating RAM for Elasticsearch
ram_gb=$[$(free -g | awk '/^Mem:/{print $2}')+1]
ram=$(( ${ram_gb} / 2 ))
if [ $ram -eq "0" ]; then ram=1; fi
echo "Setting RAM." >> /tmp/deploy.log

# Configuring jvm.options
cat > /etc/elasticsearch/jvm.options << EOF
-Xms${ram}g
-Xmx${ram}g
-Dlog4j2.disable.jmx=true
EOF
echo "Setting JVM options." >> /tmp/deploy.log

mkdir -p /etc/systemd/system/elasticsearch.service.d/
echo '[Service]' > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
echo 'LimitMEMLOCK=infinity' >> /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf

# Allowing unlimited memory allocation
echo 'elasticsearch soft memlock unlimited' >> /etc/security/limits.conf
echo 'elasticsearch hard memlock unlimited' >> /etc/security/limits.conf
echo "Setting memory lock options." >> /tmp/deploy.log
echo "Setting permissions." >> /tmp/deploy.log
start_elasticsearch
}

start_elasticsearch(){
    echo "Starting Elasticsearch and setting permissions" >> /tmp/deploy.log
    chown elasticsearch:elasticsearch -R /etc/elasticsearch
    chown elasticsearch:elasticsearch -R /usr/share/elasticsearch
    chown elasticsearch:elasticsearch -R /var/lib/elasticsearch
    systemctl daemon-reload
    # Starting Elasticsearch
    echo "daemon-reload." >> /tmp/deploy.log
    systemctl restart elasticsearch
    echo "Started elasticsearch service." >> /tmp/deploy.log
    systemctl status elasticsearch >> /tmp/deploy.log
}

disable_elk_repos(){
    # Disable repositories
    sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
}

main(){
    check_root
    create_ssh_user
    import_elk_repo
    install_elasticsearch
    configuring_elasticsearch
    start_elasticsearch
    add_wazuh_user
    disable_elk_repos
}

main