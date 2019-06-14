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
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
node_name=$(cat /tmp/wazuh_cf_settings | grep '^NodeName:' | cut -d' ' -f2)

echo "Added env vars." >> /tmp/deploy.log
echo "eth0_ip: $eth0_ip" >> /tmp/deploy.log

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
    service sshd restart
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
# Creating data and logs directories
mkdir -p /mnt/ephemeral/elasticsearch/lib
mkdir -p /mnt/ephemeral/elasticsearch/log
chown -R elasticsearch:elasticsearch /mnt/ephemeral/elasticsearch
echo "Created volumes in ephemeral." >> /tmp/log

cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: "wazuh_elastic"
node.name: "node-$node_name"
node.master: true
path.data: /mnt/ephemeral/elasticsearch/lib
path.logs: /mnt/ephemeral/elasticsearch/log
discovery.seed_hosts: 
  - "10.0.2.123"
  - "10.0.2.124"
  - "10.0.2.125"

EOF

echo "network.host: $eth0_ip" >> /etc/elasticsearch/elasticsearch.yml

# Correct owner for Elasticsearch directories
chown elasticsearch:elasticsearch -R /etc/elasticsearch
chown elasticsearch:elasticsearch -R /usr/share/elasticsearch
chown elasticsearch:elasticsearch -R /var/lib/elasticsearch

# Calculating RAM for Elasticsearch
ram_gb=$[$(free -g | awk '/^Mem:/{print $2}')+1]
ram=$(( ${ram_gb} / 2 ))
if [ $ram -eq "0" ]; then ram=1; fi
echo "Setting RAM." >> /tmp/log

# Configuring jvm.options
cat > /etc/elasticsearch/jvm.options << EOF
-Xms${ram}g
-Xmx${ram}g
EOF
echo "Setting JVM options." >> /tmp/log

mkdir -p /etc/systemd/system/elasticsearch.service.d/
echo '[Service]' > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
echo 'LimitMEMLOCK=infinity' >> /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf

# Allowing unlimited memory allocation
echo 'elasticsearch soft memlock unlimited' >> /etc/security/limits.conf
echo 'elasticsearch hard memlock unlimited' >> /etc/security/limits.conf
echo "Setting memory lock options." >> /tmp/log
echo "Setting permissions." >> /tmp/deploy.log
}

set_xpack_certs(){
    mkdir /etc/elasticsearch/certs/ca -p
    amazon-linux-extras install epel -y
    yum install -y sshpass
    sleep 500
    echo $ssh_password >> pass
    sshpass -f pass scp -o "StrictHostKeyChecking=no" wazuh@10.0.2.124:/home/wazuh/certs.zip /home/wazuh/
    rm pass -f
    cp /home/wazuh/certs.zip .
    unzip certs.zip
    cp ca/ca.crt /etc/elasticsearch/certs/ca
    cp elastic-node${node_name}/elastic-node${node_name}.crt /etc/elasticsearch/certs
    cp elastic-node${node_name}/elastic-node${node_name}.key /etc/elasticsearch/certs
    echo "xpack.security.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.verification_mode: certificate" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elastic-node${node_name}.key" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elastic-node${node_name}.crt" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]" >> /etc/elasticsearch/elasticsearch.yml
    echo "# HTTP layer" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.verification_mode: certificate" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.key: /etc/elasticsearch/certs/elastic-node${node_name}.key" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elastic-node${node_name}.crt" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]" >> /etc/elasticsearch/elasticsearch.yml
    chown -R elasticsearch: /etc/elasticsearch/certs
    systemctl restart elasticsearch
}

start_elasticsearch(){
    # Correct owner for Elasticsearch directories
    chown elasticsearch:elasticsearch -R /etc/elasticsearch
    chown elasticsearch:elasticsearch -R /usr/share/elasticsearch
    chown elasticsearch:elasticsearch -R /var/lib/elasticsearch
    systemctl daemon-reload
    # Starting Elasticsearch
    echo "daemon-reload." >> /tmp/deploy.log
    systemctl restart elasticsearch
    echo "starting elasticsearch service." >> /tmp/deploy.log
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
    set_xpack_certs
    start_elasticsearch
    disable_elk_repos
}

main