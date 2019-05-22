#!/bin/bash
# Install Elastic data node using Cloudformation template

set -e

touch /tmp/deploy.log

echo "Elasticsearch: Starting process." > /tmp/deploy.log
ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet' | head -1 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f2)
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

install_java(){
    # Uninstall OpenJDK 1.7 if exists
    if rpm -q java-1.7.0-openjdk > /dev/null; then yum -y remove java-1.7.0-openjdk; fi
    # Install OpenJDK 1.8
    yum -y install java-1.8.0-openjdk
}

import_elk_repo(){
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
echo "Added Elasticsearch repo." >> /tmp/deploy.log
}

install_elasticsearch(){
    echo "Installing Elasticsearch." >> /tmp/deploy.log

    # Installing Elasticsearch
    yum -y install elasticsearch-${elastic_version}
    chkconfig --add elasticsearch
    echo "Installed Elasticsearch." >> /tmp/deploy.log

    # Installing Elasticsearch plugin for EC2
    /usr/share/elasticsearch/bin/elasticsearch-plugin install --batch discovery-ec2
    echo "Installed EC2 plugin." >> /tmp/deploy.log
}

configuring_elasticsearch(){
    # Configuration file created by AWS Cloudformation template
    # Because of it we set the right owner/group for the file
    mv -f /tmp/wazuh_cf_elasticsearch.yml /etc/elasticsearch/elasticsearch.yml
    echo "mv -f /tmp/wazuh_cf_elasticsearch.yml /etc/elasticsearch/elasticsearch.yml" >> /tmp/deploy.log
    chown elasticsearch:elasticsearch /etc/elasticsearch/elasticsearch.yml
    echo "Setting permissions." >> /tmp/deploy.log
}


start_elasticsearch(){
    systemctl daemon-reload
    # Starting Elasticsearch
    echo "daemon-reload." >> /tmp/deploy.log
    service elasticsearch start
    echo "starting elasticsearch service." >> /tmp/deploy.log
}

add_logstash(){
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
#Installing Logstash
yum -y install logstash-${elastic_version}
echo "Installed logstash." >> /tmp/deploy.log

#Wazuh configuration for Logstash

if [[ $elastic_major_version -eq 7 ]]; then
curl -so /etc/logstash/conf.d/01-wazuh.conf "https://raw.githubusercontent.com/wazuh/wazuh/v$wazuh_major.$wazuh_minor.$wazuh_patch/extensions/logstash/7.x/01-wazuh-remote.conf"
elif [[ $elastic_major_version -eq 6 ]] && [[ $wazuh_major -eq 3 ]] && [[ $wazuh_minor -eq 9 ]] && [[ $wazuh_patch -eq 1 ]]; then
curl -so /etc/logstash/conf.d/01-wazuh.conf "https://raw.githubusercontent.com/wazuh/wazuh/v$wazuh_major.$wazuh_minor.$wazuh_patch/extensions/logstash/6.x/01-wazuh-remote.conf"
elif [[ $elastic_major_version -le 6 ]] && [[ $wazuh_major -le 3 ]] && [[ $wazuh_minor -lt 9 ]]; then
curl -so /etc/logstash/conf.d/01-wazuh.conf "https://raw.githubusercontent.com/wazuh/wazuh/v$wazuh_major.$wazuh_minor.$wazuh_patch/extensions/logstash/01-wazuh-remote.conf"
fi

sed -i "s/localhost:9200/${eth0_ip}:9200/" /etc/logstash/conf.d/01-wazuh.conf

# Creating data and logs directories
mkdir -p /mnt/ephemeral/logstash/lib
mkdir -p /mnt/ephemeral/logstash/log
chown -R logstash:logstash /mnt/ephemeral/logstash
echo "Options and volumes for logstash." >> /tmp/deploy.log

# Configuring logstash.yml
cat > /etc/logstash/logstash.yml << 'EOF'
path.data: /mnt/ephemeral/logstash/lib
path.logs: /mnt/ephemeral/logstash/log
path.config: /etc/logstash/conf.d/*.conf
EOF

}

start_logstash(){
    # Starting Logstash
    service logstash restart
    echo "Started logstash." >> /tmp/deploy.log
}

disable_elk_repos(){
    # Disable repositories
    sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
}

main(){
    check_root
    create_ssh_user
    if [[ `echo $elastic_version | cut -d'.' -f1` -ge 7 ]]; then
        install_java
    fi
    import_elk_repo
    install_elasticsearch
    configuring_elasticsearch
    start_elasticsearch
    if [[ `echo $elastic_version | cut -d'.' -f1` -ge 7 ]]; then
        add_logstash
        start_logstash
    fi
    disable_elk_repos
}

main