#!/bin/bash
# Install Elastic data node using Cloudformation template

touch /tmp/deploy.log

echo "OpenDistro: Starting process." > /tmp/deploy.log

check_root(){
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "NOT running as root. Exiting" >> /tmp/deploy.log
        echo "This script must be run as root"
        exit 1
    fi
    echo "Running as root." >> /tmp/deploy.log
}

import_opendistro_repo(){
# Configuring Elastic repository
curl https://d3g5vo6xdbdb9a.cloudfront.net/yum/opendistroforelasticsearch-artifacts.repo -o /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo

echo "Added OpenDistro repo." >> /tmp/deploy.log
}

install_opendistro(){
    echo "Installing OpenDistro." >> /tmp/deploy.log
    # Installing OpenDistro
    yum install opendistroforelasticsearch-1.2.0 -y
    echo "Installed OpenDistro." >> /tmp/deploy.log
    
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


    # Allowing unlimited memory allocation
    echo 'elasticsearch soft memlock unlimited' >> /etc/security/limits.conf
    echo 'elasticsearch hard memlock unlimited' >> /etc/security/limits.conf
}

install_java(){
    amazon-linux-extras install java-openjdk11 
}

start_opendistro(){
    systemctl start elasticsearch.service
}

main(){
    check_root
    create_ssh_user
    install_java
    import_opendistro_repo
    install_opendistro
    start_opendistro
}

main