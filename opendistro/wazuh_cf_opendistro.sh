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