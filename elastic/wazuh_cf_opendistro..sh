#!/bin/bash
# Install Elastic data node using Cloudformation template

touch /tmp/deploy.log

echo "OpenDistro: Starting process." > /tmp/deploy.log
ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
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
    yum install java-11-openjdk-devel
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