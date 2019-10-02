#!/bin/bash
# Install Kibana instance using Cloudformation template
# Support for Amazon Linux

echo "Starting process." >> /tmp/deploy.log

ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)

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

await_kibana(){
  echo "Waiting for Kibana service..." >> /tmp/deploy.log
  until curl -XGET "http://$eth0_ip:5601" -k -u elastic:${ssh_password}; do
      sleep 5
      echo "Kibana not ready yet..." >> /tmp/deploy.log
  done
  echo "Kibana is up" >> /tmp/deploy.log
}

import_opendistro_repo(){
# Configuring Elastic repository
curl https://d3g5vo6xdbdb9a.cloudfront.net/yum/opendistroforelasticsearch-artifacts.repo -o /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo
echo "Added OpenDistro repo." >> /tmp/deploy.log
}

install_java(){
    amazon-linux-extras install java-openjdk11 
}

# Installing ELK coordinating only mode
install_opendistro(){
    echo "Installing OpenDistro." >> /tmp/deploy.log
    # Installing OpenDistro
    yum install opendistroforelasticsearch-1.2.0 -y
    echo "Installed OpenDistro." >> /tmp/deploy.log
}

start_opendistro(){
    systemctl start elasticsearch.service
}


install_kibana(){
  # Installing Kibana
  yum install opendistroforelasticsearch-kibana -y
  echo "Kibana installed." >> /tmp/deploy.log
}

start_kibana(){
  # Starting Kibana
  systemctl restart kibana
  await_kibana
}


main(){
  check_root
  create_ssh_user
  import_opendistro_repo
  install_java
  install_opendistro
  configuring_elasticsearch
  start_opendistro
  install_kibana
  start_kibana
}

main