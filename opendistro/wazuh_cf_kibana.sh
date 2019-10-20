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

configure_kibana(){
  echo "server.host: 0.0.0.0" >> /etc/kibana/kibana.yml
  echo "server.port: 443" >> /etc/kibana/kibana.yml  
  setcap 'CAP_NET_BIND_SERVICE=+eip' /usr/share/kibana/node/bin/node
}

start_kibana(){
  # Starting Kibana
  systemctl restart kibana
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