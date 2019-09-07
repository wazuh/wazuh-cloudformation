#!/bin/bash
# Install Kibana instance using Cloudformation template
# Support for Amazon Linux

echo "Starting process." >> /tmp/deploy.log

ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
kibana_port=$(cat /tmp/wazuh_cf_settings | grep '^KibanaPort:' | cut -d' ' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet' | head -1 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f2)
wazuh_master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
wazuh_api_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiPort:' | cut -d' ' -f2)
EnvironmentType=$(cat /tmp/wazuh_cf_settings | grep '^EnvironmentType:' | cut -d' ' -f2)
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
elastic_minor_version=$(echo ${elastic_version} | cut -d'.' -f2)
elastic_patch_version=$(echo ${elastic_version} | cut -d'.' -f3)

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

await_kibana_ssl(){
  echo "Waiting for Kibana service..."
  status_ssl='x'
  until [ "$status_ssl" == '' ]; do
    health=`curl "https://$eth0_ip:5601" -k -u elastic:$ssh_password`
    echo $health > status_ssl
    curl "https://$eth0_ip:5601" -k -u elastic:$ssh_password 2> status_ssl
    status_ssl=`cat status_ssl`
    echo "Kibana not ready yet..."
    sleep 1
  done
  echo "Done"
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

# Installing ELK coordinating only mode
install_elasticsearch(){
    echo "Installing Elasticsearch." >> /tmp/deploy.log
    # Installing Elasticsearch
    yum -y install elasticsearch-${elastic_version}
    chkconfig --add elasticsearch
    echo "Installed Elasticsearch." >> /tmp/deploy.log
}

configuring_elasticsearch(){
mkdir -p /mnt/ephemeral/elasticsearch/lib
mkdir -p /mnt/ephemeral/elasticsearch/log
chown -R elasticsearch:elasticsearch /mnt/ephemeral/elasticsearch

echo "Created volumes in ephemeral." >> /tmp/deploy.log
cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: "wazuh_elastic"
node.name: "coordinating_node"
path.data: /mnt/ephemeral/elasticsearch/lib
path.logs: /mnt/ephemeral/elasticsearch/log
node.master: false
node.data: false
node.ingest: false
discovery.seed_hosts: 
  - "10.0.2.123"
  - "10.0.2.124"
  - "10.0.2.125"
EOF

echo "network.host: $eth0_ip" >> /etc/elasticsearch/elasticsearch.yml

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
# restarting elasticsearch after changes
}

set_security(){

    mkdir -p /etc/elasticsearch/certs
    cp /etc/kibana/certs/* /etc/elasticsearch/certs/ -R
    echo "xpack.security.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.verification_mode: certificate" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.key: "/etc/elasticsearch/certs/kibana.key"" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/kibana.crt" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]" >> /etc/elasticsearch/elasticsearch.yml
    echo "# HTTP layer" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.verification_mode: certificate" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.key: "/etc/elasticsearch/certs/kibana.key"" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/kibana.crt" >> /etc/elasticsearch/elasticsearch.yml
    echo "xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]" >> /etc/elasticsearch/elasticsearch.yml
    echo "Configured security." >> /tmp/deploy.log
    chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs
    echo "Changed permissions certs directory." >> /tmp/deploy.log
}

create_bootstrap_user(){
    echo "Creating elk user with password $ssh_password" >> /tmp/deploy.log
    echo $ssh_password | /usr/share/elasticsearch/bin/elasticsearch-keystore add -x 'bootstrap.password'
    systemctl restart elasticsearch
    echo 'Done' >> /tmp/deploy.log
}

start_elasticsearch(){
    echo "start_elasticsearch." >> /tmp/deploy.log
    # Correct owner for Elasticsearch directories
    chown elasticsearch:elasticsearch -R /etc/elasticsearch
    chown elasticsearch:elasticsearch -R /usr/share/elasticsearch
    chown elasticsearch:elasticsearch -R /var/lib/elasticsearch
    systemctl daemon-reload
    # Starting Elasticsearch
    echo "daemon-reload." >> /tmp/deploy.log
    systemctl restart elasticsearch
    echo "done with starting elasticsearch service." >> /tmp/deploy.log
}


install_kibana(){
# Installing Kibana
yum -y install kibana-${elastic_version}
chkconfig --add kibana
echo "Kibana installed." >> /tmp/deploy.log
}

kibana_certs(){
  echo "certs " >> /tmp/deploy.log
  amazon-linux-extras install epel -y
  yum install -y sshpass
  sleep 500
  echo $ssh_password >> pass
  sshpass -f pass scp -o "StrictHostKeyChecking=no" wazuh@10.0.2.124:/home/wazuh/certs.zip /home/wazuh/
  rm pass -f
  cp /home/wazuh/certs.zip .
  unzip certs.zip
  mkdir /etc/kibana/certs/ca -p
  cp ca/ca.crt /etc/kibana/certs/ca
  cp kibana/kibana.crt /etc/kibana/certs
  cp kibana/kibana.key /etc/kibana/certs
  chown -R kibana: /etc/kibana/certs
  chmod -R 770 /etc/kibana/certs
  echo "# Elasticsearch from/to Kibana" >> /etc/kibana/kibana.yml
  echo "elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca/ca.crt"]" >> /etc/kibana/kibana.yml
  echo "elasticsearch.ssl.certificate: "/etc/kibana/certs/kibana.crt"" >> /etc/kibana/kibana.yml
  echo "elasticsearch.ssl.key: "/etc/kibana/certs/kibana.key"" >> /etc/kibana/kibana.yml
  echo "# Browser from/to Kibana" >> /etc/kibana/kibana.yml
  echo "server.ssl.enabled: true" >> /etc/kibana/kibana.yml
  echo "server.ssl.certificate: "/etc/kibana/certs/kibana.crt"" >> /etc/kibana/kibana.yml
  echo "server.ssl.key: "/etc/kibana/certs/kibana.key"" >> /etc/kibana/kibana.yml
}

redirect_app(){
    await_kibana_ssl
    # Set Wazuh app as the default landing page
    echo "server.defaultRoute: /app/wazuh"  >> /etc/kibana/kibana.yml
 
    # Redirect Kibana welcome screen to Discover
    echo "Redirect Kibana welcome screen to Discover"
    sed -i "s:'/app/kibana#/home':'/app/wazuh':g" /usr/share/kibana/src/ui/public/chrome/directives/global_nav/global_nav.html
    sed -i "s:'/app/kibana#/home':'/app/wazuh':g" /usr/share/kibana/src/ui/public/chrome/directives/header_global_nav/header_global_nav.js
}

configure_kibana(){
# Configuring kibana.yml
cat > /etc/kibana/kibana.yml << EOF
elasticsearch.hosts: ["https://$eth0_ip:9200"]
server.port: 5601
server.host: "$eth0_ip"
xpack.security.enabled: true
elasticsearch.username: "elastic"
elasticsearch.password: "$ssh_password"
EOF
echo "Kibana.yml configured." >> /tmp/deploy.log

# Allow Kibana to listen on privileged ports
setcap 'CAP_NET_BIND_SERVICE=+eip' /usr/share/kibana/node/bin/node
echo "Setcap executed" >> /tmp/deploy.log

}


get_plugin_url(){
  if [[ ${EnvironmentType} == 'staging' ]]
  then
    # Adding Wazuh pre_release repository
  plugin_url="https://packages-dev.wazuh.com/staging/app/kibana/wazuhapp-${wazuh_major}.${wazuh_minor}.${wazuh_patch}_${elastic_major_version}.${elastic_minor_version}.${elastic_patch_version}-rc2.zip"
  elif [[ ${EnvironmentType} == 'production' ]]
  then
  plugin_url="https://packages.wazuh.com/wazuhapp/wazuhapp-${wazuh_major}.${wazuh_minor}.${wazuh_patch}_${elastic_major_version}.${elastic_minor_version}.${elastic_patch_version}.zip"
  elif [[ ${EnvironmentType} == 'devel' ]]
  then
  plugin_url="https://packages-dev.wazuh.com/staging/app/kibana/wazuhapp-${wazuh_major}.${wazuh_minor}.${wazuh_patch}_${elastic_major_version}.${elastic_minor_version}.${elastic_patch_version}-rc2.zip"
  else
    echo 'no repo' >> /tmp/stage
  fi
}

install_plugin(){
  echo "Installing app" >> /tmp/deploy.log
  sudo -u kibana /usr/share/kibana/bin/kibana-plugin install ${plugin_url}
  echo "App installed!" >> /tmp/deploy.log
}

add_api(){
echo "Adding Wazuh API" >> /tmp/deploy.log
api_config="/tmp/api_config.json"
api_time=$(($(date +%s%N)/1000000))
wazuh_api_password_base64=`echo -n ${wazuh_api_password} | base64`

cat > ${api_config} << EOF
{
  "api_user": "${wazuh_api_user}",
  "api_password": "${wazuh_api_password_base64}",
  "url": "https://${wazuh_master_ip}",
  "api_port": "${wazuh_api_port}",
  "insecure": "false",
  "component": "API",
  "cluster_info": {
    "manager": "wazuh-manager",
    "cluster": "disabled",
    "status": "disabled"
  }
}
EOF

CONFIG_CODE=$(curl -s -o /dev/null -w "%{http_code}" -XGET "https://10.0.2.124:9200/.wazuh/_doc/${api_time}" -u elastic:${ssh_password} -k)
if [ "x$CONFIG_CODE" != "x200" ]; then
  curl -s -XPUT "https://10.0.2.124:9200/.wazuh/_doc/${api_time}" -u elastic:${ssh_password} -k -H 'Content-Type: application/json' -d@${api_config}
  echo "Loaded Wazuh API to an Elasticsearch >=v7 cluster" >> /tmp/deploy.log
fi

rm -f ${api_config}
echo "Configured API" >> /tmp/deploy.log
}

start_kibana(){
  # Starting Kibana
  systemctl restart kibana
  await_kibana_ssl

}

kibana_optional_configs(){
echo "Configuring Kibana options" >> /tmp/deploy.log

# Configuring default index pattern for Kibana
default_index="/tmp/default_index.json"

cat > ${default_index} << EOF
{
  "changes": {
    "defaultIndex": "wazuh-alerts-3.x-*"
  }
}
EOF

await_kibana_ssl
# Configuring Kibana TimePicker
curl -XPOST "https://$eth0_ip:5601/api/kibana/settings" -k -u elastic:${ssh_password} -H "Content-Type: application/json" -H "kbn-xsrf: true" -d \
'{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}' >> /tmp/deploy.log
echo "Set up default timepicker." >> /tmp/deploy.log

curl -XPOST "https://$eth0_ip:5601/api/kibana/settings" -k -u elastic:${ssh_password} -H "Content-Type: application/json" -H "kbn-xsrf: true" -d@${default_index} >> /tmp/deploy.log
rm -f ${default_index}
echo "Set up default Index pattern." >> /tmp/deploy.log

# Do not ask user to help providing usage statistics to Elastic
curl -XPOST "https://$eth0_ip:5601/api/telemetry/v2/optIn" -k -u elastic:${ssh_password} -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{"enabled":false}' >> /tmp/deploy.log
echo  "Do not ask user to help providing usage statistics to Elastic" >> /tmp/deploy.log

# Disable Elastic repository
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
echo "Configured Kibana" >> /tmp/deploy.log
}

add_nginx(){

echo "Installing NGINX..." >> /tmp/deploy.log
# Install Nginx ang generate certificates
sudo amazon-linux-extras install nginx1.12
mkdir -p /etc/ssl/certs /etc/ssl/private
openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/kibana.key -out /etc/ssl/certs/kibana.pem
echo "Installed NGINX." >> /tmp/deploy.log

# Installing htpasswd (needed for Amazon Linux)
yum install httpd-tools-2.4.33-2.amzn2.0.2.x86_64 -y

# Configure Nginx
cat > /etc/nginx/conf.d/kibana.conf << EOF
server {
    listen ${kibana_port} default_server;
    listen            [::]:${kibana_port};
    access_log            /var/log/nginx/nginx.access.log;
    error_log            /var/log/nginx/nginx.error.log;
    location / {
        proxy_pass https://$eth0_ip:5601/;
    }
}
EOF

# Starting Nginx
systemctl restart nginx
echo "Restarted NGINX..." >> /tmp/deploy.log

}

custom_welcome(){
  await_kibana_ssl
  echo "custom_welcome " >> /tmp/deploy.log
  unalias cp
  curl https://s3.amazonaws.com/wazuh.com/wp-content/uploads/demo/custom-welcome.tar.gz --output custom.tar.gz
  tar xvf custom.tar.gz
  cp custom_welcome/wazuh_wazuh_bg.svg /usr/share/kibana/optimize/bundles/
  cp custom_welcome/wazuh_logo_circle.svg /usr/share/kibana/optimize/bundles/
  sed -i 's|Welcome to Kibana|Welcome to Wazuh|g' /usr/share/kibana/optimize/bundles/commons.bundle.js
  sed -i 's|Welcome to Kibana|Welcome to Wazuh|g' /usr/share/kibana/optimize/bundles/login.bundle.js
  sed -i 's|Welcome to Kibana|Welcome to Wazuh|g' /usr/share/kibana/optimize/bundles/kibana.bundle.js
  sed -i 's|Your window into the Elastic Stack|The Open Source Security Platform|g' /usr/share/kibana/optimize/bundles/kibana.bundle.js
  sed -i 's|Your window into the Elastic Stack|The Open Source Security Platform|g' /usr/share/kibana/optimize/bundles/login.bundle.js
  cp custom_welcome/login.style.css /usr/share/kibana/optimize/bundles/login.style.css -f
  chown kibana:kibana /usr/share/kibana/optimize/bundles/ -R
}

main(){
  check_root
  create_ssh_user
  import_elk_repo
  install_elasticsearch
  configuring_elasticsearch
  create_bootstrap_user
  set_security
  start_elasticsearch
  install_kibana
  configure_kibana
  kibana_certs
  get_plugin_url
  install_plugin
  start_kibana
  add_api
  kibana_optional_configs
  add_nginx
  custom_welcome
  redirect_app
}

main