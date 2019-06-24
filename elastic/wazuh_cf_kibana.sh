#!/bin/bash
# Install Kibana instance using Cloudformation template
# Support for Amazon Linux

echo "Starting process." >> /tmp/log

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

install_kibana(){
# Installing Kibana
yum -y install kibana-${elastic_version}
chkconfig --add kibana
echo "Kibana installed." >> /tmp/log
}

kibana_certs(){
  echo "certs " >> /tmp/log
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
  sed -i "s/^server.ssl.enabled: false/server.ssl.enabled: true/" /etc/kibana/kibana.yml
}

configure_kibana(){
# Configuring kibana.yml
cat > /etc/kibana/kibana.yml << EOF
elasticsearch.hosts: ["https://10.0.2.124:9200"]
server.port: 5601
server.host: "$eth0_ip"
server.ssl.enabled: false
xpack.security.enabled: true
elasticsearch.username: "elastic"
elasticsearch.password: "$ssh_password"
EOF
echo "Kibana.yml configured." >> /tmp/log

# Allow Kibana to listen on privileged ports
setcap 'CAP_NET_BIND_SERVICE=+eip' /usr/share/kibana/node/bin/node
echo "Setcap executed" >> /tmp/log

# Configuring Kibana default settings
cat > /etc/default/kibana << 'EOF'
ser="kibana"
group="kibana"
chroot="/"
chdir="/"
nice=""
KILL_ON_STOP_TIMEOUT=0
NODE_OPTIONS="--max-old-space-size=4096"
EOF
echo "/etc/default/kibana completed" >> /tmp/log
}


get_plugin_url(){
  if [[ ${EnvironmentType} == 'staging' ]]
  then
    # Adding Wazuh pre_release repository
  plugin_url="https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-${wazuh_major}.${wazuh_minor}.${wazuh_patch}_${elastic_major_version}.${elastic_minor_version}.${elastic_patch_version}.zip"
  elif [[ ${EnvironmentType} == 'production' ]]
  then
  plugin_url="https://packages.wazuh.com/wazuhapp/wazuhapp-${wazuh_major}.${wazuh_minor}.${wazuh_patch}_${elastic_major_version}.${elastic_minor_version}.${elastic_patch_version}.zip"
  elif [[ ${EnvironmentType} == 'devel' ]]
  then
  plugin_url="https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-${wazuh_major}.${wazuh_minor}.${wazuh_patch}_${elastic_major_version}.${elastic_minor_version}.${elastic_patch_version}.zip"
  else
    echo 'no repo' >> /tmp/stage
  fi
}

install_plugin(){
  echo "Installing app" >> /tmp/log
  /usr/share/kibana/bin/kibana-plugin install ${plugin_url}
  echo "App installed!" >> /tmp/log
}

add_api(){
echo "Adding Wazuh API" >> /tmp/log
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
  echo "Loaded Wazuh API to an Elasticsearch >=v7 cluster" >> /tmp/log
fi

rm -f ${api_config}
echo "Configured API" >> /tmp/log
}

start_kibana(){
  # Starting Kibana
  systemctl restart kibana
  sleep 60
  echo "Started Kibana" >> /tmp/log
}

kibana_optional_configs(){
echo "Configuring Kibana options" >> /tmp/log

# Enabling extensions
sed -i "s/#extensions.docker    : false/extensions.docker : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.aws    : false/extensions.aws : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.osquery    : false/extensions.osquery : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.oscap    : false/extensions.oscap : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.virustotal    : false/extensions.virustotal : true/" /usr/share/kibana/plugins/wazuh/config.yml

# Configuring default index pattern for Kibana
default_index="/tmp/default_index.json"

cat > ${default_index} << EOF
{
  "changes": {
    "defaultIndex": "wazuh-alerts-3.x-*"
  }
}
EOF

echo "Waiting for Kibana service..." >> /tmp/deploy.log
until curl -XGET "https://$eth0_ip:5601/api/status" -k -u elastic:${ssh_password}; do
    sleep 5
    echo "Kibana not ready yet..." >> /tmp/deploy.log
done

curl -POST "https://$eth0_ip:5601/api/kibana/settings" -u elastic:${ssh_password} -k -H "Content-Type: application/json" -H "kbn-xsrf: true" -d@${default_index}
rm -f ${default_index}
echo "Set up default Index pattern." >> /tmp/log

# Configuring Kibana TimePicker
curl -POST "https://$eth0_ip:5601/api/kibana/settings" -u elastic:${ssh_password} -k -H "Content-Type: application/json" -H "kbn-xsrf: true" -d \
'{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'
echo "Set up default timepicker." >> /tmp/log

# Do not ask user to help providing usage statistics to Elastic
curl -POST "https://$eth0_ip:5601/api/telemetry/v1/optIn" -u elastic:${ssh_password} -k -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{"enabled":false}'
echo  "Do not ask user to help providing usage statistics to Elastic" >> /tmp/log

# Disable Elastic repository
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
echo "Configured Kibana" >> /tmp/log
}

add_nginx(){

echo "Installing NGINX..." >> /tmp/log
# Install Nginx ang generate certificates
sudo amazon-linux-extras install nginx1.12
mkdir -p /etc/ssl/certs /etc/ssl/private
openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/kibana.key -out /etc/ssl/certs/kibana.pem
echo "Installed NGINX." >> /tmp/log

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
echo "Restarted NGINX..." >> /tmp/log

}

main(){
  check_root
  create_ssh_user
  import_elk_repo
  install_kibana
  configure_kibana
  kibana_certs
  get_plugin_url
  install_plugin
  start_kibana
  add_api
  kibana_optional_configs
  add_nginx
}

main