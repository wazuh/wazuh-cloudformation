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

extract_certs(){
  amazon-linux-extras install epel -y
  yum install -y sshpass
  echo $ssh_password >> pass

  while [ ! -f /home/wazuh/certs.zip ]; do
    sshpass -f pass scp -o "StrictHostKeyChecking=no" wazuh@10.0.2.114:/home/wazuh/certs.zip /home/wazuh/ 2> /dev/null
    sleep 10
  done
  echo "Extract certs " >> /tmp/deploy.log
  rm pass -f
  cp /home/wazuh/certs.zip .
  unzip certs.zip
}


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
  echo "Waiting for Kibana service..." >> /tmp/deploy.log
  until curl -XGET "https://$eth0_ip:5601" -k -u elastic:${ssh_password}; do
      sleep 5
      echo "Kibana not ready yet..." >> /tmp/deploy.log
  done
  echo "Kibana is up" >> /tmp/deploy.log
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
  - "10.0.2.113"
  - "10.0.2.114"
  - "10.0.2.115"
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
    cp /kibana/* /etc/elasticsearch/certs/ -R
    cp /ca /etc/elasticsearch/certs/ -R
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
    systemctl stop elasticsearch
}


install_kibana(){
# Installing Kibana
yum -y install kibana-${elastic_version}
chkconfig --add kibana
echo "Kibana installed." >> /tmp/deploy.log
}

kibana_certs(){
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

configure_kibana(){
# Configuring kibana.yml
touch /var/log/kibana.log
chmod 777 /var/log/kibana.log
echo "logging.dest: /var/log/kibana.log" >> /etc/kibana/kibana.yml
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
  if [[ ${EnvironmentType} == 'production' ]]
  then
  plugin_url="https://packages.wazuh.com/wazuhapp/wazuhapp-${wazuh_major}.${wazuh_minor}.${wazuh_patch}_${elastic_major_version}.${elastic_minor_version}.${elastic_patch_version}.zip"
  elif [[ ${EnvironmentType} == 'sources' ]]
  then
    BRANCH="3.12-7.6"
    if [[ $BRANCH != "" ]]; then
      yum install -y git
      curl --silent --location https://rpm.nodesource.com/setup_10.x | bash -
      # Installing NodeJS
      yum -y install nodejs
      npm install -g yarn@1.10.1
      git clone https://github.com/wazuh/wazuh-kibana-app -b $BRANCH --single-branch --depth=1 app
      cd app
      yarn
      yarn build 2> /dev/null
      # This command returns several errors, we workaround this by executing it twice
      yarn build 2> /dev/null
      # The built backage is under /build
      cd build
      BUILD_SRC=$(pwd)
      APP_FILE=$(ls *.zip)
    else
      echo 'Error: Unsupported Wazuh Plugin installation method' >> /tmp/deploy.log
    fi
  else
    echo 'no repo' >> /tmp/stage
  fi
}

install_plugin(){
  echo "Installing app" >> /tmp/deploy.log
  if [[ ${EnvironmentType} != 'sources' ]] || [[ ${BRANCH} == "" ]]
  then
    cd /usr/share/kibana
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install ${plugin_url}
  else
    cd /usr/share/kibana
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install file://$BUILD_SRC/$APP_FILE
  fi
  cd /tmp
  echo "App installed!" >> /tmp/deploy.log
}

optimize_kibana(){
  echo "Optimizing app" >> /tmp/deploy.log
  cd /usr/share/kibana
  NODE_OPTIONS="--max-old-space-size=3072" /usr/share/kibana/bin/kibana --optimize --allow-root > /var/log/kibana_error.log
  echo "App optimized!" >> /tmp/deploy.log
}

add_api(){
echo "Adding Wazuh API" >> /tmp/deploy.log
sed -ie '/- default:/,+4d' /usr/share/kibana/optimize/wazuh/config/wazuh.yml
cat > /usr/share/kibana/optimize/wazuh/config/wazuh.yml << EOF
hosts:
  - default:
      url: https://${wazuh_master_ip}
      port: ${wazuh_api_port}
      user: ${wazuh_api_user}
      password: ${wazuh_api_password}
EOF
echo "Configured API" >> /tmp/deploy.log
}

enable_kibana(){
    echo "Enabling Kibana..." >> /tmp/deploy.log
    systemctl enable kibana
    if [ $? -eq0 ]; then
        echo "Kibana enabled." >> /tmp/deploy.log
    else
        echo "Could not enable Kibana" >> /tmp/deploy.log
    fi
}

start_kibana(){
  # Starting Kibana
  systemctl restart kibana
  await_kibana_ssl

}

kibana_optional_configs(){
sleep 500
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

# Remove Montserrat font
sed -i 's/@import\surl.*Montserrat.*/# Removed montserrat font/g' /usr/share/kibana/optimize/bundles/login.style.css

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


main(){
  check_root
  create_ssh_user
  import_elk_repo
  install_elasticsearch
  extract_certs
  configuring_elasticsearch
  create_bootstrap_user
  set_security
  start_elasticsearch
  install_kibana
  configure_kibana
  kibana_certs
  get_plugin_url
  install_plugin
  optimize_kibana
  enable_kibana
  start_kibana
  sleep 60
  add_api
  kibana_optional_configs
  start_kibana
  add_nginx
  echo "Deploy finished" >> /tmp/deploy.log
  systemctl start elasticsearch
}

main