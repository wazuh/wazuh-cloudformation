#!/bin/bash
# Install Kibana instance using Cloudformation template
# Support for Amazon Linux
touch /tmp/log
echo "Starting process." > /tmp/log

ssh_username=$(cat /tmp/wazuh_cf_settings | grep '^SshUsername:' | cut -d' ' -f2)
ssh_password=$(cat /tmp/wazuh_cf_settings | grep '^SshPassword:' | cut -d' ' -f2)
elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
wazuh_major=`echo ${wazuh_version} | cut -d'.' -f 1`
kibana_port=$(cat /tmp/wazuh_cf_settings | grep '^KibanaPort:' | cut -d' ' -f2)
kibana_username=$(cat /tmp/wazuh_cf_settings | grep '^KibanaUsername:' | cut -d' ' -f2)
kibana_password=$(cat /tmp/wazuh_cf_settings | grep '^KibanaPassword:' | cut -d' ' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet' | head -1 | sed -e 's/^[[:space:]]*//' | cut -d' ' -f2)
wazuh_master_ip=$(cat /tmp/wazuh_cf_settings | grep '^WazuhMasterIP:' | cut -d' ' -f2)
wazuh_api_user=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminUsername:' | cut -d' ' -f2)
wazuh_api_password=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiAdminPassword:' | cut -d' ' -f2)
wazuh_api_port=$(cat /tmp/wazuh_cf_settings | grep '^WazuhApiPort:' | cut -d' ' -f2)
echo "Added env vars." >> /tmp/log

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi
echo "Running as root." >> /tmp/log

# Creating SSH user
if ! id -u ${ssh_username} > /dev/null 2>&1; then adduser ${ssh_username}; fi
echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
service sshd restart

# Uninstall OpenJDK 1.7 if exists
if rpm -q java-1.7.0-openjdk > /dev/null; then yum -y remove java-1.7.0-openjdk; fi

# Install OpenJDK 1.8
yum -y install java-1.8.0-openjdk

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
echo "Added Elasticsearch repo." >> /tmp/log

# Installing Elasticsearch
yum -y install elasticsearch-${elastic_version}
chkconfig --add elasticsearch
echo "Installed Elasticsearch." >> /tmp/log

# Installing Elasticsearch plugin for EC2
/usr/share/elasticsearch/bin/elasticsearch-plugin install --batch discovery-ec2
echo "Installed EC2 plugin." >> /tmp/log

# Configuration file created by AWS Cloudformation template
mv -f /tmp/wazuh_cf_elasticsearch.yml /etc/elasticsearch/elasticsearch.yml
chown elasticsearch:elasticsearch /etc/elasticsearch/elasticsearch.yml
echo "Copying YML to elasticsearch folder." >> /tmp/log

# Calculating RAM for Elasticsearch
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
ram=$(( ${ram_gb} / 2 ))
if [ $ram -eq "0" ]; then ram=1; fi
echo "RAM parameters." >> /tmp/log

# Configuring jvm.options
cat > /etc/elasticsearch/jvm.options << EOF
-Xms${ram}g
-Xmx${ram}g
-XX:+UseConcMarkSweepGC
-XX:CMSInitiatingOccupancyFraction=75
-XX:+UseCMSInitiatingOccupancyOnly
-XX:+AlwaysPreTouch
-Xss1m
-Djava.awt.headless=true
-Dfile.encoding=UTF-8
-Djna.nosys=true
-XX:-OmitStackTraceInFastThrow
-Dio.netty.noUnsafe=true
-Dio.netty.noKeySetOptimization=true
-Dio.netty.recycler.maxCapacityPerThread=0
-Dlog4j.shutdownHookEnabled=false
-Dlog4j2.disable.jmx=true
-Djava.io.tmpdir=\${ES_TMPDIR}
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/lib/elasticsearch
-XX:ErrorFile=/var/log/elasticsearch/hs_err_pid%p.log
8:-XX:+PrintGCDetails
8:-XX:+PrintGCDateStamps
8:-XX:+PrintTenuringDistribution
8:-XX:+PrintGCApplicationStoppedTime
8:-Xloggc:/var/log/elasticsearch/gc.log
8:-XX:+UseGCLogFileRotation
8:-XX:NumberOfGCLogFiles=32
8:-XX:GCLogFileSize=64m
9-:-Xlog:gc*,gc+age=trace,safepoint:file=/var/log/elasticsearch/gc.log:utctime,pid,tags:filecount=32,filesize=64m
9-:-Djava.locale.providers=COMPAT
EOF

mkdir -p /etc/systemd/system/elasticsearch.service.d/
echo '[Service]' > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
echo 'LimitMEMLOCK=infinity' >> /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf

# Allowing unlimited memory allocation
echo 'elasticsearch soft memlock unlimited' >> /etc/security/limits.conf
echo 'elasticsearch hard memlock unlimited' >> /etc/security/limits.conf
echo "Setting memory lock options." >> /tmp/log

systemctl daemon-reload
echo "daemon-reload." >> /tmp/log

# Starting Elasticsearch
service elasticsearch start
sleep 60
echo "Started service." >> /tmp/log

# Loading and tuning Wazuh alerts template
url_alerts_template="https://raw.githubusercontent.com/wazuh/wazuh/3.9/extensions/elasticsearch/wazuh-elastic7-template-alerts.json"
alerts_template="/tmp/wazuh-elastic7-template-alerts.json"
curl -Lo ${alerts_template} ${url_alerts_template}
curl -XPUT "http://${eth0_ip}:9200/_template/wazuh" -H 'Content-Type: application/json' -d@${alerts_template}
curl -XDELETE "http://${eth0_ip}:9200/wazuh-alerts-*"
echo "Added template." >> /tmp/log

# Installing Kibana
yum -y install kibana-${elastic_version}
chkconfig --add kibana
echo "Kibana installed." >> /tmp/log

# Configuring kibana.yml
cat > /etc/kibana/kibana.yml << EOF
elasticsearch.url: "http://${eth0_ip}:9200"
server.port: 5601
server.host: "localhost"
server.ssl.enabled: false
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

# Installing Wazuh plugin for Kibana
plugin_url="https://packages-dev.wazuh.com/staging/app/kibana/wazuhapp-3.9.0_7.0.0-rc1.zip"
/usr/share/kibana/bin/kibana-plugin install ${plugin_url}
cat >> /usr/share/kibana/plugins/wazuh/config.yml << 'EOF'
wazuh.shards: 1
wazuh.replicas: 1
wazuh-version.shards: 1
wazuh-version.replicas: 1
wazuh.monitoring.shards: 1
wazuh.monitoring.replicas: 1
EOF
echo "App installed!" >> /tmp/log

# Configuring Wazuh API for Kibana plugin
api_config="/tmp/api_config.json"
api_time=$(($(date +%s%N)/1000000))
wazuh_api_password_base64=`echo -n ${wazuh_api_password} | base64`

# Enabling extensions
sed -i "s/#extensions.docker    : false/extensions.docker : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.aws    : false/extensions.aws : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.osquery    : false/extensions.osquery : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.oscap    : false/extensions.oscap : true/" /usr/share/kibana/plugins/wazuh/config.yml
sed -i "s/#extensions.virustotal    : false/extensions.virustotal : true/" /usr/share/kibana/plugins/wazuh/config.yml

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

curl -s -XPUT "http://${eth0_ip}:9200/.wazuh/${api_time}" -H 'Content-Type: application/json' -d@${api_config}
rm -f ${api_config}
echo "Configured API" >> /tmp/log

# Starting Kibana
service kibana start
sleep 60
echo "Started Kibana" >> /tmp/log

# Configuring default index pattern for Kibana
default_index="/tmp/default_index.json"

cat > ${default_index} << EOF
{
  "changes": {
    "defaultIndex": "wazuh-alerts-3.x-*"
  }
}
EOF

curl -POST "http://localhost:5601/api/kibana/settings" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d@${default_index}
rm -f ${default_index}

# Configuring Kibana TimePicker
curl -POST "http://localhost:5601/api/kibana/settings" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d \
'{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'

# Do not ask user to help providing usage statistics to Elastic
curl -POST "http://localhost:5601/api/telemetry/v1/optIn" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{"enabled":false}'

# Disable Elastic repository
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
echo "Configured Kibana" >> /tmp/log
echo "Installing NGINX..." >> /tmp/log

# Install Nginx ang generate certificates
sudo amazon-linux-extras install nginx1.12
mkdir -p /etc/ssl/certs /etc/ssl/private
openssl req -x509 -batch -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/kibana.key -out /etc/ssl/certs/kibana.pem
echo "Installed NGINX." >> /tmp/log

# Installing htpasswd (needed for Amazon Linux)
yum install httpd-tools-2.4.33-2.amzn2.0.2.x86_64 -y

# Configure Nginx
htpasswd -b -c /etc/nginx/conf.d/kibana.htpasswd ${kibana_username} ${kibana_password}
cat > /etc/nginx/conf.d/kibana.conf << EOF
server {
    listen ${kibana_port} default_server;
    listen            [::]:${kibana_port};
    access_log            /var/log/nginx/nginx.access.log;
    error_log            /var/log/nginx/nginx.error.log;
    location / {
        auth_basic "Restricted";
        auth_basic_user_file /etc/nginx/conf.d/kibana.htpasswd;
        proxy_pass http://127.0.0.1:5601/;
    }
}
EOF

# Starting Nginx
service nginx restart
echo "Restarted NGINX..." >> /tmp/log
