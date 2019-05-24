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
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
node_name=$(cat /tmp/wazuh_cf_settings | grep '^NodeName:' | cut -d' ' -f2)

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

}

configuring_elasticsearch(){
# Creating data and logs directories
mkdir -p /mnt/ephemeral/elasticsearch/lib
mkdir -p /mnt/ephemeral/elasticsearch/log
chown -R elasticsearch:elasticsearch /mnt/ephemeral/elasticsearch
echo "Created volumes in ephemeral." >> /tmp/log

cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: "node-$node_name"
node.name: "es-node-1"
node.master: true
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
cluster.initial_master_nodes: 
  - "10.0.0.10"
  - "10.0.0.20"
  - "10.0.0.30"
EOF

echo "network.host: $eth0_ip" >> /etc/elasticsearch/elasticsearch.yml

# Correct owner for Elasticsearch directories
chown elasticsearch:elasticsearch -R /etc/elasticsearch
chown elasticsearch:elasticsearch -R /usr/share/elasticsearch
chown elasticsearch:elasticsearch -R /var/lib/elasticsearch

# Calculating RAM for Elasticsearch
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
ram=$(( ${ram_gb} / 2 ))
if [ $ram -eq "0" ]; then ram=1; fi
echo "Setting RAM." >> /tmp/log

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
echo "Setting JVM options." >> /tmp/log

mkdir -p /etc/systemd/system/elasticsearch.service.d/
echo '[Service]' > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf
echo 'LimitMEMLOCK=infinity' >> /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf


# Allowing unlimited memory allocation
echo 'elasticsearch soft memlock unlimited' >> /etc/security/limits.conf
echo 'elasticsearch hard memlock unlimited' >> /etc/security/limits.conf
echo "Setting memory lock options." >> /tmp/log
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
    if [[ `echo $elastic_version | cut -d'.' -f1` -lt 7 ]]; then
        install_java
    fi
    import_elk_repo
    install_elasticsearch
    configuring_elasticsearch
    start_elasticsearch
    if [[ `echo $elastic_version | cut -d'.' -f1` -lt 7 ]]; then
        add_logstash
        start_logstash
    fi
    disable_elk_repos
}

main