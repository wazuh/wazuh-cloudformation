#!/bin/bash
# Install Elastic data node using Cloudformation template

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
master_ip=$(cat /tmp/wazuh_cf_settings | grep '^MasterIp:' | cut -d' ' -f2)
worker_ip=$(cat /tmp/wazuh_cf_settings | grep '^WorkerIp:' | cut -d' ' -f2)
kibana_ip=$(cat /tmp/wazuh_cf_settings | grep '^KibanaIp:' | cut -d' ' -f2)

TAG="v3.12.0"
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

install_elasticsearch(){
    echo "Installing Elasticsearch." >> /tmp/deploy.log
    # Installing Elasticsearch
    yum -y install elasticsearch-${elastic_version}
    chkconfig --add elasticsearch
    echo "Installed Elasticsearch." >> /tmp/deploy.log
}

configuring_elasticsearch(){
echo "Configuring elasticsearch." >> /tmp/deploy.log

# Creating data and logs directories
mkdir -p /mnt/ephemeral/elasticsearch/lib
mkdir -p /mnt/ephemeral/elasticsearch/log
chown -R elasticsearch:elasticsearch /mnt/ephemeral/elasticsearch
echo "Created volumes in ephemeral." >> /tmp/deploy.log

cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: "wazuh_elastic"
node.name: "node-$node_name"
node.master: true
path.data: /mnt/ephemeral/elasticsearch/lib
path.logs: /mnt/ephemeral/elasticsearch/log
cluster.initial_master_nodes:
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
enable_elasticsearch
start_elasticsearch
}

load_template(){
    echo "Loading template..." >> /tmp/deploy.log
    until curl -XGET "https://$eth0_ip:9200" -k -u elastic:${ssh_password}; do
        sleep 5
        echo "Elasticsearch not ready yet..." >> /tmp/deploy.log
    done

    url_alerts_template="https://raw.githubusercontent.com/wazuh/wazuh/${TAG}/extensions/elasticsearch/7.x/wazuh-template.json"
    alerts_template="/tmp/wazuh-template.json"
    curl -Lo ${alerts_template} ${url_alerts_template}
    curl -XPUT "https://${eth0_ip}:9200/_template/wazuh" -k -u elastic:${ssh_password} -H 'Content-Type: application/json' -d@${alerts_template}
    curl -XDELETE "https://${eth0_ip}:9200/wazuh-alerts-*" -k -u elastic:${ssh_password}
    # Correct owner for Elasticsearch directories
    echo "Added template." >> /tmp/deploy.log
}

add_wazuh_user(){

until curl -XGET "https://$eth0_ip:9200" -k -u elastic:${ssh_password}; do
  sleep 5
  echo "Elasticsearch not ready yet..." >> /tmp/deploy.log
done
user_config='/tmp/userconfig'
cat > ${user_config} << EOF
{
  "password": "${ssh_password}",
  "roles" : [ "superuser" ]
}
EOF
  # Create wazuh user
  curl -XPOST "https://$eth0_ip:9200/_security/user/wazuh" -k -u elastic:${ssh_password} -d@${user_config} -H 'Content-Type: application/json'

}

enable_elasticsearch(){
    echo "Enabling elasticsearch..." >> /tmp/deploy.log
    systemctl enable elasticsearch
    if [ $? -eq0 ]; then
        echo "Elasticsearch enabled." >> /tmp/deploy.log
    else
        echo "Could not enable Elasticsearch" >> /tmp/deploy.log
    fi
}

start_elasticsearch(){
    echo "Starting Elasticsearch and setting permissions" >> /tmp/deploy.log
    chown elasticsearch:elasticsearch -R /etc/elasticsearch
    chown elasticsearch:elasticsearch -R /usr/share/elasticsearch
    chown elasticsearch:elasticsearch -R /var/lib/elasticsearch
    systemctl daemon-reload
    # Starting Elasticsearch
    echo "daemon-reload." >> /tmp/deploy.log
    systemctl restart elasticsearch
    echo "Started elasticsearch service." >> /tmp/deploy.log
    systemctl status elasticsearch >> /tmp/deploy.log
}

create_bootstrap_user(){
    echo "Creating elk user with password $ssh_password" >> /tmp/deploy.log
    echo $ssh_password | /usr/share/elasticsearch/bin/elasticsearch-keystore add -x 'bootstrap.password'
    systemctl restart elasticsearch
    sleep 60
    echo 'Done' >> /tmp/deploy.log
}

set_security(){
echo "Setting security in Elasticsearch bootstrap node" >> /tmp/deploy.log
cat > /usr/share/elasticsearch/instances.yml << EOF
instances:
    - name: "wazuh-manager"
      ip:
        - "$master_ip"
    - name: "wazuh-worker"
      ip:
        - "$worker_ip"
    - name: "kibana"
      ip:
        - "$kibana_ip"
    - name: "elastic-node2"
      ip:
        - "10.0.2.125"
    - name: "elastic-node1"
      ip:
        - "10.0.2.123"
    - name: "elasticsearch"
      ip:
        - "$eth0_ip"
EOF
/usr/share/elasticsearch/bin/elasticsearch-certutil cert ca --pem --in /usr/share/elasticsearch/instances.yml --out /usr/share/elasticsearch/certs.zip
echo "Generated certs" >> /tmp/deploy.log
cp /usr/share/elasticsearch/certs.zip /home/wazuh/
chown wazuh:wazuh /home/wazuh/certs.zip
cp /usr/share/elasticsearch/certs.zip .
unzip certs.zip
mkdir /etc/elasticsearch/certs/ca -p
cp ca/ca.crt /etc/elasticsearch/certs/ca
cp elasticsearch/elasticsearch.crt /etc/elasticsearch/certs
chmod -R 770 /etc/elasticsearch/certs
cp elasticsearch/elasticsearch.key /etc/elasticsearch/certs
echo "xpack.security.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.transport.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.transport.ssl.verification_mode: certificate" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.transport.ssl.key: /etc/elasticsearch/certs/elasticsearch.key" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.transport.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.transport.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]" >> /etc/elasticsearch/elasticsearch.yml
echo "# HTTP layer" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.http.ssl.enabled: true" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.http.ssl.verification_mode: certificate" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.http.ssl.key: /etc/elasticsearch/certs/elasticsearch.key" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.http.ssl.certificate: /etc/elasticsearch/certs/elasticsearch.crt" >> /etc/elasticsearch/elasticsearch.yml
echo "xpack.security.http.ssl.certificate_authorities: [ "/etc/elasticsearch/certs/ca/ca.crt" ]" >> /etc/elasticsearch/elasticsearch.yml
chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs
echo "Starting elasticsearch"
}

disable_elk_repos(){
    # Disable repositories
    sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
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
    #load_template
    add_wazuh_user
    disable_elk_repos
}

main