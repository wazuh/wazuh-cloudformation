#!/bin/bash
# Install Elastic data node using Cloudformation template
# Support for Amazon Linux

set -exf

elastic_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f1)
wazuh_version=$(cat /tmp/wazuh_cf_settings | grep '^Elastic_Wazuh:' | cut -d' ' -f2 | cut -d'_' -f2)
eth0_ip=$(/sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2  | cut -d' ' -f1)

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# Mounting ephemeral partition
mkdir /mnt/ephemeral
mkfs -t ext4 /dev/nvme0n1
mount /dev/nvme0n1 /mnt/ephemeral
echo "/dev/nvme0n1 /mnt/ephemeral ext4 defaults,nofail 0 2" | tee -a /etc/fstab

# Downloading and installing JRE
url_jre="https://download.oracle.com/otn-pub/java/jdk/8u191-b12/2787e4a523244c269598db4e85c51e0c/jre-8u191-linux-x64.rpm"
jre_rpm="/tmp/jre-8-linux-x64.rpm"
curl -Lo ${jre_rpm} --header "Cookie: oraclelicense=accept-securebackup-cookie" ${url_jre}
rpm -qlp ${jre_rpm} > /dev/null 2>&1 || $(echo "Unable to download JRE. Exiting." && exit 1)
yum -y localinstall ${jre_rpm} && rm -f ${jre_rpm}

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

# Installing Elasticsearch
yum -y install elasticsearch-${elastic_version}
chkconfig --add elasticsearch

# Installing Elasticsearch plugin for EC2
/usr/share/elasticsearch/bin/elasticsearch-plugin install --batch discovery-ec2

# Creating data and logs directories
mkdir -p /mnt/ephemeral/elasticsearch/lib
mkdir -p /mnt/ephemeral/elasticsearch/log
chown -R elasticsearch:elasticsearch /mnt/ephemeral/elasticsearch

# Configuration file created by AWS Cloudformation template
# Because of it we set the right owner/group for the file
mv -f /tmp/wazuh_cf_elasticsearch.yml /etc/elasticsearch/elasticsearch.yml
chown elasticsearch:elasticsearch /etc/elasticsearch/elasticsearch.yml

# Calculating RAM for Elasticsearch
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
ram=$(( ${ram_gb} / 2 ))
if [ $ram -eq "0" ]; then ram=1; fi

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

# Allowing unlimited memory allocation
echo 'elasticsearch soft memlock unlimited' >> /etc/security/limits.conf
echo 'elasticsearch hard memlock unlimited' >> /etc/security/limits.conf

# Starting Elasticsearch
service elasticsearch start

#Installing Logstash
yum -y install logstash-${elastic_version}

#Wazuh configuration for Logstash
curl -so /etc/logstash/conf.d/01-wazuh.conf "https://raw.githubusercontent.com/wazuh/wazuh/v${wazuh_version}/extensions/logstash/01-wazuh-remote.conf"
sed -i "s/localhost:9200/${eth0_ip}:9200/" /etc/logstash/conf.d/01-wazuh.conf

# Creating data and logs directories
mkdir -p /mnt/ephemeral/logstash/lib
mkdir -p /mnt/ephemeral/logstash/log
chown -R logstash:logstash /mnt/ephemeral/logstash

# Configuring logstash.yml
cat > /etc/logstash/logstash.yml << 'EOF'
path.data: /mnt/ephemeral/logstash/lib
path.logs: /mnt/ephemeral/logstash/log
path.config: /etc/logstash/conf.d/*.conf
EOF

# Calculating RAM for Logstash
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
ram=$(( ${ram_gb} / 4 ))
if [ $ram -eq "0" ]; then ram=1; fi

# Configuring jvm.options
cat > /etc/logstash/jvm.options << EOF
-Xms${ram}g
-Xmx${ram}g
-XX:+UseParNewGC
-XX:+UseConcMarkSweepGC
-XX:CMSInitiatingOccupancyFraction=75
-XX:+UseCMSInitiatingOccupancyOnly
-Djava.awt.headless=true
-Dfile.encoding=UTF-8
-Djruby.compile.invokedynamic=true
-Djruby.jit.threshold=0
-XX:+HeapDumpOnOutOfMemoryError
-Djava.security.egd=file:/dev/urandom
EOF

# Starting Logstash
initctl start logstash

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
