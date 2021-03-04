#!/bin/bash

echo "Initializing Kibana (this may take a while)"
until [[ "$(curl -XGET https://{{kibana_ip}}/status -I -uadmin:admin -k -s --max-time 300 | grep "200 OK")" ]]; do
    echo -ne "."
    sleep 10
done
conf="$(awk '{sub("url: https://localhost", "url: https://{{wazuh_master_ip}}")}1' /usr/share/kibana/data/wazuh/config/wazuh.yml)"
echo "${conf}" > /usr/share/kibana/data/wazuh/config/wazuh.yml  
echo "You can access the web interface https://{{kibana_ip}}. The credentials are admin:admin'    
