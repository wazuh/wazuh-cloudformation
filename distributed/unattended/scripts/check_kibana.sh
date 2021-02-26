#!/bin/bash

active=0

while [[ $active -eq 0 ]]; do
    systemctl is-active --quiet kibana.service
    if [ "$?" != 0 ]; then
        echo "Kibana service disable. Sleeping 60 seconds..."
        sleep 60
    else
        echo "Kibana service enable. Linking 443 port to kibana socket..."
        setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node
        echo "Restarting kibana service..."
        systemctl restart kibana.service
        active=1
    fi
done