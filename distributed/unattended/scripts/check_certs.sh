#!/bin/bash

CERTS_FILE={{src}}/certs.tar
find=0
while [ $find -eq 0 ]
do
    if [[ -f "{{dst}}/certs.tar" ]]
    then
        find=1
        echo "Cert files already in /root"
    elif [[ -f "$CERTS_FILE" ]]
    then
        find=1
        echo "Cert files found. Moving them to {{dst}}..." 
        mv $CERTS_FILE {{dst}}
    else
        echo "Cert files not found. Sleeping 60 seconds..."
        sleep 60
    fi
done
