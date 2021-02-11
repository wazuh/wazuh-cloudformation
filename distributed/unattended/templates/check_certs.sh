#!/bin/bash

CERTS_FILE={{src}}/certs.tar
find=0
while [ $find -eq 0 ]
do
    if [[ -f "$CERTS_FILE" ]]
    then
        find=1
        logger -s "Cert files found. Moving them to {{dst}}..." 2>> {{log_file}}
        mv $CERTS_FILE {{dst}}/certs.tar
    else
        logger -s "Cert files not found. Sleeping 10 seconds..." 2>> {{log_file}}
        sleep 10
    fi
done
