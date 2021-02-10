#!/bin/bash
CONFIG_FILE={{src}}/config.yml
ELASTIC_INSTALL_SCRIPT={{src}}/elastic-stack-installation.sh

find=0
while [ $find -eq 0 ]
do
    if [[ -f "$CONFIG_FILE" ]] && [[ -f "$ELASTIC_INSTALL_SCRIPT" ]]
    then
        find=1
        logger -s "Files found. Moving them to /root..." 2>> {{log_file}}
        mv $CONFIG_FILE {{dst}}/config.yml
        mv $ELASTIC_INSTALL_SCRIPT {{dst}}/elastic-stack-installation.sh
    else
        logger -s "Files not found. Sleeping 10 seconds..." 2>> {{log_file}}
        sleep 10
    fi
done
