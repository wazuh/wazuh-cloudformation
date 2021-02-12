#!/bin/bash

USER=$1
IP=$2
PORT=$3

open=0
while [ $open -eq 0 ]
do
    ssh -i ~/.ssh/ssh.key $USER@$IP "sudo netstat -tulnp" | grep $PORT &> /dev/null
    if [[ $? -eq 0 ]] # Open
    then
        open=1
        echo "Port $PORT open in $IP"
    else # Close
        echo "Port $PORT close in $IP. Sleeping 10 seconds..."
        sleep 10
    fi
done


