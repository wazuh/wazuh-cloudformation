#!/bin/bash

logger -s "Updating {{ossec_conf}}..." 2>> {{log_file}}
cat ~/cluster.conf | logger -s 2>> {{log_file}}
sed -i '/<cluster>/,/<\/cluster>/d' {{ossec_conf}}
cat ~/cluster.conf >> {{ossec_conf}}
