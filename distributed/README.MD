# Wazuh for Amazon AWS Cloudformation

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Web](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

The distributed environment has the following structure:

* A VPC with two subnets, one for Wazuh servers, and another for Elastic Stack
* Wazuh managers cluster with two nodes, a master and a worker
* Elasticsearch cluster with 3 data nodes
* Kibana nodes installed among Elasticsearch initial node
* Follow the [distributed unattended](https://documentation.wazuh.com/current/installation-guide/open-distro/distributed-deployment/unattended/index.html) installation method 
