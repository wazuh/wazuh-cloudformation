# Wazuh for Amazon AWS Cloudformation

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Web](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

This repository contains CloudFormation templates and provision scripts to deploy both a Wazuh production-ready environment and a Wazuh demo environment in Amazon Web Services (AWS):

## Production-ready environment:

* A VPC with two subnets, one for Wazuh servers, and another for Elastic Stack
* Wazuh managers cluster with two nodes, a master and a worker
* An Elasticsearch cluster with a minimum of 3 data nodes, auto-scalable to a maximum of 6 nodes
* A Kibana node that includes a local elasticsearch client node, and an Nginx for HTTP basic authentication
* Wazuh servers seat behind an internet-facing load balancer for agents to communicate with the cluster
* Kibana server seats behind an internet facing load balancer, that optionally loads an SSL Certificate for HTTPS
* Route53 DNS records for the loadbalancer, Wazuh and Elastic Stack nodes (optional).

## Demo environment:

* A VPC with two subnets, one for Wazuh servers, and another for Elastic Stack
* Wazuh managers cluster with two nodes, a master and a worker
* An Elasticsearch cluster with a minimum of 3 data nodes, auto-scalable to a maximum of 6 nodes
* A Kibana node that includes a local elasticsearch client node, and an Nginx for HTTP basic authentication
* Wazuh servers seat behind an internet-facing load balancer for agents to communicate with the cluster
* Kibana server seats behind an internet facing load balancer, that optionally loads an SSL Certificate for HTTPS
* A Splunk Indexer instance with a Splunk app for Wazuh installed on it.
* Six Wazuh agents installed on different operating systems: Red Hat 7, CentOS 7, Ubuntu, Debian, Amazon Linux and Windows.


## Unattendend all-in-one

* Install scipt following [Wazuh Unattended installation](https://documentation.wazuh.com/current/installation-guide/open-distro/all-in-one-deployment/unattended-installation.html)
* A single node with Amazon Linux

