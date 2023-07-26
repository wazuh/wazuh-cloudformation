# Note

This repository has been archived and is no longer maintained.

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
* Wazuh servers sit behind an internet-facing load balancer for agents to communicate with the cluster
* Kibana server sit behind an internet facing load balancer, that optionally loads an SSL Certificate for HTTPS
* Route53 DNS records for the loadbalancer, Wazuh and Elastic Stack nodes (optional).

## Demo environment:

* A VPC with two subnets, one for Wazuh servers, and another for Elastic Stack
* Wazuh managers cluster with two nodes, a master and a worker
* An Elasticsearch cluster with a minimum of 3 data nodes, auto-scalable to a maximum of 6 nodes
* A Kibana node that includes a local elasticsearch client node, and an Nginx for HTTP basic authentication
* Wazuh servers sit behind an internet-facing load balancer for agents to communicate with the cluster
* Kibana server sit behind an internet facing load balancer, that optionally loads an SSL Certificate for HTTPS
* A Splunk Indexer instance with a Splunk app for Wazuh installed on it.
* Six Wazuh agents installed on different operating systems: Red Hat 7, CentOS 7, Ubuntu, Debian, Amazon Linux and Windows.

## Unattendend all-in-one

* Use install script, following [Wazuh unattended all-in-one installation](https://documentation.wazuh.com/current/installation-guide/open-distro/all-in-one-deployment/unattended-installation.html)
* Resources:
    - WazuhAIO: EC2 instance
    - SecurityGroup: EC2 Security Group. It enables the following ports:
        - 443 ( HTTPS) -> 0.0.0.0
        - 22 (SSH) -> 0.0.0.0

## Unattended distributed 

* Use install script, following [Wazuh unattended distributed installation](https://documentation.wazuh.com/current/installation-guide/open-distro/distributed-deployment/unattended/index.html)
* Reosurces:
    - WazuhVPC: EC2 VPC
    - SubnetWazuh: EC2 Subnet over WazuhVPC
    - SubnetElasticsearch: EC2 Subnet over WazuhVPC
    - InternetGateway: EC2 InternetGateway between WazuhVPC and public network
    - GatewayToInternet: EC2 VPCGatewayAttachment attached to WazuhVPC
    - PublicRouteTable: EC2 RouteTable for WazuhVPC
    - PublicRoute: EC2 Route of PublicRouteTable with a specific destination CIDR
    - SubnetWazuhPublicRouteTable: EC2 SubnetRouteTableAssociation attached to SubnetWazuh
    - SubnetElasticPublicRouteTable: EC2 SubnetRouteTableAssociation attached to SubnetElasticsearch
    - WazuhSecurityGroup: EC2 SecurityGroup over WazuhVPC. It enables the following ports and protocols:
        -   22 (SSH) -> 0.0.0.0
        -   ICMP -> 0.0.0.0
        -   1514-1516 (Wazuh manager) -> WazuhVPC
        -   55000 (Wazuh API) -> WazuhVPC
    - ElasticSecurityGroup: EC2 SecurityGroup over WazuhVPC. It enables the following ports and protocols:
        - 22 (SSH) -> 0.0.0.0
        - ICMP -> 0.0.0.0
        - 443 (HTTPS) -> 0.0.0.0
        - 9200-9400 (Wazuh manager) -> WazuhVPC
        - 5000 (wazuh manager) -> WazuhVPC
    - Elastic1: EC2 Instance Elasticsearch initial node (with Kibana)
    - Elastic2: EC2 Instance Elasticsearch node
    - Elastic3: EC2 Instance Elasticsearch node
    - WazuhMaster: EC2 Instance Wazuh master node
    - WazuhWorker: EC2 Instance Wazuh worker node
