# Wazuh for Amazon AWS Cloudformation

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Web](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

The production environment has the following structure:

* A VPC with two subnets, one for Wazuh servers, and another for Elastic Stack
* Wazuh managers cluster with two nodes, a master and a worker
* An Elasticsearch cluster with a minimum of 3 data nodes, auto-scalable to a maximum of 6 nodes
* A Kibana node that includes a local elasticsearch client node, and an Nginx for HTTP basic authentication
* Wazuh servers seat behind an internet-facing load balancer for agents to communicate with the cluster
* Kibana server seats behind an internet facing load balancer, that optionally loads an SSL Certificate for HTTPS
* Route53 DNS records for the loadbalancer, Wazuh and Elastic Stack nodes (optional).

## Elasticsearch cluster configuration

Elasticsearch data nodes are deployed as part of an auto scaling group, that scales based on CPU usage. Minimum number of nodes is 3, and maximum is 6.

Elasticsearch instance types can be chosen from:

* i3.large
* i3.xlarge
* i3.2xlarge
* t2.large
* t2.medium

These instance types are recommended due to Elasticsearch disk requirements. Ephemeral disks are used for data storage.

None of these instances are directly accessible from the Internet, although they can be reached jumping through the Kibana system, that has a public SSH service.

## Kibana server configuration

Kibana server runs an instance of Elasticsearch (acting as a client node), an instance of Kibana (with Wazuh plugin installed and configured), and an instance of Nginx (used to provide SSL encryption and basic HTTP authentication).

Kibana instance types can be chosen from:

* m5.large
* m5.xlarge
* m5.2xlarge
* t2.large
* t2.medium
* r5.large

These instance types are recommended due to Kibana and Elasticsearch memory requirements.

In addition, the Kibana server takes care of:

* Setting up wazuh-alerts template in Elasticsearch
* Setting default index-pattern to wazuh-alerts
* Setting default time-picker to 24 hours

Kibana server is reachable from the Internet, directly via its own Elastic IP, or through an internet-facing load balancer. The load balancer can be used, optionally, to add a valid Amazon SSL Certificate for HTTPS communications.

## Wazuh cluster configuration

The Wazuh cluster deployed has one master node (providing API and registration server) and one worker node.

Wazuh instance types can be chosen from:

* m5.large
* m5.xlarge
* m5.2xlarge
* t2.micro
* t2.medium
* t2.large

These instance types are recommended for the managers, as they provide enough memory for Wazuh components.

The Wazuh API, running on Wazuh master node, is automatically configured to use HTTPS protocol.

The Wazuh registration service (authd), running on Wazuh master node, is configured not to use source IP addresses. We assume that agents will connect through the Internet, and most likely several will use the same source IP (sitting behind a NAT). This service is configured automatically to require password authentication for new agents registration.

Filebeat runs on both the Wazuh master node and the worker node, reading alerts and forwarding those to Elasticsearch nodes via the internal load balancer.

New agents can make use of the Wazuh master public Elastic IP address for registration.

Once registered, new agents can connect to the Wazuh cluster, via TCP, using the load balancer public IP address.

## Optional DNS records

Optionally it is possible to deploy DNS records for the loadbalancer, Wazuh nodes and Elastic Stack nodes. The `EnableDNSRecord`, `Subdomain` and `HostedZoneName` parameters configure the related Route 53 settings.

* `EnableDNSRecord` parameter enables/disables the DNS record usage.
* `HostedZoneName` sets the parent domain for the loadbalancer and the instances.
* The `Subdomain` parameter sets the subdomain name for the loadbalancer.
* Elastic Stack nodes and Wazuh nodes subdomain names are hardcoded on the CloudFormation template.


## Parameters template

The following template contains an example list of parameters and value placeholders.

```json
[{
    "ParameterKey": "ElasticWazuhVersion",
    "ParameterValue": "<ElasticWazuhVersion>"
},
{
    "ParameterKey": "WazuhInstanceType",
    "ParameterValue": "t2.medium"
},
{
    "ParameterKey": "InstallType",
    "ParameterValue": "<InstallType>"
},
{
    "ParameterKey": "ElasticInstanceType",
    "ParameterValue": "t2.large"
},
{
    "ParameterKey": "KibanaInstanceType",
    "ParameterValue": "t2.large"
},
{
    "ParameterKey": "SshUsername",
    "ParameterValue": "<SshUsername>"
},
{
    "ParameterKey": "SshPassword",
    "ParameterValue": "<SshPassword>"
},
{
    "ParameterKey": "WazuhServerPort",
    "ParameterValue": "1514"
},
{
    "ParameterKey": "WazuhRegistrationPort",
    "ParameterValue": "1515"
},
{
    "ParameterKey": "WazuhRegistrationPassword",
    "ParameterValue": "<WazuhRegistrationPassword>"
},
{
    "ParameterKey": "WazuhApiPort",
    "ParameterValue": "55000"
},
{
    "ParameterKey": "WazuhApiAdminUsername",
    "ParameterValue": "<WazuhApiAdminUsername>"
},
{
    "ParameterKey": "WazuhApiAdminPassword",
    "ParameterValue": "<WazuhApiAdminPassword>"
},
{
    "ParameterKey": "KeyPairName",
    "ParameterValue": "<KeyPairName>"
},
{
    "ParameterKey": "AvailabilityZone",
    "ParameterValue": "<AvailabilityZone>"
},
{
    "ParameterKey": "SSLCertificateARN",
    "ParameterValue": "<SSLCertificateARN>"
},
{
    "ParameterKey": "EnableDNSRecord",
    "ParameterValue": "disabled"
},
{
    "ParameterKey": "Subdomain",
    "ParameterValue": "<Subdomain>"
},
{
    "ParameterKey": "HostedZoneName",
    "ParameterValue": "<HostedZoneName>"
}
]
```

## AWS production environment diagram

![wazuh_template](images/wazuh_template-designer.png)