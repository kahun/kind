# Changelog

## 0.17.0-0.4.0 (upcoming)

* Added infrastructure validations for azs, vpcs, subnets and k8s versions
* [Azure] Bump cluster-api-provider-azure to v1.11.3: Add priority class to NMI
* [Core] Restrict the maximum number of unhealthy nodes in MachineHealthCheck
* [Core] Add PDB and PriorityClass to capx components
* [Core] Bump cluster api to v1.5.3
* [Core] Enable scale from zero
* [Core] Add core dns PDB if required
* [Core] Add keos 1.1.x support
* [Core] Added new CR, clusterconfig, for cluster configurations
* [Core] Added default retrieval of the latest cluster-operator version.
* [Core] Added the possibility to specify the required chart version and image version in clusterconfig

## 0.17.0-0.3.0 (2023-09-14)

* Customize coredns configuration
* Fix wait conditions for unmanaged clusters
* [AWS] Bump cluster-api-provider-aws to v2.2.0
* [AWS] Add clusterAPI capabilities for AWS VMs
* [AWS] Add EKS secrets encryption support
* [Azure] Add Azure file CSI driver
* [Azure] Bump cluster-api-provider-azure to v1.10.0: Fix Azure VMs load balancer health check
* [GCP] Bump cluster-api-provider-gcp to v1.4.0: Fix GCP VMs load balancer health check
* [Core] Bump cluster api to v1.5.1
* [Core] Bump Calico to v3.26.1
* [AWS] Bump cluster-api-provider-aws to v1.5.1
* [AWS] Bump clusterawsadm to v2.2.1
* [Azure] Bump cluster-api-provider-azure unmanaged to v1.9.8
* [Azure] Bump cluster-api-provider-azure managed to v1.10.3

## 0.17.0-0.2.0 (2023-07-03)

* Add clusterAPI capabilities for AKS
* Add clusterAPI capabilities for Azure VMs

## 0.17.0-0.1.0 (2023-03-31)

* Add clusterAPI capabilities for EKS

## Previous development
