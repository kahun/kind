# Changelog

## 0.17.0-0.3.7 (2024-01-23)

* [Docs] Fix: EFS permissions
* [Docs] Add AWS details
* [Core] Fix: check if coredns pdb already exists before deploying

## 0.17.0-0.3.6 (2023-12-21)

* [Core] HotFix: storageclass.parameters.label validation

## 0.17.0-0.3.5 (2023-12-19)

* [Core] Change create_iam default behaviour (to false)
* [Core] Add example full descriptor v1beta1
* [Core] Update documentation
* [Core] Update upgrade script (upgrade-provisioner_v0.3.py)
* [AWS] Update required policies
* [Core] Add coredns PDB
* [Core] Add cluster-autoscaler annotations to evict local volumes (for coredns, metrics-server, calico, cloud-controllers and CSIs)

## 0.17.0-0.3.4 (2023-11-17)

* [Core] Conditionally increase replicas for capi controllers
* [Core] Add PDB and PriorityClass to capx components
* [Core] Fix authentication for helm repositories
* [Azure] Add PriorityClass to NMI components
* [Core] Add upgrade script from 0.2 to 0.3

## 0.17.0-0.3.3 (2023-10-11)

* [Core] Add remote command execution retries

## 0.17.0-0.3.2 (2023-09-29)

* [Core] Bump cluster-operator due to hotfix

## 0.17.0-0.3.1 (2023-09-28)

* [Core] Add status in KeosCluster
* [Azure] Bump Azure provider to 1.10.4

## 0.17.0-0.3.0 (2023-09-15)

* [Core] Customize coredns configuration
* [Core] Fix wait conditions for unmanaged clusters
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

* [Azure] Add clusterAPI capabilities for AKS
* [Azure] Add clusterAPI capabilities for Azure VMs

## 0.17.0-0.1.0 (2023-03-31)

* [AWS] Add clusterAPI capabilities for EKS

## Previous development
