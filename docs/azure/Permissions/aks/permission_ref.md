# AZURE (AKS) Permissions

Requirements:
- Service Principal (cloud-provisioner credentials)
  - Application Id = descriptor (client_id)
  - AAD - Application Secret ID = descriptor (client_secret)
- Resource group (capz for example) (control-plane and workers identities)
  - Managed Identity (capz-test-agp-restricted) --> Azure roles Assignments (aks-capz-test-role-node)
  - Managed Identity (capz-test-controlplane) --> Azure roles Assignments (aks-capz-test-role-control-plane)

### Permissions Table

**Test:** cloud-provisioner create cluster --name jazure --vault-password "123456"  -d cluster-aks.yaml --delete-previous --avoid-creation

| Permission | Needed for | Description | Resource | Application |
| --- | --- | --- | --- | --- |
| Microsoft.ContainerRegistry/registries/pull/read | Get ACR auth token | Failed to obtain the ACR token with the provided credentials | Microsoft.ContainerRegistry | Provisioner |

**Test:** cloud-provisioner create cluster --name jazure --retain --vault-password 123456 --keep-mgmt (CAPZ)

| Permission | Needed for | Description | Resource | Application |
| --- | --- | --- | --- | --- |
| Microsoft.Resources/subscriptions/resourcegroups/read | Get ResourceGroup | does not have authorization to perform action 'Microsoft.Resources/subscriptions/resourcegroups/read' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx | Microsoft.Resources | Provisioner |
| Microsoft.Resources/subscriptions/resourcegroups/write | Create ResourceGroup | does not have authorization to perform action 'Microsoft.Resources/subscriptions/resourcegroups/write' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx | Microsoft.Resources | Provisioner |
| Microsoft.Network/virtualNetworks/read | Get VirtualNetwork | does not have authorization to perform action 'Microsoft.Network/virtualNetworks/read' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure | Microsoft.Network | Provisioner |
| Microsoft.Resources/tags/read | Get Tags | does not have authorization to perform action 'Microsoft.Resources/tags/read' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure/providers/Microsoft.Resources/tags/default | Microsoft.Resources | Provisioner |
| Microsoft.Network/virtualNetworks/write | Create VirtualNetwork | does not have authorization to perform action 'Microsoft.Network/virtualNetworks/write' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure | Microsoft.Network | Provisioner |
| Microsoft.Network/virtualNetworks/subnets/read | Get Subnet | does not have authorization to perform action 'Microsoft.Network/virtualNetworks/subnets/read' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure/subnets/jazure | Microsoft.Network | Provisioner |
| Microsoft.Network/virtualNetworks/subnets/write | Create Subnet | does not have authorization to perform action 'Microsoft.Network/virtualNetworks/subnets/write' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure/subnets/jazure | Microsoft.Network | Provisioner |
| Microsoft.ContainerService/managedClusters/read | Get AKS Cluster | does not have authorization to perform action 'Microsoft.ContainerService/managedClusters/read' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.ContainerService/managedClusters/jazure | Microsoft.ContainerService | Provisioner |
| Microsoft.ContainerService/managedClusters/write | Create AKS Cluster | does not have authorization to perform action 'Microsoft.ContainerService/managedClusters/write' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.ContainerService/managedClusters/jazure | Microsoft.ContainerService | Provisioner |
| Microsoft.Network/virtualNetworks/subnets/join/action | Join Subnet | does not have authorization to perform action 'Microsoft.Network/virtualNetworks/subnets/join/action' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure/subnets/jazure | Microsoft.Network | Provisioner |
| Microsoft.ManagedIdentity/userAssignedIdentities/assign/action | userAssignedIdentities assign | does not have permission to perform action 'Microsoft.ManagedIdentity/userAssignedIdentities/assign/action' | Microsoft.ManagedIdentity | Provisioner |
| Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action | listClusterAdminCredential | does not have permission to perform action 'Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action' | Microsoft.ContainerService | Provisioner |
| Microsoft.ContainerService/managedClusters/agentPools/read | Get AKS AgentPool | does not have authorization to perform action 'Microsoft.ContainerService/managedClusters/agentPools/read' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.ContainerService/managedClusters/jazure/agentPools/jazure1mp1 | Microsoft.ContainerService | Provisioner |
| Microsoft.Compute/virtualMachineScaleSets/* | Failed to find scale set over resource group machine pool | failed to find vm scale set in resource group jazure-nodes matching pool named jazure1mp0 | Microsoft.Compute | Provisioner |
| "Microsoft.ManagedIdentity/userAssignedIdentities/*/read" "Microsoft.ManagedIdentity/userAssignedIdentities/*/assign/action" "Microsoft.Authorization/*/read" "Microsoft.Insights/alertRules/*" "Microsoft.Resources/subscriptions/resourceGroups/read" "Microsoft.Resources/deployments/*" "Microsoft.Support/*" | failed to reconcile AzureManagedControlPlane | The cluster using user-assigned managed identity must be granted 'Managed Identity Operator' role to assign kubelet identity. | Microsoft.ManagedIdentity Microsoft.Insights Microsoft.Resources Microsoft.Support | Provisioner |
| Microsoft.ContainerRegistry/registries/pull/read | Get ACR auth token | Failed to authorize: failed to fetch anonymous token | Microsoft.ContainerRegistry | Provisioner |

**Test:** cloud-provisioner create cluster --name jazure --retain --vault-password 123456 (same permissions as --keep-mgmt) (same as above)

**Test:** clusterctl move --kubeconfig remote_kubeconfig --to-kubeconfig local_kubeconfig --namespace cluster-jazure --dry-run

Performing move...
********************************************************
This is a dry-run move, will not perform any real action
********************************************************
Discovering Cluster API objects  
Moving Cluster API objects Clusters=1  
Moving Cluster API objects ClusterClasses=0  
Creating objects in the target cluster  
Deleting objects from the source cluster  

❯ clusterctl move --kubeconfig remote_kubeconfig --to-kubeconfig local_kubeconfig --namespace cluster-jazure (no needed additonal permissions)

Performing move...  
Discovering Cluster API objects  
Moving Cluster API objects Clusters=1  
Moving Cluster API objects ClusterClasses=0  
Creating objects in the target cluster  
Deleting objects from the source cluster  

❯ clusterctl move --to-kubeconfig remote_kubeconfig --kubeconfig local_kubeconfig --namespace cluster-jazure

Performing move...  
Discovering Cluster API objects  
Moving Cluster API objects Clusters=1  
Moving Cluster API objects ClusterClasses=0  
Creating objects in the target cluster  
Deleting objects from the source cluster  

❯ clusterctl --kubeconfig /home/jnovoa/.kube/configs/remote_kubeconfig describe cluster jazure -n cluster-jazure

NAME                                                  READY  SEVERITY  REASON  SINCE  MESSAGE  
Cluster/jazure                                        True                     24m  
├─ClusterInfrastructure - AzureManagedCluster/jazure  
├─ControlPlane - AzureManagedControlPlane/jazure      True                     24m  
└─Workers  
  ├─MachinePool/jazure1-mp-0                          True                     94s  
  ├─MachinePool/jazure1-mp-1                          True                     94s  
  └─MachinePool/jazure1-mp-2                          True                     94s  

**Test:** scale up with cluster-operator / manual

| Permission | Needed for | Description | Resource | Application |
| --- | --- | --- | --- | --- |
| Microsoft.ContainerService/managedClusters/agentPools/write | Scale up | does not have authorization to perform action 'Microsoft.ContainerService/managedClusters/agentPools/write' over scope '/subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65/resourceGroups/jazure/providers/Microsoft.ContainerService/managedClusters/jazure/agentPools/jazure1mp1' | Microsoft.ContainerService | Provisioner |

| NAME |      CLUSTER  | DESIRED |  REPLICAS |  PHASE  |   AGE   |  VERSION
| --- | --- | --- | --- | --- | --- | --- |
| jazure1-mp-0  | jazure  |  1  |       1    |      Running    | 7m11s  | v1.26.3 |
| jazure1-mp-1  | jazure  |  1  |       1    |      Running    | 7m11s  | v1.26.3 |
| jazure1-mp-2  | jazure  |  2  |       1    |      ScalingUp  | 7m10s  | v1.26.3 |

**Test:** Remove machine pool (same as above)

| Permission | Needed for | Description | Resource | Application |
| --- | --- | --- | --- | --- |
| Microsoft.ContainerService/managedClusters/agentPools/delete | Delete MachinePool | does not have authorization to perform action 'Microsoft.ContainerService/managedClusters/agentPools/delete' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.ContainerService/managedClusters/jazure/agentPools/jazure1mp2 | Microsoft.ContainerService | Provisioner |

**Test:** Destroy Machine on Azure UI (self-healing) (same as above)

**Test:** upgrade k8s version from 1.26.3 to 1.27.3 (same as above)

**Test:** Delete cluster (From local container)
kubectl --kubeconfig local_kubeconfig -n cluster-azure1 delete cluster --all

| Permission | Needed for | Description | Resource | Application |
| --- | --- | --- | --- | --- |
| Microsoft.ContainerService/managedClusters/delete | Delete AKS Cluster | does not have authorization to perform action 'Microsoft.ContainerService/managedClusters/delete' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.ContainerService/managedClusters/jazure | Microsoft.ContainerService | Provisioner |
| Microsoft.Network/virtualNetworks/subnets/delete | Delete Subnet | does not have authorization to perform action 'Microsoft.Network/virtualNetworks/subnets/delete' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure/subnets/jazure | Microsoft.Network | Provisioner |
| Microsoft.Network/virtualNetworks/delete | Delete VirtualNetwork | does not have authorization to perform action 'Microsoft.Network/virtualNetworks/delete' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx/providers/Microsoft.Network/virtualNetworks/jazure | Microsoft.Network | Provisioner |
| Microsoft.Resources/subscriptions/resourcegroups/delete | Delete ResourceGroup | does not have authorization to perform action 'Microsoft.Resources/subscriptions/resourcegroups/delete' over scope '/subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/xxxxxx | Microsoft.Resources | Provisioner |

**Test**: Keos Install (same as above) (no-modules)
