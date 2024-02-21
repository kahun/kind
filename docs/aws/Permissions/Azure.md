# Get the Azure AD Application ID and Role Assignments

```bash

❯ az ad app list --query "[?contains(displayName, 'cloud-provisioner')].{name:displayName, appId:appId} | sort_by(@, &name)" --output table
Name                              AppId
--------------------------------  ------------------------------------
cloud-provisioner                 7cf3ce06-2689-4c17-b2da-09df11fb725b  
cloud-provisioner-restricted      e979a59d-ba11-4fcc-b174-64cfab548943  (spec.credentials.client_id)
cloud-provisioner-restricted-aks  e3b6e5b9-e729-4612-a3cf-4bda74c240c4  (spec.credentials.client_id)

❯ az role assignment list --all --assignee 7cf3ce06-2689-4c17-b2da-09df11fb725b --query "[].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" --output table
Principal                             Role         Scope
------------------------------------  -----------  ---------------------------------------------------------------------------------------------------------------------------------------
7cf3ce06-2689-4c17-b2da-09df11fb725b  Contributor  /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65
7cf3ce06-2689-4c17-b2da-09df11fb725b  AcrPull      eosregistry
7cf3ce06-2689-4c17-b2da-09df11fb725b  AcrPull      offlineregistry
7cf3ce06-2689-4c17-b2da-09df11fb725b  AcrPush      offlineregistry

❯ az role assignment list --all --assignee e979a59d-ba11-4fcc-b174-64cfab548943 --query "[].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" --output table
Principal                             Role                  Scope
------------------------------------  --------------------  -----------------------------------------------------------------------
e979a59d-ba11-4fcc-b174-64cfab548943  capz-role-restricted  /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65/resourceGroups/capz
e979a59d-ba11-4fcc-b174-64cfab548943  capz-role-restricted  /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65

❯ az role assignment list --all --assignee e3b6e5b9-e729-4612-a3cf-4bda74c240c4 --query "[].{Principal:principalName, Role:roleDefinitionName, Scope:scope}" --output table
Principal                             Role                      Scope
------------------------------------  ------------------------  -----------------------------------------------------------------------
e3b6e5b9-e729-4612-a3cf-4bda74c240c4  capz-role-restricted-aks  /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65/resourceGroups/capz
e3b6e5b9-e729-4612-a3cf-4bda74c240c4  capz-role-restricted-aks  /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65

# Get roles permissions

❯ az role definition list --name "Contributor" --output table
Name         Type                                     Description
-----------  ---------------------------------------  -------------------------------------------------------------------------------------------------------------------------------------------------------------------
Contributor  Microsoft.Authorization/roleDefinitions  Grants full access to manage all resources, but does not allow you to assign roles in Azure RBAC, manage assignments in Azure Blueprints, or share image galleries.

❯ az role definition list --name "AcrPull" --output table
Name         Type                                   Description
-------  ---------------------------------------    -------------
AcrPush  Microsoft.Authorization/roleDefinitions    acr pull

❯ az role definition list --name "AcrPush" --output table
Name         Type                                   Description
-------  ---------------------------------------    -------------
AcrPull  Microsoft.Authorization/roleDefinitions    acr push

❯ az role definition list --name "capz-role-restricted" --output table
Name         Type                                   Description
-------  ---------------------------------------    -------------
capz-role-restricted  Microsoft.Authorization/roleDefinitions  Restricted role for testing permissions

❯ az role definition list --name "capz-role-restricted-aks" --output table
Name                      Type                                     Description
------------------------  ---------------------------------------  ----------------------------
capz-role-restricted-aks  Microsoft.Authorization/roleDefinitions  Stratio aks role permissions

```

# Managed Identity

## Azure Unmanaged

> capz-controlplane  
>> Role: capz-role-controlplane
```bash
# Get json permissions
❯ az role definition list --name "capz-role-controlplane"
```

> capz-agentpool-restricted
>> Role: capz-role-node
```bash
# Get json permissions
❯ az role definition list --name "capz-role-node"
```

## Azure Managed

> capz-test-controlplane  
>> Role: capz-test-role-controlplane
```bash
# Get json permissions
❯ az role definition list --name "capz-test-role-controlplane"
```

> capz-test-agp-restricted
>> Role: capz-test-role-node
```bash
# Get json permissions
❯ az role definition list --name "capz-test-role-node"
```

# Relationship chart
    
```plaintext
cloud-provisioner   <--- Contributor  <--- /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65
                    <--- AcrPull      <--- eosregistry
                    <--- AcrPull      <--- offlineregistry
                    <--- AcrPush      <--- offlineregistry

cloud-provisioner-restricted   <--- capz-role-restricted  <--- /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65/resourceGroups/capz
                               <--- capz-role-restricted  <--- /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65

cloud-provisioner-restricted-aks   <--- capz-role-restricted-aks  <--- /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65/resourceGroups/capz
                                   <--- capz-role-restricted-aks  <--- /subscriptions/6e2a38cd-ef16-47b3-a75e-5a4960cedf65                    

Azure Unmanaged <--- cloud-provisioner-resticted <--- capz-role-restricted    (spec.credentials.client_id)
                <--- capz-controlplane    (spec.security.control_plane_identity)
                <--- capz-agentpool    (spec.security.nodes_identity)

Azure Managed   <--- cloud-provisioner-resticted-aks <--- capz-role-restricted-aks    (spec.credentials.client_id)
                <--- capz-test-controlplane    (spec.security.control_plane_identity)
                <--- capz-test-agp-restricted   (spec.security.nodes_identity)
```