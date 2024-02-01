# Resumen tareas al crear una nueva cuenta

* [Resumen tareas al crear una nueva cuenta](#resumen-tareas-al-crear-una-nueva-cuenta)
	* [Quotas](#quotas)
    * [IAM](#iam)
    * [Passbolt](#passbolt)
    * [ECR](#ecr)
    * [Lambda](#lambda)

## Quotas

Lo primero que haremos será solicitar un aumento de cuotas para los siguientes recursos:

| Recurso | Cantidad |
|---------|----------|
| Elastic IP address quota per NAT gateway | 8 |
| NAT gateways per Availability Zone | 30 |
| Internet gateways per Region | 20 |
| EC2-VPC Elastic IPs | 50 |

Pre-requisitos usuario con los permisos necesarios para poder hacer las queries a la API de AWS.

| Service | Access level |
|---------|--------------|
| Service Quotas | Full Access |

## Get service quotas

```bash
# Elastic IP address quota per NAT gateway
aws service-quotas get-service-quota --service-code vpc --quota-code L-5F53652F | jq '.Quota.Value' | cat
# NAT gateways per Availability Zone
aws service-quotas get-service-quota --service-code vpc --quota-code L-026E1A4D | jq '.Quota.Value' | cat
# Internet gateways per Region
aws service-quotas get-service-quota --service-code vpc --quota-code L-A4707A72 | jq '.Quota.Value' | cat
# EC2-VPC Elastic IPs
aws service-quotas get-service-quota --service-code ec2 --quota-code L-0263D0A3 | jq '.Quota.Value' | cat
```

# IAM

## Esquema de usuarios y políticas

> User: cloud-provisioner  
>>  Description: Full access to enhance development  
    Policy: stratio-cloud-provisioner  

> User: cloud-provisioner-eks
>>    Description: Only EKS deployments  
>>    Policy:  
>>        - stratio-eks-policy (EKS deployments) [stratio-eks-policy](../Permissions/EKS/eks_permission_ref.json)  
>>        - stratio-fc-policy (CloudFormation) [stratio-fc-policy](../Permissions/EKS/eks_Cloud_Formation.json)  
>>        - stratio-eks-offline (Offline EKS deployments)  

> User: cloud-provisioner-aws
>>    Description: Only AWS deployments  
>>    Policy:  
>>        - stratio-aws-policy (AWS deployments) [stratio-aws-policy](../Permissions/AWS/aws_permission_ref.json)  
>>        - stratio-fc-policy (CloudFormation) [stratio-fc-policy](../Permissions/AWS/aws_Cloud_Formation.json)  
>>        - stratio-aws-offline (Offline AWS deployments)  

* Nota: Todas las políticas/roles deberían de llevar la misma nomenclatura, por ejemplo: 'stratio-'

# Passbolt

[Stratio-Passbolt](https://llavero.int.stratio.com/)  
Compartir de forma segura mediante passbolt las credenciales de los usuarios creados.

# CloudFormation

Asegurarse de que el despliegue del stack de CloudFormation se hace de forma satisfactoria, desplegando un cluster de EKS con el cloud-provisioner.

Crear de forma manual el role: "AWSServiceRoleForAmazonEKS" y asociarle la política "AmazonEKSServiceRolePolicy".

# ECR

Crear repositorio y subir todas las imagenes necesarias para los despliegues

# Lambda

Es recomenable crear varias lambdas:

- Comprobar el estado del stack de CloudFormation y notificar si hay algún error.
- Borrar los posibles volúmenes de despliegues de test que se nos queden pendientes.
    > Periodicidad: 0 23 ? * MON-FRI * (Lunes a Viernes a las 23:00)  
    > script: [deleteUnusedEBS](../../../scripts/deleteUnusedEBS.py)  
- Borrar los Provedores de identidad del tipo "OpenID Connect (OIDC)" que no estén en uso.
    > Periodicidad: 0 23 ? * MON-FRI * (Lunes a Viernes a las 23:00)  
    > script: [deleteoldOIDC](../../../scripts/delete_oidc.py)
- Revisión de clusters con más de '3' días desplegado.  
    > Periodicidad: 0 23 ? * MON-FRI * (Lunes a Viernes a las 23:00)  
    > script: [ClustersWatch](../../../scripts/ClustersWatch.py)  
    > Para evitar mensajes sobre una vpc deberíamos añadir el tag "Custom" en la misma.   