# Scripts

| Script Name | Description |
|-------------|-------------|
| aws_images_vpc.py | Vpc creation for images building (if no default vpc exists) |
| upgrade-provisioner.py | Stratio Cloud Provisioner upgrade |
| upload-images.py | Upload keos images to the cloud-provisioner |

## aws_images_vpc.py

> What the script does?  
> This Python script uses the Boto3 library to create a Virtual Private Cloud (VPC) in Amazon Web Services (AWS). The script prompts the user for a VPC name and a region, and then creates a VPC with the specified name and CIDR block. It then creates an Internet Gateway, a subnet in the VPC, and a Security Group that allows SSH traffic. Finally, the script associates the Internet Gateway with the VPC's default route table and the new subnet.
 
> Boto3 is a Python library that allows you to interact with Amazon Web Services (AWS) services, such as EC2, S3, and many others, programmatically.  
To use Boto3, you need to provide AWS credentials that allow access to the services you want to use.
> Configuring AWS Credentials on Linux  
To configure your AWS credentials on a Linux machine, you can use the AWS CLI tool. Follow these steps:  
>> * Install the AWS CLI tool by running the following command in your terminal:  
>> `sudo apt install awscli`  
>> * Once installed, run the `aws configure` command to set up your credentials. This command will prompt you to enter your Access Key ID, Secret Access Key, default region name, and default output format.  
>> * Enter your Access Key ID and Secret Access Key when prompted. These keys can be generated in the AWS Management Console by navigating to the IAM service and creating a new user with programmatic access.  
>> * After entering your credentials, you will be prompted to enter the default region name. This is the region that the AWS CLI will use by default for any AWS service commands you run. You can set this to the region where you want to create your VPC.  
>> * Finally, you will be prompted to enter the default output format. This is the format in which the AWS CLI will display its output. You can choose either json, text, or table.  

> Once you have configured your credentials, you can use the boto3.Session() method in your Python script to create a session with AWS using your credentials. This will allow you to interact with AWS services programmatically using the Boto3 library.  
> Here is an example of how to create a session using the credentials configured with the AWS CLI:  
```python
import boto3

# Create a session using the default profile
session = boto3.Session(profile_name='default')

# Use the session to create an EC2 client
ec2 = session.client('ec2')
```
> In this example, we are creating a session using the default profile, which is the profile created by the aws configure command. We are then using the session to create an EC2 client, which can be used to create and manage EC2 instances in AWS.  

## upgrade-provisioner.py

> Related documentation is on stratio-docs folder.

## upload-images.py

### Pre-requisites and considerations
    # Local requirements:
        # Python3
        # Install boto3
            # pip3 install boto3
        # Install awscli
            # pip3 install awscli
        # Install azure-cli
            # pip3 install azure-cli
        # Install gcloud client
            # https://cloud.google.com/sdk/docs/install
    # VPN connection to Stratio network (Sometimes queries to providers fail, just try again).
    # Do not use Chartmuseum.
    # Check keos.yaml and secrets.yml if needed.
        #Example:
        # keos.yaml
            # docker_registry: 963353511234.dkr.ecr.eu-west-1.amazonaws.com
            # helm_repository: https://repo.stratio.com/repository/helm-14.0-devel
        # secrets.yml
            # helm_repository: https://repo.stratio.com/repository/helm-14.0-devel
    # Modify aws_registry, azure_registry and gcp_registry variables if needed, but take care on splits

### Usage
    # Example: python3 upload-images.py  -w /home/jnovoa/org/Work/workspace/gcp/unmanaged/0.3.6 -p gcp -k 1.0.4 -v 123456
    # keos version 1.0.4:
        # Copy get-keos-docker-images-list.yml on your home directory.
        # Helm repo: helm-14.0-devel
    # keos version 1.0.5:
        # Remove 'deploy_tigera_operator' property on keos.yaml.
        # Do not copy get-keos-docker-images-list.yml on your home directory.
        # Remove bind_mount_var (variable) and bind mount (volume) on docker run command.
        # Helm repo: helm-14.0-devel
    # keos version 1.1.0:
        # Remove 'deploy_tigera_operator' property on keos.yaml.
        # Do not copy get-keos-docker-images-list.yml on your home directory.
        # Remove bind_mount_var (variable) and bind mount (volume) on docker run command.
        # Helm repo: helm-15.0-devel
