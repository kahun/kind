#!/usr/bin/env python3

import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

region = 'eu-west-1'

def list_eks_clusters():
    # Create list for those checked clusters than are older than 3 days
    checked_eks_clusters = []
    eks = boto3.client('eks', region_name=region)
    try:
        # List all clusters
        clusters = eks.list_clusters()
        if 'clusters' not in clusters or len(clusters['clusters']) == 0:
            print('No clusters found.')
        else:
            print('List of EKS clusters:')
            print("-----------------------------------------------------------")
            for cluster in clusters['clusters']:
                print(f"Cluster: {cluster}")
                # If cluster is older than 3 days, add it to checked_eks_clusters list
                if check_eks_cluster(eks, cluster) != None:
                    checked_eks_clusters.append(cluster)
        print("-----------------------------------------------------------")
        return checked_eks_clusters
    except Exception as e:
        print(f'Error listing clusters: {str(e)}')

def check_eks_cluster(eks, cluster_name):
    try:
        eks = boto3.client('eks', region_name=region)
        clusters = eks.list_clusters()

        # Get detailed information for the cluster to determine its creation date
        cluster_details = eks.describe_cluster(name=cluster_name)
        cluster_creation_date = cluster_details['cluster']['createdAt']
        print("Cluster creation date: ", cluster_creation_date)

        # Get current date and time
        current_date = datetime.now()

        # Avoid error compare offset-naive and offset-aware datetimes
        cluster_creation_date = cluster_creation_date.replace(tzinfo=None)
        current_date = current_date.replace(tzinfo=None)

        # Calculate cutoff date
        cutoff_date = current_date - timedelta(days=3)
        print("Cutoff date: ", cutoff_date)
        print (cluster_creation_date < cutoff_date)

        # if cluster is older than 5 minutes, return name of cluster else return None
        if cluster_creation_date < cutoff_date:
            print("Cluster", cluster_name, "is older than 3 days. Adding to checked_eks_clusters list.")
            return cluster_name
        else:
            print("Cluster", cluster_name, "is not older than 3 days. Not adding to checked_eks_clusters list.")
            return None

    except Exception as e:
        print(f'Error checking cluster {cluster_name}: {str(e)}')

def list_aws_clusters():
    try:
        # We will be able to rule out a list of clusters that are not going to be checked
        rule_out_list = ['vpc-0dcf067a3219a0394']

        # Create list for those checked clusters than are older than 3 days
        checked_aws_clusters = []

        # Get the list of VPCs
        ec2 = boto3.client('ec2', region_name=region)
        vpcs = ec2.describe_vpcs()

        # if vpc is empty or the only vpcs are the ones in rule_out_list, return None
        if 'Vpcs' not in vpcs or len(vpcs['Vpcs']) == 0:
            print('No VPCs found.')
            return None

        # Get creation date for each VPC using cloud trail (event name: CreateVpc) (event time has creation date)
        cloudtrail = boto3.client('cloudtrail', region_name=region)
        print("List of AWS clusters:")
        print("-----------------------------------------------------------")
        for vpc in vpcs['Vpcs']:
            # Get VPC creation date
            vpc_id = vpc['VpcId']
            # filter vpc_id not in rule_out_list
            if vpc_id not in rule_out_list:
                print("VPC ID: ", vpc_id)
                response = cloudtrail.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'ResourceName',
                            'AttributeValue': vpc_id
                        },
                    ],
                    MaxResults=1
                )
                events = response['Events']
                for event in events:
                    event_time = event['EventTime']
                    print("Event time: ", event_time)
                    vpc_creation_date = event_time

                # Get value from vpc tags which key is "keos.stratio.com/owner"  and create a variable with it (we do not check if tag exists)
                vpctags = vpc['Tags']
                for tag in vpctags:
                    # Si la tag key es custom o  Custom en mayusculas, no se añade a la lista de clusters a revisar
                    if tag['Key'] == 'custom' or tag['Key'] == 'Custom':
                        print("VPC", vpc_id, "has tag key 'custom' or 'Custom'. Not adding to checked_aws_clusters list.")
                        continue
                    if tag['Key'] == 'keos.stratio.com/owner':
                        vpc_owner = tag['Value']

                # Get value from vpc tags which key is "Name"  and create a variable with it
                for tag in vpctags:
                    if tag['Key'] == 'Name':
                        vpc_name = tag['Value']

                # Get current date
                current_date = datetime.now()

                # Error checking cluster lrecio-aws: can't compare offset-naive and offset-aware datetimes
                vpc_creation_date = vpc_creation_date.replace(tzinfo=None)
                current_date = current_date.replace(tzinfo=None)

                # Calculate cutoff date
                cutoff_date = current_date - timedelta(days=3)
                print("Cutoff date: ", cutoff_date)
                print (vpc_creation_date < cutoff_date)

                # if cluster is older than 5 minutes, return value of tag key "keos.stratio.com/owner" else return None
                if vpc_creation_date < cutoff_date:
                    print("VPC", vpc_name, "is older than 3 days. Adding to checked_aws_clusters list.")
                    checked_aws_clusters.append(vpc_owner)
                else:
                    print("VPC", vpc_name, "is not older than 3 days. Not adding to checked_aws_clusters list.")

                # Remove from checked_aws_clusters list those clusters that are in rule_out_list
                if len(rule_out_list) > 0:
                    for i in rule_out_list:
                        if i in checked_aws_clusters:
                            checked_aws_clusters.remove(i)
        print("-----------------------------------------------------------")
        return checked_aws_clusters
    except Exception as e:
        print(f'Error listing clusters: {str(e)}')

def send_email(check_eks_clusters, check_aws_clusters):
    print("Sending email...")
    print("checked_eks_clusters: ", check_eks_clusters)
    print("checked_aws_clusters: ", check_aws_clusters)
    exit()

    # If common clusters are found on both lists, remove them from check_aws_clusters list or exit if both lists are empty
    if len(check_eks_clusters) > 0 and len(check_aws_clusters) > 0:
        for i in check_eks_clusters:
            if i in check_aws_clusters:
                check_aws_clusters.remove(i)
    elif len(check_eks_clusters) == 0 and len(check_aws_clusters) == 0:
        print("No clusters found.")
        exit()

    # Cluster name is a list, so we need to convert it to string
    eks_clusters = str(check_eks_clusters)
    aws_clusters = str(check_aws_clusters)

    # remove brackets from string
    eks_clusters = eks_clusters.replace("[", "")
    eks_clusters = eks_clusters.replace("]", "")
    aws_clusters = aws_clusters.replace("[", "")
    aws_clusters = aws_clusters.replace("]", "")

    # Use SES to send email
    SENDER = "clouds-integration@stratio.com"
    RECIPIENT = "clouds-integration@stratio.com"
    AWS_REGION = region
    SUBJECT = "Clouds AWS Active Clusters"
    BODY_TEXT = ("[Account:963353511234EKS]")
    BODY_HTML = """<html>
    <head></head>
    <body>
      <h1>Account:963353511234</h1>
        <p style="font-size:160%;">EKS Clusters older than 3 days:</p>
        <p style="font-size:160%;">""" + eks_clusters + """</p>
        <p style="font-size:160%;">AWS Clusters older than 3 days:</p>
        <p style="font-size:160%;">""" + aws_clusters + """</p>
    </body>
    </html>
                """
    CHARSET = "UTF-8"
    client = boto3.client('ses',region_name=AWS_REGION)
    try:
        # Provide the contents of the email.
        response = client.send_email(
            Destination={
                'ToAddresses': [
                    RECIPIENT,
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': CHARSET,
                        'Data': BODY_HTML,
                    },
                },
                'Subject': {
                    'Charset': CHARSET,
                    'Data': SUBJECT,
                },
            },
            Source=SENDER,
        )
        print("Email sent! Message ID:"),
        print(response['MessageId'])
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])

def main(event, context):
    eks_clusters = list_eks_clusters()
    aws_clusters = list_aws_clusters()
    send_email(eks_clusters, aws_clusters)


if __name__ == '__main__':
    main('', '')