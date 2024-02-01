import boto3
from datetime import datetime, timedelta

def list_openid_connect_providers():
    region = 'eu-west-1'
    iam = boto3.client('iam', region_name=region)

    try:
        # List all OpenID Connect providers
        providers = iam.list_open_id_connect_providers()

        if 'OpenIDConnectProviderList' not in providers or len(providers['OpenIDConnectProviderList']) == 0:
            print('No OpenID Connect providers found.')
        else:
            print('List of OpenID Connect providers:')
            for provider in providers['OpenIDConnectProviderList']:
                print(f"Provider ARN: {provider['Arn']}")
                check_and_delete_provider(iam, provider['Arn'])
    except Exception as e:
        print(f'Error listing OpenID Connect providers: {str(e)}')

def check_and_delete_provider(iam, provider_arn):
    try:
        # Get detailed information for the provider to determine its creation date
        provider_details = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
        cluster_owner = provider_details['Tags'][0]['Value']
        print("Cluster owner: ", cluster_owner)

        # Check if eks cluster is still active (status: ACTIVE)
        region = 'eu-west-1'
        eks = boto3.client('eks', region_name=region)
        clusters = eks.list_clusters()
        #print("Clusters: ", clusters)
        # Get status of cluster
        cluster_status = eks.describe_cluster(name=cluster_owner)
        print("Cluster status: ", cluster_status['cluster']['status'])
        if eks.describe_cluster(name=cluster_owner)['cluster']['status'] == 'ACTIVE':
            print("Cluster is still active. Not deleting OIDC provider.")

    except Exception as e:
        # ResourceNotFoundException
        if str(e).find('ResourceNotFoundException') > -1:
            print(f"cluster owner {cluster_owner} not found. Deleting OIDC provider.")
            # Delete the provider
            print(f"Deleting provider {provider_arn}")
            iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
        else:
            print(f'Error checking/deleting provider {provider_arn}: {str(e)}')

# Call the function to list and potentially delete older OpenID Connect providers
def main(event, context):
    list_openid_connect_providers()

if __name__ == '__main__':
    main('', '')