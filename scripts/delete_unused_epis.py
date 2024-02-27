import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def read_init_params(event):
    operating_mode = event.get('operating_mode', 'report_only')
    actual_deletion = operating_mode == 'actual_deletion'
    logger.info(f'---- {"EIP deletion" if actual_deletion else "EIP report only"} mode enabled ----')
    return actual_deletion

def get_unassociated_eips(ec2_client):
    unassociated_eips = []
    eips = ec2_client.describe_addresses()['Addresses']
    for eip in eips:
        if 'AssociationId' not in eip:
            unassociated_eips.append({
                'AllocationId': eip['AllocationId']
            })
    return unassociated_eips

def batch_release_addresses(ec2_client, region_name, unassociated_eips, actual_deletion):
    for elasticip_to_release in unassociated_eips:
        allocation_id = elasticip_to_release['AllocationId']
        if actual_deletion:
            logger.info(f'Releasing unassociated EIP in region {region_name}: {allocation_id}')
            ec2_client.release_address(AllocationId=allocation_id)
        else:
            logger.info(f'Reporting unassociated EIP in region {region_name}: {allocation_id}')

def invoke_eip_cleanup(actual_deletion):
    ec2 = boto3.client('ec2')
    regions = ec2.describe_regions()['Regions']
    
    for region in regions:
        region_name = region['RegionName']
        ec2_client = boto3.client('ec2', region_name=region_name)
        logger.info('--- Checking EIPs in region ---> ' + region_name)
        unassociated_eips = get_unassociated_eips(ec2_client)
        if unassociated_eips:
            batch_release_addresses(ec2_client, region_name, unassociated_eips, actual_deletion)
        else:
            logger.info('No unassociated EIPs found in region')

def main(event, context):
    actual_deletion = read_init_params(event)
    invoke_eip_cleanup(actual_deletion)