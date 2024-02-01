import sys
import boto3
import botocore.exceptions
ec2 = boto3.resource('ec2', region_name='eu-west-1')

def get_all_unused_ebs_volumes() -> list:
    """
    Returns:
        list: Unused EBS volume list
    """
    try:
        volumes = ec2.volumes.all()
        return [volume for volume in volumes if len(volume.attachments) == 0]
    except botocore.exceptions.ClientError as e:
        print(f'Failed to create ec2 resource :{e}')
        return []

def delete_unused_ebs_volumes(unused_volume_list: list, dry_run: bool = False):
    """Delete give unused EBS volumes
    Args:
        unused_volume_list (list): List of unused volume objs
        dry_run (bool, optional): Defaults to True.
    """
    for volume in unused_volume_list:
        if not dry_run:
            volume.delete()
            print(f'Deleting {volume.id}')

def main(event, context):
    # Get all unused EBS volumes
    unused_ebs_volumes = get_all_unused_ebs_volumes()

    # Delete unused EBS volumes
    if unused_ebs_volumes:
        print('All unused EBS volumes:')
        for volume in unused_ebs_volumes:
            print(volume.id)
        delete_unused_ebs_volumes(unused_ebs_volumes)
    else:
        print('No unused EBS volume to delete')