#!/usr/bin/env python3

##############################################################
# Author: Stratio Clouds <clouds-integration@stratio.com>    #
# Date: 03/01/2024                                           #
# Version: 1.0                                               #
# Supported providers: EKS, GCP, Azure                       #
##############################################################

import os
import subprocess
import sys
import boto3
import re
import argparse
from azure.cli.core import get_default_cli

# Variables
images_file = "/keos-docker-images.txt"
aws_registry = "963353511234.dkr.ecr.eu-west-1.amazonaws.com"
#aws_registry = "268367799918.dkr.ecr.eu-west-1.amazonaws.com"
azure_registry = "eosregistry.azurecr.io"
gcp_registry = "europe-docker.pkg.dev/clusterapi-369611"
bind_mount_var = os.environ['HOME'] + "/get-keos-docker-images-list.yml"

# Check parameters
def check_parameters():
    os.system("clear")

    parser = argparse.ArgumentParser(description='Upload images script.')
    parser.add_argument('-w', '--workspace', required=True, help='Workspace local path where secrets.yml and keos.yaml are located - example: /home/jnovoa/org/Work/workspace/aws/unmanaged/0.4.0')
    parser.add_argument('-p', '--provider', required=True, help='Provider (aws|azure|gcp)')
    parser.add_argument('-k', '--keos_version', required=True, help='Keos installer version - example: 1.0.4')
    parser.add_argument('-v', '--vault_password', required=True, help='Vault password - example: 123456')
    args = parser.parse_args()

    # Check if secrets.yml & keos.yaml exists
    if not os.path.exists(args.workspace + "/secrets.yml"):
        print("WARNING: 'secrets.yml' file does not exist & is needed to run keos container")
        sys.exit(1)
    if not os.path.exists(args.workspace + "/keos.yaml"):
        print("WARNING: 'keos.yaml' file does not exist & is needed to run keos container")
        sys.exit(1)
    # Ceck if provider is aws|azure|gcp
    if args.provider not in ["aws", "azure", "gcp"]:
        print("WARNING: Provider must be aws|azure|gcp")
        sys.exit(1)
    return args

# Check if container is running
def check_container_is_running():
    # Check if container is running
    try:
        # Get container list into container_list variable
        container_list = subprocess.check_output(["docker", "ps", "-a"])
        for container in container_list.splitlines():
            if container_name.encode() in container:
                print("****")
                print("Checking if container > " + container_name + " < is running ...")
                print("Removing container ...")
                # Remove old container
                os.system("docker rm -f " + container_name)
                break
    except Exception as e:
        print("Container " + container_name + " is not running")
        print("Exception: " + str(e))

# Remove keos-docker-images.txt if exists
def remove_keos_docker_images_txt():
    if os.path.exists(options.workspace  + images_file):
        os.remove(options.workspace  + images_file)
        print("****")
        print("Checking if file > " + options.workspace  + images_file + " < exists ...")
        print("Removing file ...")
        print("****")

# Run docker image (Remove bind mount ( and bind_mount_var) when new keos image is out, now 1.0.4 do not have get-keos-docker-images-list.yml fixed)
# https://github.com/Stratio/keos-installer/pull/2626/files
def run_docker_image():
        # Run container in background
        print("****")
        print("Running keos container  version > " + options.keos_version + " <")
        os.system("docker run --restart always -d -i --net host --name " + container_name + " \
        -e VAULT_MASTER_KEY=" + options.vault_password + " \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v " + options.workspace  + ":/workspace/ \
        --mount type=bind,source=" + bind_mount_var + ",target=/stratio/ansible/playbooks/utils/get-keos-docker-images-list.yml \
        qa.int.stratio.com/stratio/keos-installer:" + options.keos_version)

def get_container_id():
    print("****")
    print("Identifying container id ...")
    subprocess.call(["sleep", "5"])
    container_id = subprocess.check_output(["docker", "ps", "-aqf", "name=" + container_name ])
    print("****")
    return container_id

def run_command_in_container():
    # Run command in container and wait for it to finish use popen
    print("****")
    print("Running keos play 'get-keos-docker-images-list.yml' in container ...")
    container_id = get_container_id()
    command = "keos play /stratio/ansible/playbooks/utils/get-keos-docker-images-list.yml -e source_helm_chart_repo_url=http://qa.int.stratio.com/repository/helm-14.0-devel"
    os.system("docker exec -it " + container_id.decode("utf-8").strip() + " " + command)
    # Keos play finished
    print("Keos play finished.")
    print("****")
    subprocess.call(["sleep", "5"])

def login_registry():
    # Login to registry
    if options.provider == "aws":
        print("****")
        print("Login to AWS registry")
        os.system("aws ecr get-login-password --region eu-west-1 | docker login --username AWS --password-stdin " + aws_registry)
        print("****")
    elif options.provider == "azure":
        print("****")
        print("Login to AZURE registry")
        os.system("docker login " + azure_registry)
        print("****")
    elif options.provider == "gcp":
        print("****")
        print("Login to GCP registry")
        os.system("gcloud auth configure-docker " + gcp_registry.split("/")[0])
        print("****")

def check_repository():
    # Create list for new repositories
    new_repositories = []
    print("****")
    print("Checking if repositories exist ...")
    print("----")
    # Read images_list and check if repository exists
    with open(options.workspace + "/keos-docker-images.txt") as f:
        lines = f.readlines()
    # Remove whitespace characters like `\n` at the end of each line
    lines = [x.strip() for x in lines]
    for line in lines:
        # If line do not contains string "qa.int" do next line
        if "qa.int" not in line:
            #DEBUG print("Line do not contains string qa.int (Avoid):" + line)
            continue
        else:
            print("Original repository: " + line.split(":")[0])
            #DEBUG print(line)
            # Get the repository
            pattern = r"keos/stratio/[\w-]+"
            match = re.search(pattern, line)
            print ("Cloud Repository: " + match.group())
            if match:
                if options.provider == "aws":
                    try:
                        # Check if repository exists
                        client = boto3.client('ecr', region_name='eu-west-1')
                        response = client.describe_repositories(repositoryNames=[match.group()])
                        print("Repository exists: " + match.group())
                    except Exception as e:
                        print("Exception: " + str(e))
                        print("Repository does not exist: " + match.group())
                        #DEBUG print(e)
                        # Add repository to new_repositories list
                        new_repositories.append(match.group())
                        # Create repository
                        print("Creating repository: " + match.group())
                        # scanOnPush is False and imageTagMutability must be MUTABLE
                        client.create_repository(repositoryName=match.group(), imageScanningConfiguration={'scanOnPush': False}, imageTagMutability='MUTABLE')
                elif options.provider == "azure":
                    try:
                        # Check if repository exists
                        azure_registry_name = azure_registry.split(".")[0]
                        response = get_default_cli().invoke(['acr', 'repository', 'show', '--name', azure_registry_name, '--repository', match.group()])
                        print("Repository exists: " + match.group())
                    except SystemExit as e:
                        print("Exception: " + str(e))
                        print("Repository does not exist: " + match.group())
                        print("Upload images to repository will create it")
                        new_repositories.append(match.group())
                elif options.provider == "gcp":
                    try:
                        # Check if repository exists
                        cmd = "gcloud container images list-tags" + " " + gcp_registry + "/" + match.group()
                        response = subprocess.check_output(cmd, shell=True)
                        # Check if response contains "DIGEST" in that case repository exists (When not exists it returns "Listed 0 items.")
                        if "DIGEST" in response.decode("utf-8"):
                            print("Repository exists: " + match.group())
                        else:
                            print("Repository does not exist: " + match.group())
                            print("Upload images to repository will create it")
                            new_repositories.append(match.group())
                    except Exception as e:
                        print("Exception: " + str(e))
    f.close()
    if new_repositories:
        print("----")
        print("New repositories: ")
        for repository in new_repositories:
            print(repository)
        print("****")
    else:
        print("----")
        print("No new repositories")
        print("****")

def check_images():
    # Create a list for all images being pushed
    images_list = []
    print("****")
    print("Checking if images exist in repository ...")
    print("----")
    # Read file to get first url and tag on specific lines with "hdfs-operator" or "postgres-operator" or "kafka-operator" or "opensearch-operator"
    with open(options.workspace + "/keos-docker-images.txt") as f:
        lines = f.readlines()
    # Remove whitespace characters like `\n` at the end of each line
    lines = [x.strip() for x in lines]
    f.close()

    # Check if each file is split by " ", but not at the end of the line
    with open(options.workspace + "/keos-docker-images.txt") as f:
        lines = f.readlines()
    # Remove whitespace characters like `\n` at the end of each line
    lines = [x.strip() for x in lines]
    if options.provider == "aws":
        for line in lines:
            # If line do not contains string "qa.int" do next line
            if "qa.int" not in line:
                #DEBUG print("Line do not contains string qa.int (Avoid):" + line)
                #DEBUG print("----")
                continue
            else:
                # Check if image already exists in repository
                client = boto3.client('ecr', region_name='eu-west-1')
                try:
                    print(line)
                    repo_name = re.search(r"keos/stratio/[\w-]+", line).group()
                    #DEBUG print("repo_name: " + repo_name)
                    # Get the image tag, so search for the second ":" and get the rest of the string
                    image_tag = line.split(":")[2]
                    #DEBUG print("image_tag: " + image_tag)
                    response = client.describe_images(repositoryName=repo_name, imageIds=[{'imageTag': image_tag}])
                    if response:
                        print("Image already exists in repository: " + line.split(" ")[1])
                        continue
                except Exception as e:
                    print("Exception: " + str(e))
                    images_list.append(line.split(" ")[1])
                    pull_tag_push(line)
    elif options.provider == "azure":
        for line in lines:
            # If line do not contains string "qa.int" do next line
            if "qa.int" not in line:
                #DEBUG print("Line do not contains string qa.int (Avoid):" + line)
                continue
            else:
                # Check if image already exists in repository
                try:
                    print(line)
                    repo_name = re.search(r"keos/stratio/[\w-]+", line).group()
                    #DEBUG print("repo_name: " + repo_name)
                    # Get the image tag, so search for the second ":" and get the rest of the string
                    image_tag = line.split(":")[2]
                    #DEBUG print("image_tag: " + image_tag)
                    response = get_default_cli().invoke(['acr', 'repository', 'show', '--name', 'eosregistry', '--image', repo_name + ":" + image_tag])
                    if response:
                        print("Image already exists in repository: " + line.split(" ")[1])
                        continue
                except SystemExit as e:
                    print("Exception: " + str(e))
                    images_list.append(line.split(" ")[1])
                    pull_tag_push(line)
    elif options.provider == "gcp":
        for line in lines:
            # If line do not contains string "qa.int" do next line
            if "qa.int" not in line:
                #DEBUG print("Line do not contains string qa.int (Avoid):" + line)
                continue
            else:
                # Check if image already exists in repository
                try:
                    print(line)
                    repo_name = re.search(r"keos/stratio/[\w-]+", line).group()
                    #DEBUG print("repo_name: " + repo_name)
                    # Get the image tag, so search for the second ":" and get the rest of the string
                    image_tag = line.split(":")[2]
                    #DEBUG print("image_tag: " + image_tag)
                    response = subprocess.check_output(["gcloud", "container", "images", "list-tags", "europe-docker.pkg.dev/clusterapi-369611/" + repo_name])
                    # Command returns "Listed 0 items" if image does not exist
                    if image_tag in response.decode("utf-8"):
                        print("Image already exists in repository: " + line.split(" ")[1])
                        continue
                    else:
                        print("Image does not exist in repository: " + line.split(" ")[1])
                        images_list.append(line.split(" ")[1])
                        pull_tag_push(line)
                except Exception as e:
                    print("Exception: " + str(e))
    f.close()
    if images_list:
        print("----")
        print("Images pushed: ")
        for image in images_list:
            print(image)
        print("****")
    else:
        print("----")
        print("No images pushed")
        print("****")

def pull_tag_push(line):
    # Pull image
    os.system("docker pull " + line.split(" ")[0])
    # Tag image
    os.system("docker tag " + line.split(" ")[0] + " " + line.split(" ")[1])
    # Push image and add it to images_list
    os.system("docker push " + line.split(" ")[1])

if __name__ == "__main__":
    options = check_parameters()
    container_name = "upload-images-" + options.provider + "-" + options.keos_version
    check_container_is_running()
    remove_keos_docker_images_txt()
    run_docker_image()
    get_container_id()
    run_command_in_container()
    login_registry()
    check_repository()
    check_images()
