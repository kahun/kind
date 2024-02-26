#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################
# Author: Stratio Clouds <clouds-integration@stratio.com>    #
# Supported provisioner versions: 0.3.X                      #
# Supported cloud providers:                                 #
#   - AWS VMs & EKS                                          #
#   - GCP VMs                                                #
#   - Azure VMs & AKS                                        #
##############################################################

__version__ = "0.4.0"

import argparse
import os
import sys
import subprocess
import yaml
import base64
import re
from datetime import datetime
from ansible_vault import Vault

CLOUD_PROVISIONER = "0.17.0-0.4.0"
CLUSTER_OPERATOR = "0.2.0-SNAPSHOT"
CLUSTER_OPERATOR_UPGRADE_SUPPORT = "0.1.7"
CLOUD_PROVISIONER_LAST_PREVIOUS_RELEASE = "0.17.0-0.3.7"

CAPI = "v1.5.3"
CAPA = "v2.2.1"
CAPG = "v1.4.0"
CAPZ = "v1.11.4"

def parse_args():
    parser = argparse.ArgumentParser(
        description='''This script upgrades a cluster installed using cloud-provisioner:0.17.0-0.2.0 to
                        ''' + CLOUD_PROVISIONER + ''' by upgrading CAPX and Calico and installing cluster-operator.
                        It requires kubectl, helm and jq binaries in $PATH.
                        A component (or all) must be selected for upgrading.
                        By default, the process will wait for confirmation for every component selected for upgrade.''',
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-y", "--yes", action="store_true", help="Do not wait for confirmation between tasks")
    parser.add_argument("-k", "--kubeconfig", help="Set the kubeconfig file for kubectl commands, It can also be set using $KUBECONFIG variable", default="~/.kube/config")
    parser.add_argument("-p", "--vault-password", help="Set the vault password file for decrypting secrets", required=True)
    parser.add_argument("-s", "--secrets", help="Set the secrets file for decrypting secrets", default="secrets.yml")
    parser.add_argument("-d", "--descriptor", help="Set the cluster descriptor file", default="cluster.yaml")
    parser.add_argument("--disable-backup", action="store_true", help="Disable backing up files before upgrading (enabled by default)")
    parser.add_argument("--disable-prepare-capsule", action="store_true", help="Disable preparing capsule for the upgrade process (enabled by default)")
    parser.add_argument("--dry-run", action="store_true", help="Do not upgrade components. This invalidates all other options")
    args = parser.parse_args()
    return vars(args)

def backup(backup_dir, namespace, cluster_name):
    print("[INFO] Backing up files into directory " + backup_dir)

    # Backup CAPX files
    os.makedirs(backup_dir + "/" + namespace, exist_ok=True)
    command = "clusterctl --kubeconfig " + kubeconfig + " -n cluster-" + cluster_name + " move --to-directory " + backup_dir + "/" + namespace + " >/dev/null 2>&1"
    status, output = subprocess.getstatusoutput(command)
    if status != 0:
        print("[ERROR] Backing up CAPX files failed:\n" + output)
        sys.exit(1)

    # Backup calico files
    os.makedirs(backup_dir + "/calico", exist_ok=True)
    command = kubectl + " get installation default -o yaml > " + backup_dir + "/calico/installation_calico.yaml"
    status, output = subprocess.getstatusoutput(command)
    if status != 0:
        print("[ERROR] Backing up Calico files failed:\n" + output)
        sys.exit(1)
    command = helm + " -n tigera-operator get values calico 2>/dev/null > " + backup_dir + "/calico/values-tigera_calico.yaml"
    status, output = subprocess.getstatusoutput(command)
    if status != 0:
        print("[ERROR] Backing up Calico files failed:\n" + output)
        sys.exit(1)

    # Backup capsule files
    os.makedirs(backup_dir + "/capsule", exist_ok=True)
    command = kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration"
    status, _ = subprocess.getstatusoutput(command)
    if status == 0:
        command = kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration -o yaml 2>/dev/null > " + backup_dir + "/capsule/capsule-mutating-webhook-configuration.yaml"
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Backing up capsule files failed:\n" + output)
            sys.exit(1)
    command = kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration"
    status, _ = subprocess.getstatusoutput(command)
    if status == 0:
        command = kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o yaml 2>/dev/null > " + backup_dir + "/capsule/capsule-validating-webhook-configuration.yaml"
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Backing up capsule files failed:\n" + output)
            sys.exit(1)

def prepare_capsule(dry_run):
    print("[INFO] Preparing capsule-mutating-webhook-configuration for the upgrade process:", end =" ", flush=True)
    command = kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration"
    status, output = subprocess.getstatusoutput(command)
    if status != 0:
        if "NotFound" in output:
            print("SKIP")
        else:
            print("[ERROR] Preparing capsule-mutating-webhook-configuration failed:\n" + output)
            sys.exit(1)
    else:
        command = (kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration -o json | " +
                '''jq -r '.webhooks[0].objectSelector |= {"matchExpressions":[{"key":"name","operator":"NotIn","values":["kube-system","tigera-operator","calico-system","cert-manager","capi-system","''' +
                namespace + '''","capi-kubeadm-bootstrap-system","capi-kubeadm-control-plane-system"]},{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["kube-system","tigera-operator","calico-system","cert-manager","capi-system","''' +
                namespace + '''","capi-kubeadm-bootstrap-system","capi-kubeadm-control-plane-system"]}]}' | ''' + kubectl + " apply -f -")
        execute_command(command, dry_run)

    print("[INFO] Preparing capsule-validating-webhook-configuration for the upgrade process:", end =" ", flush=True)
    command = kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration"
    status, _ = subprocess.getstatusoutput(command)
    if status != 0:
        if "NotFound" in output:
            print("SKIP")
        else:
            print("[ERROR] Preparing capsule-validating-webhook-configuration failed:\n" + output)
            sys.exit(1)
    else:
        command = (kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o json | " +
                '''jq -r '.webhooks[] |= (select(.name == "namespaces.capsule.clastix.io").objectSelector |= ({"matchExpressions":[{"key":"name","operator":"NotIn","values":["''' +
                namespace + '''","tigera-operator","calico-system"]},{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["''' +
                namespace + '''","tigera-operator","calico-system"]}]}))' | ''' + kubectl + " apply -f -")
        execute_command(command, dry_run)

def restore_capsule(dry_run):
    print("[INFO] Restoring capsule-mutating-webhook-configuration:", end =" ", flush=True)
    command = kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration"
    status, output = subprocess.getstatusoutput(command)
    if status != 0:
        if "NotFound" in output:
            print("SKIP")
        else:
            print("[ERROR] Restoring capsule-mutating-webhook-configuration failed:\n" + output)
            sys.exit(1)
    else:
        command = (kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration -o json | " +
                "jq -r '.webhooks[0].objectSelector |= {}' | " + kubectl + " apply -f -")
        execute_command(command, dry_run)

    print("[INFO] Restoring capsule-validating-webhook-configuration:", end =" ", flush=True)
    command = kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration"
    status, _ = subprocess.getstatusoutput(command)
    if status != 0:
        if "NotFound" in output:
            print("SKIP")
        else:
            print("[ERROR] Restoring capsule-validating-webhook-configuration failed:\n" + output)
            sys.exit(1)
    else:
        command = (kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o json | " +
                """jq -r '.webhooks[] |= (select(.name == "namespaces.capsule.clastix.io").objectSelector |= {})' """ +
                "| " + kubectl + " apply -f -")
        execute_command(command, dry_run)

def upgrade_capx(kubeconfig, managed, provider, namespace, version, env_vars, dry_run):
    print("[INFO] Upgrading " + namespace.split("-")[0] + " to " + version + " and capi to " + CAPI + ":", end =" ", flush=True)
    # Check if capx & capi are already upgraded
    capx_version = get_deploy_version(namespace.split("-")[0] + "-controller-manager", namespace, "controller")
    capi_version = get_deploy_version("capi-controller-manager", "capi-system", "controller")
    if capx_version == version and capi_version == CAPI:
        print("SKIP")
        return
    # Upgrade capx & capi
    command = (env_vars + " clusterctl upgrade apply --kubeconfig " + kubeconfig + " --wait-providers" +
                " --core capi-system/cluster-api:" + CAPI +
                " --bootstrap capi-kubeadm-bootstrap-system/kubeadm:" + CAPI +
                " --control-plane capi-kubeadm-control-plane-system/kubeadm:" + CAPI +
                " --infrastructure " + namespace + "/" + provider + ":" + version)
    execute_command(command, dry_run)

    replicas = "2"
    print("[INFO] Scaling " + namespace.split("-")[0] + "-controller-manager to " + replicas + " replicas:", end =" ", flush=True)
    command = kubectl + " -n " + namespace + " scale --replicas " + replicas + " deploy " + namespace.split("-")[0] + "-controller-manager"
    execute_command(command, dry_run)
    print("[INFO] Scaling capi-controller-manager to " + replicas + " replicas:", end =" ", flush=True)
    command = kubectl + " -n capi-system scale --replicas " + replicas + " deploy capi-controller-manager"
    execute_command(command, dry_run)

    # For AKS/EKS clusters scale capi-kubeadm-control-plane-controller-manager and capi-kubeadm-bootstrap-controller-manager to 0 replicas
    if managed:
        replicas = "0"
    print("[INFO] Scaling capi-kubeadm-control-plane-controller-manager to " + replicas + " replicas:", end =" ", flush=True)
    command = kubectl + " -n capi-kubeadm-control-plane-system scale --replicas " + replicas + " deploy capi-kubeadm-control-plane-controller-manager"
    execute_command(command, dry_run)
    print("[INFO] Scaling capi-kubeadm-bootstrap-controller-manager to " + replicas + " replicas:", end =" ", flush=True)
    command = kubectl + " -n capi-kubeadm-bootstrap-system scale --replicas " + replicas + " deploy capi-kubeadm-bootstrap-controller-manager"
    execute_command(command, dry_run)

    return

def cluster_operator(helm_repo, provider, credentials, cluster_name, dry_run):
    # Check if cluster-operator is already upgraded
    cluster_operator_version = get_chart_version("cluster-operator", "kube-system")
    if cluster_operator_version == CLUSTER_OPERATOR:
        print("[INFO] Upgrading Cluster Operator to " + CLUSTER_OPERATOR + ": SKIP")
        return
    if cluster_operator_version != None:
        # Get cluster-operator values
        command = helm + " -n kube-system get values cluster-operator -o json"
        values = execute_command(command, dry_run, False)
        cluster_operator_values = open('./clusteroperator.values', 'w')
        cluster_operator_values.write(values)
        cluster_operator_values.close()
        # Uninstall cluster-operator
        print("[INFO] Uninstalling Cluster Operator " + CLUSTER_OPERATOR + ":", end =" ", flush=True)
        command = helm + " -n kube-system uninstall cluster-operator"
        execute_command(command, dry_run)
    # Upgrade cluster-operator
    print("[INFO] Installing Cluster Operator " + CLUSTER_OPERATOR + ":", end =" ", flush=True)
    command = (helm + " -n kube-system install cluster-operator cluster-operator" +
        " --wait --version " + CLUSTER_OPERATOR + " --values ./clusteroperator.values" +
        " --set provider=" + provider +
        " --set app.containers.controllerManager.image.tag=" + CLUSTER_OPERATOR +
        " --repo " + helm_repo["url"])
    if "user" in helm_repo:
        command += " --username=" + helm_repo["user"]
        command += " --password=" + helm_repo["pass"]
    if provider == "aws":
        command += " --set secrets.common.credentialsBase64=" + credentials
    if provider == "azure":
        command += " --set secrets.azure.clientIDBase64=" + base64.b64encode(credentials["client_id"].encode("ascii")).decode("ascii")
        command += " --set secrets.azure.clientSecretBase64=" + base64.b64encode(credentials["client_secret"].encode("ascii")).decode("ascii")
        command += " --set secrets.azure.tenantIDBase64=" + base64.b64encode(credentials["tenant_id"].encode("ascii")).decode("ascii")
        command += " --set secrets.azure.subscriptionIDBase64=" + base64.b64encode(credentials["subscription_id"].encode("ascii")).decode("ascii")
    if provider == "gcp":
        command += " --set secrets.common.credentialsBase64=" + credentials
    execute_command(command, dry_run)
    os.remove('./clusteroperator.values')
    print("[INFO] Creating ClusterConfig for " + cluster_name + ":", end =" ", flush=True)
    command = kubectl + " -n cluster-" + cluster_name + " get ClusterConfig " + cluster_name
    status, _ = subprocess.getstatusoutput(command)
    if status == 0:
        print("SKIP")
    else:
        clusterConfig = {
                        "apiVersion": "installer.stratio.com/v1beta1",
                        "kind": "ClusterConfig",
                        "metadata": {
                                    "name": cluster_name,
                                    "namespace": "cluster-"+ cluster_name
                                },
                        "spec": {
                                    "private_registry": False,
                                    "cluster_operator_version": CLUSTER_OPERATOR,
                                    "cluster_operator_image_version": CLUSTER_OPERATOR
                                }
                        }
        clusterConfig_file = open('./clusterconfig.yaml', 'w')
        clusterConfig_file.write(yaml.dump(clusterConfig, default_flow_style=False))
        clusterConfig_file.close()
        command = kubectl + " apply -f clusterconfig.yaml"
        execute_command(command, dry_run)
        os.remove('./clusterconfig.yaml')
    return

def execute_command(command, dry_run, result = True):
    output = ""
    if dry_run:
        if result:
            print("DRY-RUN: " + command)
    else:
        status, output = subprocess.getstatusoutput(command)
        if status == 0:
            if result:
                print("OK")
        else:
            print("FAILED (" + output + ")")
            sys.exit(1)
    return output

def get_deploy_version(deploy, namespace, container):
    command = kubectl + " -n " + namespace + " get deploy " + deploy + " -o json  | jq -r '.spec.template.spec.containers[].image' | grep '" + container + "' | cut -d: -f2"
    output = execute_command(command, False, False)
    return output.split("@")[0]

def get_chart_version(chart, namespace):
    command = helm + " -n " + namespace + " list"
    output = execute_command(command, False, False)
    for line in output.split("\n"):
        splitted_line = line.split()
        if chart == splitted_line[0]:
            if len(splitted_line) < 10:
                return splitted_line[8].split("-")[-1]
            return splitted_line[9]
    return None

def get_version(version):
    return re.sub(r'\D', '', version)

def print_upgrade_support():
    print("[WARN] Upgrading cloud-provisioner from a version minor than " + CLOUD_PROVISIONER_LAST_PREVIOUS_RELEASE + " to " + CLOUD_PROVISIONER + " is NOT SUPPORTED")
    print("[WARN] You have to upgrade to cloud-provisioner:"+ CLOUD_PROVISIONER_LAST_PREVIOUS_RELEASE + " first")
    sys.exit(0)

def verify_upgrade():
    print("[INFO] Verifying upgrade process")
    cluster_operator_version = get_chart_version("cluster-operator", "kube-system")
    if cluster_operator_version == None:
        if os.path.exists('./clusteroperator.values'):
            return
        else:
            print_upgrade_support()
    patch_version = get_version(cluster_operator_version)
    if int(patch_version[:2]) < int(get_version(CLUSTER_OPERATOR)[:2]):
        if int(patch_version) != int(get_version(CLUSTER_OPERATOR_UPGRADE_SUPPORT)):
            print_upgrade_support()
    elif int(patch_version) > int(get_version(CLUSTER_OPERATOR)):
        print("[WARN] Downgrading cloud-provisioner from a version major than " + CLUSTER_OPERATOR + " is NOT SUPPORTED")
        sys.exit(0)
    return

def request_confirmation():
    enter = input("Press ENTER to continue upgrading the cluster or any other key to abort: ")
    if enter != "":
        sys.exit(0)

if __name__ == '__main__':
    # Init variables
    keos_registry = ""
    docker_registries = []
    backup_dir = "./backup/upgrade/"
    binaries = ["clusterctl", "kubectl", "helm", "jq"]
    helm_repo = {}

    # Parse arguments
    config = parse_args()

    # Set kubeconfig
    if os.environ.get("KUBECONFIG"):
        kubeconfig = os.environ.get("KUBECONFIG")
    else:
        kubeconfig = os.path.expanduser(config["kubeconfig"])

    # Check binaries
    for binary in binaries:
        if not subprocess.getstatusoutput("which " + binary)[0] == 0:
            print("[ERROR] " + binary + " binary not found in $PATH")
            sys.exit(1)

    # Check paths
    if not os.path.exists(config["descriptor"]):
        print("[ERROR] Descriptor file not found")
        sys.exit(1)
    if not os.path.exists(config["secrets"]):
        print("[ERROR] Secrets file not found")
        sys.exit(1)
    if not os.path.exists(kubeconfig):
        print("[ERROR] Kubeconfig file not found")
        sys.exit(1)

    print("[INFO] Using kubeconfig: " + kubeconfig)

    # Set kubectl
    kubectl = "kubectl --kubeconfig " + kubeconfig

    # Set helm
    helm = "helm --kubeconfig " + kubeconfig

    # Get cluster descriptor
    with open(config["descriptor"]) as file:
        cluster = yaml.safe_load(file)
    file.close()

    # Set cluster_name
    if "metadata" in cluster:
        cluster_name = cluster["metadata"]["name"]
    else:
        cluster_name = cluster["spec"]["cluster_id"]
    print("[INFO] Cluster name: " + cluster_name)

    # Check kubectl access
    command = kubectl + " get cl -A --no-headers | awk '{print $1}'"
    status, output = subprocess.getstatusoutput(command)
    if status != 0 or output != "cluster-" + cluster_name:
        print("[ERROR] Cluster not found. Verify the kubeconfig file")
        sys.exit(1)

    # Get secrets
    try:
        vault = Vault(config["vault_password"])
        data = vault.load(open(config["secrets"]).read())
    except Exception as e:
        print("[ERROR] Decoding secrets file failed:\n" + str(e))
        sys.exit(1)

    # Set env vars
    env_vars = "CLUSTER_TOPOLOGY=true CLUSTERCTL_DISABLE_VERSIONCHECK=true"
    provider = cluster["spec"]["infra_provider"]
    managed = cluster["spec"]["control_plane"]["managed"]
    if provider == "aws":
        namespace = "capa-system"
        version = CAPA
        credentials = subprocess.getoutput(kubectl + " -n " + namespace + " get secret capa-manager-bootstrap-credentials -o jsonpath='{.data.credentials}'")
        env_vars += " CAPA_EKS_IAM=true AWS_B64ENCODED_CREDENTIALS=" + credentials
    if provider == "gcp":
        namespace = "capg-system"
        version = CAPG
        credentials = subprocess.getoutput(kubectl + " -n " + namespace + " get secret capg-manager-bootstrap-credentials -o json | jq -r '.data[\"credentials.json\"]'")
        if managed:
            env_vars += " EXP_MACHINE_POOL=true EXP_CAPG_GKE=true"
        env_vars += " GCP_B64ENCODED_CREDENTIALS=" + credentials
    if provider == "azure":
        namespace = "capz-system"
        version = CAPZ
        if managed:
            env_vars += " EXP_MACHINE_POOL=true"
        if "credentials" in data["secrets"]["azure"]:
            credentials = data["secrets"]["azure"]["credentials"]
            env_vars += " AZURE_CLIENT_ID_B64=" + base64.b64encode(credentials["client_id"].encode("ascii")).decode("ascii")
            env_vars += " AZURE_CLIENT_SECRET_B64=" + base64.b64encode(credentials["client_secret"].encode("ascii")).decode("ascii")
            env_vars += " AZURE_SUBSCRIPTION_ID_B64=" + base64.b64encode(credentials["subscription_id"].encode("ascii")).decode("ascii")
            env_vars += " AZURE_TENANT_ID_B64=" + base64.b64encode(credentials["tenant_id"].encode("ascii")).decode("ascii")
        else:
            print("[ERROR] Azure credentials not found in secrets file")
            sys.exit(1)

    if "github_token" in data["secrets"]:
        env_vars += " GITHUB_TOKEN=" + data["secrets"]["github_token"]
        helm = "GITHUB_TOKEN=" + data["secrets"]["github_token"] + " " + helm
        kubectl = "GITHUB_TOKEN=" + data["secrets"]["github_token"] + " " + kubectl

    # Set helm repository
    helm_repo["url"] = cluster["spec"]["helm_repository"]["url"]
    if "auth_required" in cluster["spec"]["helm_repository"]:
        if cluster["spec"]["helm_repository"]["auth_required"]:
            helm_repo["user"] = data["secrets"]["helm_repository"]["user"]
            helm_repo["pass"] = data["secrets"]["helm_repository"]["pass"]

    # Verify upgrade
    verify_upgrade()

    # Backup
    if not config["disable_backup"]:
        now = datetime.now()
        backup_dir = backup_dir + now.strftime("%Y%m%d-%H%M%S")
        backup(backup_dir, namespace, cluster_name)

    # Prepare capsule
    if not config["disable_prepare_capsule"]:
        prepare_capsule(config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    # CAPX
    upgrade_capx(kubeconfig, managed, provider, namespace, version, env_vars, config["dry_run"])
    if not config["yes"]:
        request_confirmation()

    # Cluster Operator
    cluster_operator(helm_repo, provider, credentials, cluster_name, config["dry_run"])
    if not config["yes"]:
        request_confirmation()

    # Restore capsule
    if not config["disable_prepare_capsule"]:
        restore_capsule(config["dry_run"])

    print("[INFO] Upgrade process finished successfully")
