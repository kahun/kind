#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# TODO: Don't prepare capsule if doesn't exist

##############################################################
# Author: Stratio Clouds <clouds-integration@stratio.com>    #
# Date: 03/11/2023                                           #
# Version: 0.3.0                                             #
# Supported provisioner versions: 0.2.0                      #
# Supported providers: EKS, GCP                              #
##############################################################

__version__ = "0.3.0"

import argparse
import os
import json
import sys
import subprocess
import yaml
from datetime import datetime
from ansible_vault import Vault

# Versions
CAPA_VERSION = "v2.2.1"
CAPG_VERSION = "v1.4.0"
CAPI_VERSION = "v1.5.1"
CALICO_VERSION = "v3.26.1"
CALICO_NODE_VERSION = "v1.30.5"
CLUSTER_OPERATOR = "0.1.3"

def parse_args():
    parser = argparse.ArgumentParser(
        description='''This script upgrades a cluster installed using cloud-provisioner:0.17.0-0.2.0 to
                        0.17.0-0.3.3 by upgrading CAPX and Calico and installing cluster-operator.
                        It requires kubectl, helm and jq binaries in $PATH.
                        A component (or all) must be selected for upgrading.
                        By default, the process will wait for confirmation for every component selected for upgrade.''',
                                    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-a", "--all", action="store_true", help="Upgrade all components")
    parser.add_argument("-y", "--yes", action="store_true", help="Do not wait for confirmation between tasks")
    parser.add_argument("-k", "--kubeconfig", help="Set the kubeconfig file for kubectl commands, It can also be set using $KUBECONFIG variable", default="~/.kube/config")
    parser.add_argument("-p", "--vault-password", help="Set the vault password file for decrypting secrets", required=True)
    parser.add_argument("-s", "--secrets", help="Set the secrets file for decrypting secrets", default="secrets.yml")
    parser.add_argument("-d", "--descriptor", help="Set the cluster descriptor file", default="cluster.yaml")
    parser.add_argument("--helm-repo", help="Set the helm repository for installing cluster-operator", required=True)
    parser.add_argument("--helm-user", help="Set the helm repository user for installing cluster-operator")
    parser.add_argument("--helm-password", help="Set the helm repository password for installing cluster-operator")
    parser.add_argument("--disable-backup", action="store_true", help="Disable backing up files before upgrading (enabled by default)")
    parser.add_argument("--only-capx", action="store_true", help="Upgrade only CAPx components")
    parser.add_argument("--only-calico", action="store_true", help="Upgrade only Calico components")
    parser.add_argument("--only-cluster-operator", action="store_true", help="Install only Cluster Operator")
    parser.add_argument("--only-cluster-operator-descriptor", action="store_true", help="Create only Cluster Operator descriptor")
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
    command = kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration -o yaml 2>/dev/null > " + backup_dir + "/capsule/capsule-mutating-webhook-configuration.yaml"
    status, output = subprocess.getstatusoutput(command)
    if status != 0:
        print("[ERROR] Backing up capsule files failed:\n" + output)
        sys.exit(1)
    command = kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o yaml 2>/dev/null > " + backup_dir + "/capsule/capsule-validating-webhook-configuration.yaml"
    status, output = subprocess.getstatusoutput(command)
    if status != 0:
        print("[ERROR] Backing up capsule files failed:\n" + output)
        sys.exit(1)

def prepare_capsule(dry_run):
    print("[INFO] Preparing the Capsule webhook for the upgrade process")

    # Get capsule version
    command = (kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration -o json | " +
               '''jq -r '.webhooks[0].objectSelector |= {"matchExpressions":[{"key":"name","operator":"NotIn","values":["kube-system","tigera-operator","calico-system","cert-manager","capi-system","''' +
               namespace + '''","capi-kubeadm-bootstrap-system","capi-kubeadm-control-plane-system"]},{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["kube-system","tigera-operator","calico-system","cert-manager","capi-system","''' +
               namespace + '''","capi-kubeadm-bootstrap-system","capi-kubeadm-control-plane-system"]}]}' | ''' + kubectl + " apply -f -")
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Getting capsule version failed:\n" + output)
            sys.exit(1)
    command = (kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o json | " +
               '''jq -r '.webhooks[] |= (select(.name == "namespaces.capsule.clastix.io").objectSelector |= ({"matchExpressions":[{"key":"name","operator":"NotIn","values":["''' +
               namespace + '''","tigera-operator","calico-system"]},{"key":"kubernetes.io/metadata.name","operator":"NotIn","values":["''' +
               namespace + '''","tigera-operator","calico-system"]}]}))' | ''' + kubectl + " apply -f -")
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Getting capsule version failed:\n" + output)
            sys.exit(1)

def restore_capsule(dry_run):
    print("[INFO] Restoring the Capsule webhooks")

    command = (kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration -o json | " +
               "jq -r '.webhooks[0].objectSelector |= {}' | " + kubectl + " apply -f -")
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Restoring capsule webhooks failed:\n" + output)
            sys.exit(1)

    command = (kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o json | " +
               """jq -r '.webhooks[] |= (select(.name == "namespaces.capsule.clastix.io").objectSelector |= {})' """ +
               "| " + kubectl + " apply -f -")
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Restoring capsule webhooks failed:\n" + output)
            sys.exit(1)

def upgrade_capx(kubeconfig, provider, namespace, version, env_vars, dry_run):
    print("[INFO] Upgrading CAPX")

    # Update GlobalNetworkPolicy
    if provider == "aws":
        gnp = """
---
apiVersion: crd.projectcalico.org/v1
kind: GlobalNetworkPolicy
metadata:
  name: allow-traffic-to-aws-imds-capa
spec:
  egress:
  - action: Allow
    destination:
      nets:
      - 169.254.169.254/32
    protocol: TCP
  order: 0
  namespaceSelector: kubernetes.io/metadata.name in { 'kube-system', 'capa-system' }
  selector: app.kubernetes.io/name == 'aws-ebs-csi-driver' || cluster.x-k8s.io/provider == 'infrastructure-aws' || k8s-app == 'aws-cloud-controller-manager'
  types:
  - Egress
"""
    if provider == "gcp":
        gnp = """
---
apiVersion: crd.projectcalico.org/v1
kind: GlobalNetworkPolicy
metadata:
  name: allow-traffic-to-gcp-imds-capg
spec:
  egress:
  - action: Allow
    destination:
      nets:
      - 169.254.169.254/32
    protocol: TCP
  order: 0
  namespaceSelector: kubernetes.io/metadata.name in { 'kube-system', 'capg-system' }
  selector: app == 'gcp-compute-persistent-disk-csi-driver' || cluster.x-k8s.io/provider == 'infrastructure-gcp'
  types:
  - Egress
"""
    command = "cat <<EOF | " + kubectl + " apply -f -" + gnp + "EOF"
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Updating GlobalNetworkPolicy failed:\n" + output)
            sys.exit(1)

    # Check capx version
    command = kubectl + " -n " + namespace + " get deploy -o json  | jq -r '.items[0].spec.template.spec.containers[].image' 2>/dev/null | cut -d: -f2"
    status, output = subprocess.getstatusoutput(command)
    if status == 0 and output == version:
        print("[INFO] CAPX is already at the latest version (" + version + ")")
        return
    elif status != 0:
        print("[ERROR] Getting CAPX version failed:\n" + output)
        sys.exit(1)

    # Upgrade capx
    command = (env_vars + " clusterctl upgrade apply --kubeconfig " + kubeconfig + " --wait-providers" +
        " --core capi-system/cluster-api:" + CAPI_VERSION +
        " --bootstrap capi-kubeadm-bootstrap-system/kubeadm:" + CAPI_VERSION +
        " --control-plane capi-kubeadm-control-plane-system/kubeadm:" + CAPI_VERSION +
        " --infrastructure " + namespace + "/" + provider + ":" + version)
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] CAPX upgrade failed:\n" + output)
            sys.exit(1)

	# Scale CAPX to 2 replicas
    command = kubectl + " -n " + namespace + " scale --replicas 2 deploy " + namespace.split("-")[0] + "-controller-manager"
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] CAPX scale failed:\n" + output)
            sys.exit(1)

    # Scale CAPI to 2 replicas
    command = kubectl + " -n capi-system scale --replicas 2 deploy capi-controller-manager"
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] CAPI scale failed:\n" + output)
            sys.exit(1)

def upgrade_calico(dry_run):
    print("[INFO] Upgrading Calico")

    # Apply the v3.26 CRDs
    if not dry_run:
        command = kubectl + " apply --server-side --force-conflicts -f https://raw.githubusercontent.com/projectcalico/calico/" + CALICO_VERSION + "/manifests/operator-crds.yaml"
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Applying Calico CRDs failed:\n" + output)
            sys.exit(1)

    # Get the current calico values
    values = subprocess.getoutput(helm + " -n tigera-operator get values calico -o json")
    values = values.replace("v3.25.1", CALICO_VERSION)
    values = values.replace("v1.29.3", CALICO_NODE_VERSION)

    # Write calico values to file
    calico_values = open('./calico.values', 'w')
    calico_values.write(values)
    calico_values.close()

    # Add calico repo
    status, output = subprocess.getstatusoutput(helm + " repo list | grep '^projectcalico'")
    if not dry_run and status != 0:
        status, output = subprocess.getstatusoutput(helm + " repo add projectcalico https://docs.projectcalico.org/charts")
        if status != 0:
            print("[ERROR] Adding calico repo failed:\n" + output)
            sys.exit(1)

    # Update calico repo
    if not dry_run:
        subprocess.getstatusoutput(helm + " repo update projectcalico")

    # Upgrade calico
    if not dry_run:
        command = helm + " -n tigera-operator upgrade calico projectcalico/tigera-operator --wait --version " + CALICO_VERSION + " --values ./calico.values"
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Calico upgrade failed:\n" + output)
            sys.exit(1)

    # Delete calico values file
    os.remove("./calico.values")

def install_cluster_operator(helm_repo, keos_registry, docker_registries, dry_run):
    print("[INFO] Installing Cluster Operator")

    # Create keoscluster-registries secret
    if not dry_run:
        command = kubectl + " -n kube-system get secret keoscluster-registries"
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            command = kubectl + " -n kube-system create secret generic keoscluster-registries --from-literal=credentials='" + str(docker_registries) + "'"
            status, output = subprocess.getstatusoutput(command)
            if status != 0:
                print("[ERROR] Creating keoscluster-registries secret failed:\n" + output)
                sys.exit(1)

    # Install cluster operator
    command = (helm + " install --wait cluster-operator cluster-operator --namespace kube-system" +
        " --version " + CLUSTER_OPERATOR + " --repo " + helm_repo["url"] +
        " --set app.containers.controllerManager.image.registry=" + keos_registry +
        " --set app.containers.controllerManager.image.repository=stratio/cluster-operator" +
        " --set app.containers.controllerManager.image.tag=" + CLUSTER_OPERATOR +
        " --set app.replicas=2")
    if "user" in helm_repo:
        command += " --username=" + helm_repo["user"]
        command += " --password=" + helm_repo["pass"]
    if not dry_run:
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("[ERROR] Installing Cluster Operator failed:\n" + output)
            sys.exit(1)

def create_cluster_operator_descriptor(cluster, cluster_name, helm_repo):
    print("[INFO] Creating Cluster Operator descriptor")

    keoscluster = cluster
    keoscluster["apiVersion"] = "installer.stratio.com/v1beta1"
    keoscluster["kind"] = "KeosCluster"
    keoscluster["metadata"] = {"name": cluster_name, "namespace": "cluster-" + cluster_name, "finalizers": ["cluster-finalizer"]}
    if "cluster_id" in keoscluster["spec"]:
        keoscluster["spec"].pop("cluster_id")
    if "external_domain" not in keoscluster["spec"]:
        keoscluster["spec"]["external_domain"] = "domain.ext"
    if "storageclass" in keoscluster["spec"]:
        keoscluster["spec"].pop("storageclass")
    if "keos" in keoscluster["spec"]:
        keoscluster["spec"].pop("keos")
    if "aws" in keoscluster["spec"]["control_plane"]:
        if "logging" in keoscluster["spec"]["control_plane"]["aws"]:
            for k in ["api_server", "audit", "authenticator", "controller_manager", "scheduler"]:
                if k not in keoscluster["spec"]["control_plane"]["aws"]["logging"]:
                    keoscluster["spec"]["control_plane"]["aws"]["logging"][k] = False
    if "security" in keoscluster["spec"]:
        if "aws" in keoscluster["spec"]["security"]:
            keoscluster["spec"]["security"].pop("aws")
        if keoscluster["spec"]["security"] == {}:
            keoscluster["spec"].pop("security")
    keoscluster["spec"]["helm_repository"] = {"url": helm_repo["url"]}
    if "user" in helm_repo:
        keoscluster["spec"]["helm_repository"]["auth_required"] = True
    else:
        keoscluster["spec"]["helm_repository"]["auth_required"] = False
    keoscluster["metadata"]["annotations"] = {"cluster-operator.stratio.com/last-configuration": json.dumps(keoscluster, indent=None)}
    keoscluster_file = open('./keoscluster.yaml', 'w')
    keoscluster_file.write(yaml.dump(keoscluster, default_flow_style=False))
    keoscluster_file.close()
    status, output = subprocess.getstatusoutput(kubectl + " apply -f ./keoscluster.yaml")
    if status != 0:
        print("[ERROR] Creating Cluster Operator descriptor failed:\n" + output)
        sys.exit(1)

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
    print("[INFO] Cluster name is " + cluster_name)

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

    # Get docker registries info
    for registry in cluster["spec"]["docker_registries"]:
        # Get keos registry url
        if registry["keos_registry"]:
            keos_registry = registry["url"]
        if registry["type"] == "generic" and registry["auth_required"]:
            # Get docker registries credentials
            if "docker_registries" in data["secrets"]:
                docker_registries = data["secrets"]["docker_registries"]
            else:
                print("[ERROR] Docker registries credentials not found in secrets file")
                sys.exit(1)

    # Set env vars
    if "aws" in data["secrets"]:
        provider = "aws"
        namespace = "capa-system"
        version = CAPA_VERSION
        credentials = subprocess.getoutput(kubectl + " -n " + namespace + " get secret capa-manager-bootstrap-credentials -o json | jq -r .data.credentials")
        env_vars = "CLUSTER_TOPOLOGY=true CLUSTERCTL_DISABLE_VERSIONCHECK=true CAPA_EKS_IAM=true AWS_B64ENCODED_CREDENTIALS=" + credentials
    elif "gcp" in data["secrets"]:
        provider = "gcp"
        namespace = "capg-system"
        version = CAPG_VERSION
        credentials = subprocess.getoutput(kubectl + " -n " + namespace + " get secret capg-manager-bootstrap-credentials -o json | jq -r '.data[\"credentials.json\"]'")
        env_vars = "CLUSTER_TOPOLOGY=true CLUSTERCTL_DISABLE_VERSIONCHECK=true GCP_B64ENCODED_CREDENTIALS=" + credentials

    if data["secrets"]["github_token"] != "":
        env_vars += " GITHUB_TOKEN=" + data["secrets"]["github_token"]
        helm = "GITHUB_TOKEN=" + data["secrets"]["github_token"] + " " + helm

    # Set helm repo
    helm_repo["url"] = config["helm_repo"]
    if config["helm_user"] != None:
        if config["helm_password"] == None:
            print("[ERROR] Helm password must be set if helm user is set")
            sys.exit(1)
        helm_repo["user"] = config["helm_user"]
    if config["helm_password"] != None:
        if config["helm_user"] == None:
            print("[ERROR] Helm user must be set if helm password is set")
            sys.exit(1)
        helm_repo["pass"] = config["helm_password"]
        # Save helm repo credentials to secrets file
        if "helm_repository" not in data["secrets"]:
            data["secrets"]["helm_repository"] = helm_repo
            vault.dump(data, open(config["secrets"], 'w'))

    if not config["disable_backup"]:
        now = datetime.now()
        backup_dir = backup_dir + now.strftime("%Y%m%d-%H%M%S")
        backup(backup_dir, namespace, cluster_name)

    prepare_capsule(config["dry_run"])
    if not config["yes"]:
        request_confirmation()

    if config["all"] or config["only_capx"]:
        upgrade_capx(kubeconfig, provider, namespace, version, env_vars, config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_calico"]:
        upgrade_calico(config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_cluster_operator"]:
        install_cluster_operator(helm_repo, keos_registry, docker_registries, config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_cluster_operator_descriptor"]:
        create_cluster_operator_descriptor(cluster, cluster_name, helm_repo)
        if not config["yes"]:
            request_confirmation()

    restore_capsule(config["dry_run"])
