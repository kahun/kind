#!/usr/bin/env python3
# -*- coding: utf-8 -*-

##############################################################
# Author: Stratio Clouds <clouds-integration@stratio.com>    #
# Date: 14/11/2023                                           #
# Version: 0.3.1                                             #
# Supported provisioner versions: 0.2.0                      #
# Supported providers: EKS, GCP, Azure                       #
##############################################################

__version__ = "0.3.2"

import argparse
import os
import json
import sys
import subprocess
import yaml
import base64
import re
from datetime import datetime
from ansible_vault import Vault

CALICO_VERSION = "v3.26.1"
CALICO_NODE_VERSION = "v1.30.5"
AZUREDISK_CSI_DRIVER_CHART = "v1.28.3"
AZUREFILE_CSI_DRIVER_CHART = "v1.28.3"
CLOUD_PROVIDER_AZURE_CHART = "v1.26.7"

CLOUD_PROVISIONER = "0.17.0-0.3.8"
CLUSTER_OPERATOR = "0.1.8-SNAPSHOT"

CAPI = "v1.5.1"
CAPA = "v2.2.1"
CAPG = "v1.4.0"
CAPZ = "v1.10.4"

def parse_args():
    parser = argparse.ArgumentParser(
        description='''This script upgrades a cluster installed using cloud-provisioner:0.17.0-0.2.0 to
                        ''' + CLOUD_PROVISIONER + ''' by upgrading CAPX and Calico and installing cluster-operator.
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
    parser.add_argument("--disable-prepare-capsule", action="store_true", help="Disable preparing capsule for the upgrade process (enabled by default)")
    parser.add_argument("--only-pdbs", action="store_true", help="Only add PodDisruptionBudgets")
    parser.add_argument("--only-annotations", action="store_true", help="Only add annotations to evict local volumes")
    parser.add_argument("--only-capx", action="store_true", help="Only upgrade CAPx components")
    parser.add_argument("--only-calico", action="store_true", help="Only upgrade Calico components")
    parser.add_argument("--only-drivers", action="store_true", help="Only upgrade Azure drivers")
    parser.add_argument("--only-cluster-operator", action="store_true", help="Only install Cluster Operator")
    parser.add_argument("--only-cluster-operator-descriptor", action="store_true", help="Only create Cluster Operator descriptor")
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

def add_pdbs(provider, namespace, dry_run):
    pdb = ""
    capi_pdb = """
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: capi-controller-manager
  labels:
    control-plane: controller-manager
    cluster.x-k8s.io/provider: cluster-api
  namespace: capi-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      control-plane: controller-manager
      cluster.x-k8s.io/provider: cluster-api
"""
    core_dns_pdb = """
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: coredns
  labels:
    k8s-app: kube-dns
  namespace: kube-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      k8s-app: kube-dns
"""
    capi_kubeadm_pdb = """
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: capi-kubeadm-bootstrap-controller-manager
  labels:
    control-plane: controller-manager
    cluster.x-k8s.io/provider: bootstrap-kubeadm
  namespace: capi-kubeadm-bootstrap-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      control-plane: controller-manager
      cluster.x-k8s.io/provider: bootstrap-kubeadm
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: capi-kubeadm-control-plane-controller-manager
  labels:
    control-plane: controller-manager
    cluster.x-k8s.io/provider: control-plane-kubeadm
  namespace: capi-kubeadm-control-plane-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      control-plane: controller-manager
      cluster.x-k8s.io/provider: control-plane-kubeadm
"""

    if provider == "aws":
        pdb = """
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: capa-controller-manager
  labels:
    control-plane: capa-controller-manager
    cluster.x-k8s.io/provider: infrastructure-aws
  namespace: capa-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      control-plane: capa-controller-manager
      cluster.x-k8s.io/provider: infrastructure-aws
"""

    if provider == "gcp":
        pdb = """
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: capg-controller-manager
  labels:
    control-plane: capg-controller-manager
    cluster.x-k8s.io/provider: infrastructure-gcp
  namespace: capg-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      control-plane: capg-controller-manager
      cluster.x-k8s.io/provider: infrastructure-gcp
"""

    if provider == "azure":
        pdb = """
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: capz-controller-manager
  labels:
    control-plane: capz-controller-manager
    cluster.x-k8s.io/provider: infrastructure-azure
  namespace: capz-system
spec:
  minAvailable: 1
  selector:
    matchLabels:
      control-plane: capz-controller-manager
      cluster.x-k8s.io/provider: infrastructure-azure
"""

    print("[INFO] Adding PodDisruptionBudget to " + namespace.split("-")[0] + ":", end =" ", flush=True)
    command = "cat <<EOF | " + kubectl + " apply -f -" + pdb + "EOF"
    execute_command(command, dry_run)

    print("[INFO] Adding PodDisruptionBudget to capi-controller-manager:", end =" ", flush=True)
    command = "cat <<EOF | " + kubectl + " apply -f -" + capi_pdb + "EOF"
    execute_command(command, dry_run)

    if provider != "aws":
        print("[INFO] Adding PodDisruptionBudget to capi-kubeadm:", end =" ", flush=True)
        command = "cat <<EOF | " + kubectl + " apply -f -" + capi_kubeadm_pdb + "EOF"
        execute_command(command, dry_run)

    print("[INFO] Adding PodDisruptionBudget to coredns:", end =" ", flush=True)
    command = "cat <<EOF | " + kubectl + " apply -f -" + core_dns_pdb + "EOF"
    execute_command(command, dry_run)

def add_cluster_autoscaler_annotations(provider, namespace, dry_run):
    ca_annotation = "cluster-autoscaler.kubernetes.io/safe-to-evict-local-volumes"

    if provider == "aws":
        print("[INFO] Adding cluster-autoscaler annotations to coredns:", end =" ", flush=True)
        command = kubectl + ' -n kube-system patch deploy coredns -p \'{\"spec\": {\"template\": {\"metadata\": {\"annotations\": {\"' + ca_annotation + '\": \"tmp\"}}}}}\''
        execute_command(command, dry_run)

        print("[INFO] Adding cluster-autoscaler annotations to ebs-csi-controller:", end =" ", flush=True)
        command = kubectl + ' -n kube-system patch deploy ebs-csi-controller -p \'{\"spec\": {\"template\": {\"metadata\": {\"annotations\": {\"' + ca_annotation + '\": \"socket-dir\"}}}}}\''
        execute_command(command, dry_run)

    if provider == "azure":
        print("[INFO] Adding cluster-autoscaler annotations to cloud-controller-manager:", end =" ", flush=True)
        command = kubectl + ' -n kube-system patch deploy cloud-controller-manager -p \'{\"spec\": {\"template\": {\"metadata\": {\"annotations\": {\"' + ca_annotation + '\": \"etc-kubernetes,ssl-mount,msi\"}}}}}\''
        execute_command(command, dry_run)

    if provider == "gcp":
        print("[INFO] Adding cluster-autoscaler annotations to csi-gce-pd-controller:", end =" ", flush=True)
        command = kubectl + ' -n gce-pd-csi-driver patch deploy csi-gce-pd-controller -p \'{\"spec\": {\"template\": {\"metadata\": {\"annotations\": {\"' + ca_annotation + '\": \"socket-dir\"}}}}}\''
        execute_command(command, dry_run)

def upgrade_capx(kubeconfig, managed, provider, namespace, version, env_vars, dry_run):
    replicas = "2"
    gnp = ""

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

    if provider == "azure":
        print("[INFO] Setting priorityClass system-node-critical to capz-nmi daemonset:", end =" ", flush=True)
        command =  kubectl + " -n " + namespace + " get ds capz-nmi -o jsonpath='{.spec.template.spec.priorityClassName}'"
        priorityClassName = execute_command(command, dry_run, False)
        if priorityClassName == "system-node-critical":
            print("SKIP")
        else:
            command =  kubectl + " -n " + namespace + " patch ds capz-nmi -p '{\"spec\": {\"template\": {\"spec\": {\"priorityClassName\": \"system-node-critical\"}}}}' --type=merge"
            execute_command(command, dry_run, False)
            command =  kubectl + " -n " + namespace + " rollout status ds capz-nmi --timeout 120s"
            execute_command(command, dry_run)
    else:
        print("[INFO] Updating GlobalNetworkPolicy:", end =" ", flush=True)
        command = "cat <<EOF | " + kubectl + " apply -f -" + gnp + "EOF"
        execute_command(command, dry_run)

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

def upgrade_drivers(cluster, cluster_name, dry_run):
    # Azuredisk CSI driver
    print("[INFO] Upgrading Azuredisk CSI driver to " + AZUREDISK_CSI_DRIVER_CHART + ":", end =" ", flush=True)
    chart_version = subprocess.getstatusoutput(helm + " list -A | grep azuredisk-csi-driver")[1].split()[9]
    if chart_version == AZUREDISK_CSI_DRIVER_CHART:
        print("SKIP")
    else:
        chart_values = subprocess.getoutput(helm + " -n kube-system get values azuredisk-csi-driver -o json")
        f = open('./azurediskcsidriver.values', 'w')
        f.write(chart_values)
        f.close()
        command = (helm + " -n kube-system upgrade azuredisk-csi-driver azuredisk-csi-driver" +
                   " --wait --version " + AZUREDISK_CSI_DRIVER_CHART + " --values ./azurediskcsidriver.values" +
                   " --set controller.podAnnotations.\"cluster-autoscaler\\.kubernetes\\.io/safe-to-evict-local-volumes=socket-dir\\,azure-cred\"" +
                   " --repo https://raw.githubusercontent.com/kubernetes-sigs/azuredisk-csi-driver/master/charts")
        execute_command(command, dry_run)
        os.remove("./azurediskcsidriver.values")

    # Azurefile CSI driver
    status, output = subprocess.getstatusoutput(helm + " list -A | grep azurefile-csi-driver")
    if status == 0:
        chart_version = output.split()[9]
        chart_namespace = output.split()[1]
        chart_values = subprocess.getoutput(helm + " -n " + chart_namespace + " get values azurefile-csi-driver -o yaml")
        output = subprocess.getoutput(kubectl + " get csidrivers file.csi.azure.com -o yaml")
        fsGroupPolicy = yaml.safe_load(output)["spec"]["fsGroupPolicy"]
        if chart_values == "null":
            chartValuesYaml = {"feature": {}}
        else:
            chartValuesYaml = yaml.safe_load(chart_values)
            if "feature" not in chartValuesYaml:
                chartValuesYaml["feature"] = {}
        if "fsGroupPolicy" in chartValuesYaml["feature"]:
            if chartValuesYaml["feature"]["fsGroupPolicy"] != fsGroupPolicy:
                chartValuesYaml["feature"]["fsGroupPolicy"] = fsGroupPolicy
                chart_values = yaml.dump(chartValuesYaml)
        elif fsGroupPolicy != "ReadWriteOnceWithFSType":
            chartValuesYaml["feature"]["fsGroupPolicy"] = fsGroupPolicy
            chart_values = yaml.dump(chartValuesYaml)
        f = open('./azurefilecsidriver.values', 'w')
        f.write(chart_values)
        f.close()
        if chart_namespace != "kube-system":
            print("[INFO] Uninstalling Azurefile CSI driver:", end =" ", flush=True)
            command = helm + " -n " + chart_namespace + " uninstall azurefile-csi-driver"
            execute_command(command, dry_run)
            print("[INFO] Installing Azurefile CSI driver " + AZUREFILE_CSI_DRIVER_CHART + " in kube-system namespace:", end =" ", flush=True)
            command = (helm + " -n kube-system install azurefile-csi-driver azurefile-csi-driver" +
                       " --wait --version " + AZUREFILE_CSI_DRIVER_CHART + " --values ./azurefilecsidriver.values" +
                       " --set controller.podAnnotations.\"cluster-autoscaler\\.kubernetes\\.io/safe-to-evict-local-volumes=socket-dir\\,azure-cred\"" +
                       " --repo https://raw.githubusercontent.com/kubernetes-sigs/azurefile-csi-driver/master/charts")
            execute_command(command, dry_run)
        else:
            print("[INFO] Upgrading Azurefile CSI driver to " + AZUREFILE_CSI_DRIVER_CHART + ":", end =" ", flush=True)
            if chart_version == AZUREFILE_CSI_DRIVER_CHART:
                print("SKIP")
            else:
                command = (helm + " -n kube-system upgrade azurefile-csi-driver azurefile-csi-driver" +
                        " --wait --version " + AZUREFILE_CSI_DRIVER_CHART + " --values ./azurefilecsidriver.values" +
                        " --set controller.podAnnotations.\"cluster-autoscaler\\.kubernetes\\.io/safe-to-evict-local-volumes=socket-dir\\,azure-cred\"" +
                        " --repo https://raw.githubusercontent.com/kubernetes-sigs/azurefile-csi-driver/master/charts")
                execute_command(command, dry_run)
    else:
        print("[INFO] Installing Azurefile CSI driver " + AZUREFILE_CSI_DRIVER_CHART + ":", end =" ", flush=True)
        command = (helm + " -n kube-system install azurefile-csi-driver azurefile-csi-driver" +
                   " --wait --version " + AZUREFILE_CSI_DRIVER_CHART +
                   " --set controller.podAnnotations.\"cluster-autoscaler\\.kubernetes\\.io/safe-to-evict-local-volumes=socket-dir\\,azure-cred\"" +
                   " --repo https://raw.githubusercontent.com/kubernetes-sigs/azurefile-csi-driver/master/charts")
        if os.path.isfile('./azurefilecsidriver.values'):
            command += " --values ./azurefilecsidriver.values"
        execute_command(command, dry_run)
    if os.path.isfile('./azurefilecsidriver.values'):
        os.remove("./azurefilecsidriver.values")

    # Cloud provider Azure
    status, output = subprocess.getstatusoutput(helm + " list -A | grep cloud-provider-azure")
    if status == 0:
        chart_version = output.split()[8].split("-")[3]
        chart_namespace = output.split()[1]
        if chart_version == CLOUD_PROVIDER_AZURE_CHART[1:] and chart_namespace == "kube-system":
            print("SKIP")
        else:
            chart_values = subprocess.getoutput(helm + " -n " + chart_namespace + " get values cloud-provider-azure -o json")
            f = open('./cloudproviderazure.values', 'w')
            f.write(chart_values)
            f.close()
            print("[INFO] Uninstalling Cloud Provider Azure:", end =" ", flush=True)
            command = helm + " -n " + chart_namespace + " uninstall cloud-provider-azure"
            execute_command(command, dry_run)
            print("[INFO] Installing Cloud Provider Azure " + CLOUD_PROVIDER_AZURE_CHART + " in kube-system namespace:", end =" ", flush=True)
            command = (helm + " -n kube-system install cloud-provider-azure cloud-provider-azure" +
                        " --wait --version " + CLOUD_PROVIDER_AZURE_CHART + " --values ./cloudproviderazure.values" +
                        " --set cloudControllerManager.configureCloudRoutes=false" +
                        " --set cloudControllerManager.replicas=2" +
                        " --repo https://raw.githubusercontent.com/kubernetes-sigs/cloud-provider-azure/master/helm/repo")
            execute_command(command, dry_run)
    else:
            print("[INFO] Installing Cloud Provider Azure " + CLOUD_PROVIDER_AZURE_CHART + ":", end =" ", flush=True)
            command = (helm + " -n kube-system install cloud-provider-azure cloud-provider-azure" +
                        " --wait --version " + CLOUD_PROVIDER_AZURE_CHART +
                        " --set cloudControllerManager.configureCloudRoutes=false" +
                        " --set cloudControllerManager.replicas=2" +
                        " --repo https://raw.githubusercontent.com/kubernetes-sigs/cloud-provider-azure/master/helm/repo")
            if os.path.isfile('./cloudproviderazure.values'):
                command += " --values ./cloudproviderazure.values"
            else:
                podsCidrBlock = "192.168.0.0/16"
                if "networks" in cluster["spec"]:
                    if "pods_cidr" in cluster["spec"]["networks"]:
                        podsCidrBlock = cluster["spec"]["networks"]["pods_cidr"]
                command += " --set infra.clusterName=" + cluster_name + " --set 'cloudControllerManager.clusterCIDR=" + podsCidrBlock + "'"
            execute_command(command, dry_run)
    if os.path.isfile('./cloudproviderazure.values'):
        os.remove("./cloudproviderazure.values")

def upgrade_calico(dry_run):
    print("[INFO] Applying new Calico CRDs:", end =" ", flush=True)
    status, output = subprocess.getstatusoutput(helm + " list -A | grep calico")
    chart_version = output.split()[9]
    if status == 0 and chart_version == CALICO_VERSION:
        print("SKIP")
    elif status == 0:
        command = kubectl + " apply --server-side --force-conflicts -f https://raw.githubusercontent.com/projectcalico/calico/" + CALICO_VERSION + "/manifests/operator-crds.yaml"
        execute_command(command, dry_run)
    else:
        print("FAILED (" + output + ")")
        sys.exit(1)

    print("[INFO] Upgrading Calico to " + CALICO_VERSION + ":", end =" ", flush=True)
    if chart_version == CALICO_VERSION:
        print("SKIP")
    else:
        # Get the current calico values
        values = subprocess.getoutput(helm + " -n tigera-operator get values calico -o json")
        values = values.replace("v3.25.1", CALICO_VERSION)
        values = values.replace("v1.29.3", CALICO_NODE_VERSION)
        values = values.replace('"podAnnotations":{}', '"podAnnotations":{"cluster-autoscaler.kubernetes.io/safe-to-evict-local-volumes": "var-lib-calico"}')

        # Write calico values to file
        calico_values = open('./calico.values', 'w')
        calico_values.write(values)
        calico_values.close()
        command = (helm + " -n tigera-operator upgrade calico tigera-operator" +
                   " --wait --wait-for-jobs --version " + CALICO_VERSION + " --values ./calico.values" +
                   " --repo https://docs.projectcalico.org/charts")
        execute_command(command, dry_run)
        os.remove("./calico.values")

def install_cluster_operator(helm_repo, keos_registry, docker_registries, dry_run):
    print("[INFO] Creating keoscluster-registries secret:", end =" ", flush=True)
    command = kubectl + " -n kube-system get secret keoscluster-registries"
    status = subprocess.getstatusoutput(command)[0]
    if status == 0:
        print("SKIP")
    else:
        command = kubectl + " -n kube-system create secret generic keoscluster-registries --from-literal=credentials='" + json.dumps(docker_registries, separators=(',', ':')) + "'"
        execute_command(command, dry_run)

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
        " --wait --version " + CLUSTER_OPERATOR + " --repo " + helm_repo["url"] +
        " --set app.containers.controllerManager.image.registry=" + keos_registry +
        " --set app.containers.controllerManager.image.repository=stratio/cluster-operator" +
        " --set app.containers.controllerManager.image.tag=" + CLUSTER_OPERATOR +
        " --set app.replicas=2")
    if os.path.isfile('./clusteroperator.values'):
        command += " --values ./clusteroperator.values"
    if "user" in helm_repo:
        command += " --username=" + helm_repo["user"]
        command += " --password=" + helm_repo["pass"]
    execute_command(command, dry_run)
    os.remove('./clusteroperator.values')

def create_cluster_operator_descriptor(cluster, cluster_name, helm_repo, dry_run):
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
    if provider in ["azure", "gcp"]:
        if not "highly_available" in keoscluster["spec"]["control_plane"]:
            keoscluster["spec"]["control_plane"]["highly_available"] = True
        if not "managed" in keoscluster["spec"]["control_plane"]:
            keoscluster["spec"]["control_plane"]["managed"] = False
    else:
        if not "managed" in keoscluster["spec"]["control_plane"]:
            keoscluster["spec"]["control_plane"]["managed"] = True
    if "security" in keoscluster["spec"]:
        if "aws" in keoscluster["spec"]["security"]:
            keoscluster["spec"]["security"].pop("aws")
        if "nodes_identity" in keoscluster["spec"]["security"]:
            keoscluster["spec"]["security"]["control_plane_identity"] = keoscluster["spec"]["security"]["nodes_identity"]
        if keoscluster["spec"]["security"] == {}:
            keoscluster["spec"].pop("security")
    keoscluster["spec"]["helm_repository"] = {"url": helm_repo["url"]}
    if "user" in helm_repo:
        keoscluster["spec"]["helm_repository"]["auth_required"] = True
    else:
        keoscluster["spec"]["helm_repository"]["auth_required"] = False
    keoscluster["metadata"]["annotations"] = {"cluster-operator.stratio.com/last-configuration": json.dumps(keoscluster, separators=(',', ':'))}
    keoscluster_file = open('./keoscluster.yaml', 'w')
    keoscluster_file.write(yaml.dump(keoscluster, default_flow_style=False))
    keoscluster_file.close()

    print("[INFO] Applying Cluster Operator descriptor:", end =" ", flush=True)
    command = kubectl + " -n cluster-" + cluster_name + " get keoscluster " + cluster_name
    status = subprocess.getstatusoutput(command)[0]
    if status == 0:
        print("SKIP")
    else:
        command = kubectl + " apply -f ./keoscluster.yaml"
        execute_command(command, dry_run)

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

def verify_upgrade():
    print("[INFO] Verifying upgrade process")
    cluster_operator_version = get_chart_version("cluster-operator", "kube-system")
    if cluster_operator_version == None:
        return
    patch_version = get_version(cluster_operator_version)
    if int(patch_version[:2]) < int(get_version(CLUSTER_OPERATOR)[:2]):
        return
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
    env_vars = "CLUSTER_TOPOLOGY=true CLUSTERCTL_DISABLE_VERSIONCHECK=true"
    provider = cluster["spec"]["infra_provider"]
    managed = cluster["spec"]["control_plane"]["managed"]
    if "aws" in data["secrets"]:
        namespace = "capa-system"
        version = CAPA
        credentials = subprocess.getoutput(kubectl + " -n " + namespace + " get secret capa-manager-bootstrap-credentials -o jsonpath='{.data.credentials}'")
        env_vars += " CAPA_EKS_IAM=true AWS_B64ENCODED_CREDENTIALS=" + credentials
    elif "gcp" in data["secrets"]:
        namespace = "capg-system"
        version = CAPG
        credentials = subprocess.getoutput(kubectl + " -n " + namespace + " get secret capg-manager-bootstrap-credentials -o json | jq -r '.data[\"credentials.json\"]'")
        env_vars += " GCP_B64ENCODED_CREDENTIALS=" + credentials
    elif "azure" in data["secrets"]:
        namespace = "capz-system"
        version = CAPZ
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

    # Verify upgrade
    verify_upgrade()

    if not config["disable_backup"]:
        now = datetime.now()
        backup_dir = backup_dir + now.strftime("%Y%m%d-%H%M%S")
        backup(backup_dir, namespace, cluster_name)

    if not config["disable_prepare_capsule"]:
        prepare_capsule(config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_pdbs"]:
        add_pdbs(provider, namespace, config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_capx"]:
        upgrade_capx(kubeconfig, managed, provider, namespace, version, env_vars, config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if (config["all"] or config["only_drivers"]) and provider == "azure":
        upgrade_drivers(cluster, cluster_name, config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_calico"]:
        upgrade_calico(config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_annotations"]:
        add_cluster_autoscaler_annotations(provider, namespace, config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_cluster_operator"]:
        install_cluster_operator(helm_repo, keos_registry, docker_registries, config["dry_run"])
        if not config["yes"]:
            request_confirmation()

    if config["all"] or config["only_cluster_operator_descriptor"]:
        create_cluster_operator_descriptor(cluster, cluster_name, helm_repo, config["dry_run"])

    if not config["disable_prepare_capsule"]:
        restore_capsule(config["dry_run"])

    print("[INFO] Upgrade process finished successfully")
