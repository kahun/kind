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
import zlib
from datetime import datetime
from ansible_vault import Vault

CLOUD_PROVISIONER = "0.17.0-0.4.0"
CLUSTER_OPERATOR = "0.2.0"
CLUSTER_OPERATOR_UPGRADE_SUPPORT = "0.1.7"
CLOUD_PROVISIONER_LAST_PREVIOUS_RELEASE = "0.17.0-0.3.7"

AWS_LOAD_BALANCER_CONTROLLER_CHART = "1.6.2"

CLUSTERCTL = "v1.5.3"

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
    parser.add_argument("--enable-lb-controller", action="store_true", help="Install AWS Load Balancer Controller for EKS clusters (disabled by default)")
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
        print("FAILED")
        print("[ERROR] Backing up CAPX files failed:\n" + output)
        sys.exit(1)

    # Backup capsule files
    os.makedirs(backup_dir + "/capsule", exist_ok=True)
    command = kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration"
    status, _ = subprocess.getstatusoutput(command)
    if status == 0:
        command = kubectl + " get mutatingwebhookconfigurations capsule-mutating-webhook-configuration -o yaml 2>/dev/null > " + backup_dir + "/capsule/capsule-mutating-webhook-configuration.yaml"
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("FAILED")
            print("[ERROR] Backing up capsule files failed:\n" + output)
            sys.exit(1)
    command = kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration"
    status, _ = subprocess.getstatusoutput(command)
    if status == 0:
        command = kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o yaml 2>/dev/null > " + backup_dir + "/capsule/capsule-validating-webhook-configuration.yaml"
        status, output = subprocess.getstatusoutput(command)
        if status != 0:
            print("FAILED")
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
            print("FAILED")
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
            print("FAILED")
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
            print("FAILED")
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
            print("FAILED")
            print("[ERROR] Restoring capsule-validating-webhook-configuration failed:\n" + output)
            sys.exit(1)
    else:
        command = (kubectl + " get validatingwebhookconfigurations capsule-validating-webhook-configuration -o json | " +
                """jq -r '.webhooks[] |= (select(.name == "namespaces.capsule.clastix.io").objectSelector |= {})' """ +
                "| " + kubectl + " apply -f -")
        execute_command(command, dry_run)

def install_lb_controller(cluster_name, account_id, dry_run):
    print("[INFO] Installing LoadBalancer Controller:", end =" ", flush=True)
    chart_version = get_chart_version("aws-load-balancer-controller", "kube-system")
    if chart_version == AWS_LOAD_BALANCER_CONTROLLER_CHART:
        print("SKIP")
        return
    gnpPatch = {
                    "spec": {
                                "selector":
                                    "app.kubernetes.io/name in {'aws-ebs-csi-driver', 'aws-load-balancer-controller' } || " +
                                    "cluster.x-k8s.io/provider == 'infrastructure-aws' || " +
                                    "k8s-app == 'aws-cloud-controller-manager'"
                            }
                }
    gnpPatch_file = open('./gnpPatch.yaml', 'w')
    gnpPatch_file.write(yaml.dump(gnpPatch, default_flow_style=False))
    gnpPatch_file.close()
    command = kubectl + " patch globalnetworkpolicy allow-traffic-to-aws-imds-capa --type merge --patch-file gnpPatch.yaml"
    execute_command(command, dry_run, False)
    os.remove('./gnpPatch.yaml')
    role_name = cluster_name + "-lb-controller-manager"
    command = (helm + " -n kube-system install aws-load-balancer-controller aws-load-balancer-controller" +
                " --wait --version " + AWS_LOAD_BALANCER_CONTROLLER_CHART +
                " --set clusterName=" + cluster_name +
                " --set podDisruptionBudget.minAvailable=1" +
                " --set serviceAccount.annotations.\"eks\\.amazonaws\\.com/role-arn\"=arn:aws:iam::" + account_id + ":role/" + role_name +
                " --repo https://aws.github.io/eks-charts")
    execute_command(command, dry_run)

def upgrade_capx(kubeconfig, managed, provider, namespace, version, env_vars, dry_run):
    print("[INFO] Upgrading " + namespace.split("-")[0] + " to " + version + " and capi to " + CAPI + ":", end =" ", flush=True)
    # Check if capx & capi are already upgraded
    capx_version = get_deploy_version(namespace.split("-")[0] + "-controller-manager", namespace, "controller")
    capi_version = get_deploy_version("capi-controller-manager", "capi-system", "controller")
    if capx_version == version and capi_version == CAPI:
        print("SKIP")
    else:
        # Upgrade capx & capi
        command = (env_vars + " clusterctl upgrade apply --kubeconfig " + kubeconfig + " --wait-providers" +
                    " --core capi-system/cluster-api:" + CAPI +
                    " --bootstrap capi-kubeadm-bootstrap-system/kubeadm:" + CAPI +
                    " --control-plane capi-kubeadm-control-plane-system/kubeadm:" + CAPI +
                    " --infrastructure " + namespace + "/" + provider + ":" + version)
        if dry_run:
            print("DRY-RUN")
        else:
            status, output = subprocess.getstatusoutput(command)
            if status == 0:
                print("OK")
            else:
                if "timeout" in output:
                    os.sleep(60)
                    execute_command(command, dry_run)
                else:
                    print("FAILED")
                    print("[ERROR] " + output)
                    sys.exit(1)
            if provider == "azure":
                command =  kubectl + " -n " + namespace + " rollout status ds capz-nmi --timeout 120s"
                execute_command(command, dry_run, False)

    deployments = [
        {"name": namespace.split("-")[0] + "-controller-manager", "namespace": namespace},
        {"name": "capi-controller-manager", "namespace": "capi-system"}
    ]
    if not managed:
        deployments.append({"name": "capi-kubeadm-control-plane-controller-manager", "namespace": "capi-kubeadm-control-plane-system"})
        deployments.append({"name": "capi-kubeadm-bootstrap-controller-manager", "namespace": "capi-kubeadm-bootstrap-system"})
    for deploy in deployments:
        print("[INFO] Setting priorityClass system-node-critical to " + deploy["name"] + ":", end =" ", flush=True)
        command =  kubectl + " -n " + deploy["namespace"] + " get deploy " + deploy["name"] + " -o jsonpath='{.spec.template.spec.priorityClassName}'"
        priorityClassName = execute_command(command, dry_run, False)
        if priorityClassName == "system-node-critical":
            print("SKIP")
        else:
            command =  kubectl + " -n " + deploy["namespace"] + " patch deploy " + deploy["name"] + " -p '{\"spec\": {\"template\": {\"spec\": {\"priorityClassName\": \"system-node-critical\"}}}}' --type=merge"
            execute_command(command, dry_run, False)
            command =  kubectl + " -n " + deploy["namespace"] + " rollout status deploy " + deploy["name"] + " --timeout 120s"
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

def cluster_operator(kubeconfig, helm_repo, provider, credentials, cluster_name, dry_run):
    # Check if cluster-operator is already upgraded
    cluster_operator_version = get_chart_version("cluster-operator", "kube-system")
    if cluster_operator_version == CLUSTER_OPERATOR:
        print("[INFO] Upgrading Cluster Operator to " + CLUSTER_OPERATOR + ": SKIP")
    else:
        print("[INFO] Applying new KeosCluster CRD:", end =" ", flush=True)
        # https://github.com/Stratio/cluster-operator/blob/master/deploy/helm/cluster-operator/crds/installer.stratio.com_keosclusters.yaml
        keoscluster_crd = "eJztXM2P27YSv+9fQaCHvgKRt5v2UPjy0G5egaAfWGSDnIon0NKszFoiVZJyuinyv3dIWWtJFj8sexctYB6CiEMOh8OZH4dDepMkuaI1+wBSMcGXBP8Pf2rg5kstNt+pBRPX25urDeP5ktw2SovqHSjRyAzewAPjTGPLqwo0zammyytCKOdCU1OtzCchmeBairIEmRTAF5tmBauGlTlIy7wbevv14ub14ga7cFrBkmxAqKzEEbHBgnGlqWGxUFoa5otMVFeqhsyMUUjR1Esy3ajlt5OlncdPyPq2ZW1rS6b0T2PKz1hpqXXZSFoOBbIExXjRlFQOSEhRmahxAr+aYWuaQY51u2laMRJC89wqjpZ3knHsdSvKpuoUlpDfleB3VK+XBKdCdaMWEmj+aKmdft71avSjGXAlRAmUO3nUa6pgwOOuV9PyQM3hrJwsdpO8b78MkwG/vlIjOSK1KEBaJe0ZvR/VHrBqm21vVmh5N+1qZGuo6HLXAVeAf3/39sM394NqXE2JJKlZZxFt6flAr5aQHFQmWa2thX5pGLatkIDGD4roNXRrC/lOBiIesJ4pIqGWoIC37jBgTEwjyolY/Q6ZXpB7kIYNUWvRlLnxGfzUyCETBWefnnjjiMIOWlINOwPdF2tLaFVkS8sGXuEAOanoI7Ixo5CG9/jZJmpBfhESsOODWJK11rVaXl8XTHe+jx5UNejlj9fWjdmq0UKq6xy2UF4rViRUZmumkXsj4RrVmFjRufX/RZV/IXdoob4cyHqwoG2x/ulZAeOlBDVLd13bWewVbaqMdt797/496Ya2izHWvtX7vqPaL4FRGOoDZLuID1JUlifwvBaoYfuRlQx7jZiqZlUxbdb9D1StNmu1ILcWEMkKSFMjRkK+IG851lZQ3qL3PfsCGE2rxCg2bgn6WD5u3GqtR+gQ2LFePTi9x5YDr8GGTBq7Ru8A4w1jVO7KtMeasqJKH7jsgRA/tK16a23H33UmH3456O4e0RTcYsRHyG/fvnn3QymyzWQj9EUNlYPk1P24AZWSPk7QucghZRUtYHqAAHul1ukGHqf7Voz/DLwwGH0zh/m2ShUCzAzBjNsYkzjsmnQiH1AcdmnKbq9K0R8eWJFKeDhk7F9pu8kcPw+fTG0slNYl5ROsA4b30WFP/m62q1IiY+hoqWB5lmKHLcMAzNV8KqI4LMAz+WidzG1Ne14eY8cITBQFUt08wlM0BeEvVRbGfa3iZmf5NRinnYsVgg6ickYRv8/Dch9YpxXlCAZn4msijbwpz8PO7dRdSXrL5mtk1sJL7ynY0+5Qa57GT6oIGPeks0c1oJ9w357r1kjzLBLwpvKp/UcJ4CHfUZbP9+nAtPGUKWm6Ncce1/S8G2gMHmCMxDJI3SgeORUrb4t1PjuO9YhY2IyUrKQrKH1cghv6EYNVouE6rc0J7oVGPMvquQOSJ4FZhc4SIa45Yvkww7Y6Td4QZCbtmjup+0VyNjEK8YamQUBzhaZrVqzLx5RuKUMpS2/85PaUFpkdGgh1PjE6lkLoHTLNxeUItHjhAMvvATGm7TfsU/eDmUcGJNNizv7Rz8CFd5IIBZ/kNr6Tz84Vjjll5FCXAn2w0UJldDKQw5M4bUq9JFo2h0jgM86cTyjK7xIPQn6kEs8bDhUjvaIoC6u33774WbrVb/pJTB3ITPGraj+Ay5d9CyWyDcahEgpm5J/SnnPqIRQy8XAa2krCKGRS252ATggKs/Ghhy9Oxbg+cyFSQsBDK6iH5usHHCTL5hpbI53BWERYFNqaPMuZ2M6TBJRpCjl9iOX2GXM/ZHLMaS4qyiaSb545rKGs0JhqoRge0ibMKZAACZt0yBLddvjk5j4DCKyPc/FPS6r5toeBTibok0YxbRIeg2D8AY9r7rTRtAsnJmU1UVtk9VRbcxI+xpo236l0O3VrYwqGv8ZOl+T/29/yxW/5X68/m39vXr3+/J+k2ID5+ObVt5+/+u8xQ3LQH4WcSvn6LbcWuUozljtO690GaFrMsTvLXjUrFO+5DtNu4SOnEDWRtkjhOje0xZ/Y6CV5Eptn9bY0h4WTj5dW8ynzJgfOdygOnw+fBHqeM153sZa2F+9zLPZirF25GOvzGuu2zp4ReQ13lyrnXhKZaHtqS/PwU5A1kumjI6rBfRROxCTQp7gEp9NmXdQpLDwaMXsunpPsEOc8In2afaaMyF8HcCz2Tisyix3p/ZGZ7PjLovhsdrSEwYx2ND5FDxmX1z7/uGdb1VCGOzLHHZvlDue5Y3fPiOtBX7Y7Kt8dyHhHbDGhTWZntP+gdGNF//S8w4gwh7AhIIu4Ib6ePYTPP4JaCt0DRLD4o6Ge7ewsUwxeN8RtFP/cC8oQNL3YvVrQZwLGfGLyzryWE87XJOGl8b7aikmDU9Tx3FglWr1uhDQZ9jS3ie5VM/1ury3+fPCKYqyaTeS6ugYNDzQ5Kcnae/M8JHRQMUl07D6zUrDT8iXDWH5EO7hoGNFHSd0RdZS2HVGHucERsZejG1HaU86osh/oD0iu96f2EflQE84XqLbt4A2qWNlnRyc9Qh08iZ9x/moDg+fKhJRU6feScmVHec/84WZ3GjbvlBPNJi29K3HvRUApz/4bzUcCVW7AiGajAG3Rs53HM3Ks9pFsXuSxSCurk+y4NdoPPzvzMvP5LBq2+VnKvLcb5kcxc26GPFM1P1iieXV7d3HxqXJx8YuLO/v9S1y8otkag4I39t1MBVy3rn7WZGMIB86ULjwODY7Dg/h0WhgTonmFcSE+SRaBDfHMgvgQzeoFc2lepAhgxVnyZCdldDyoEdHbgxyRD0eOfy2zQ5Y75HvBlOlywZQ9swumuJtcMMUvsUdWh5Q++Z5+l3/EQK7MVP8PD3R1/T9o0Gc70sZBZZuw6T3GVVpIgwu9mmb19KvzTpSdZ5G/Pl/9DatBx1E="
        if dry_run:
            print("DRY-RUN")
        else:
            p = subprocess.Popen(["kubectl", "--kubeconfig", kubeconfig, "apply", "--server-side", "--force-conflicts", "-f", "-"], stdin=subprocess.PIPE, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            keoscluster_decoded = zlib.decompress(base64.b64decode(keoscluster_crd))
            _, errors = p.communicate(input=yaml.dump(yaml.safe_load(keoscluster_decoded), default_flow_style=False))
            if errors == "":
                print("OK")
            else:
                print("FAILED")
                print("[ERROR] " + errors)

        print("[INFO] Applying new ClusterConfig CRD", end =" ", flush=True)
        # https://github.com/Stratio/cluster-operator/blob/master/deploy/helm/cluster-operator/crds/installer.stratio.com_clusterconfigs.yaml
        clusterconfig_crd = "eJzFVkuP0zAQvvdXjMRhLyTdwgXlhgqHFQ+hLdpr5CST1NSxgx9lC+K/M7bTR9J0VYFW+FTPjL+Z+eaRJkkyYx1/QG24khnQb3y0KP3NpJs3JuVqvl3MNlxWGSydsaq9R6OcLvEd1lxyS5azFi2rmGXZDIBJqSzzYuOvAKWSVishUCcNynTjCiwcFxXqAL53vb1NF6/SBT2RrMUMSkHeUNPrmjcUhzSWeZDUWO3h01K1M9Nh6b00Wrkug2mjiNhH02cSwZcBPMgFN/bDue4jiYO+E04zMQ4rqAyXjRNMj5SkM6XqKJXP3n3HSqxI1iccwkn6XLeLghhcRLRyjS2LwQLQe/n2y93D69VADFChKTXvbOBuEDJwA3aNEF9ArXS4DgMHAj1gdZrcaMv3HMVz0hcn0pHnGx9ctCIFNQRG532WWPX5gKpJTpFp7DQalLFFBsDgjZgEVXzD0qawQu1hwKyVE5XvI7paQihVI/nPAzZ5VMGpYBb7ch0Pl5S1ZAK2TDh8SQ4qaNmOYLwXcPIEL5iYFD4pjfSwVhmsre1MNp833O7ngXqqddT5u3lobV44q7SZV7hFMTe8SZgu19wSutM4JxqTELoMM5G21QvdT5C5GcRqd75ZqHOpn04UoWOfqIDvWl9z1j+NWRyJ9iLPzv371VfYuw7FGLMfeD8+NMcSeMKID9SxiLVWbcBEWXWKGO47jNOrEahxRcutr/t3otb6WqWwDEsCCgTX0d7AKoU7SdIWxZIZfPYCeKZN4om9rgSn+21sHFk7Uex30oV6DWZ1RbaDuSFTrn1n03ygn4fzTbU/01PrD25MLor8uHjHBj6kmjlhM6iZMHimjqkVSglk4yHtF0nuvTMiPuctazDfTu2KJzidhPorkJhmJ5jEPK638/eXyfKnZY+5k2tkwq53UwbBhLeuzWBxezttQB/DYDCtjgn4ZdSgvpDeWSvFyPmWeiHX2NC3SE+E9w+1/KH0hih/PtoOsV2k7f/w6teRH7Rh1MnFjrxq8Glmnbl69IP1YPhVYfy+vWr6J2M4E0a8DKx2sTHoD5ymaT2VuOLwPdrH3mcCv37P/gDZnAI8"
        clusterconfig_decoded = zlib.decompress(base64.b64decode(clusterconfig_crd))
        if dry_run:
            print("DRY-RUN")
        else:
            p = subprocess.Popen(["kubectl", "--kubeconfig", kubeconfig, "apply", "--server-side", "--force-conflicts", "-f", "-"], stdin=subprocess.PIPE, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _, errors = p.communicate(input=yaml.dump(yaml.safe_load(clusterconfig_decoded), default_flow_style=False))
            if errors == "":
                print("OK")
            else:
                print("FAILED")
                print("[ERROR] " + errors)

        command = helm + " -n kube-system get values cluster-operator -o yaml"
        values = execute_command(command, dry_run, False)
        cluster_operator_values = open('./clusteroperator.values', 'w')
        cluster_operator_values.write(values)
        cluster_operator_values.close()

        # Upgrade cluster-operator
        print("[INFO] Upgrading Cluster Operator " + CLUSTER_OPERATOR + ":", end =" ", flush=True)
        command = (helm + " -n kube-system upgrade cluster-operator cluster-operator" +
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

def execute_command(command, dry_run, result = True):
    output = ""
    if dry_run:
        if result:
            print("DRY-RUN")
    else:
        status, output = subprocess.getstatusoutput(command)
        if status == 0:
            if result:
                print("OK")
        else:
            print("FAILED")
            print("[ERROR] " + output)
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
            if chart == "cluster-operator":
                return splitted_line[9]
            else:
                return splitted_line[8].split("-")[-1]
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
        if int(patch_version) < int(get_version(CLUSTER_OPERATOR_UPGRADE_SUPPORT)):
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

    command = "clusterctl version -o short"
    status, output = subprocess.getstatusoutput(command)
    if (status != 0) or (get_version(output) < get_version(CLUSTERCTL)):
        print("[ERROR] clusterctl version " + CLUSTERCTL + " is required")
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
    env_vars = "CLUSTER_TOPOLOGY=true CLUSTERCTL_DISABLE_VERSIONCHECK=true GOPROXY=off"
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
            if "user" in data["secrets"]["helm_repository"] and "pass" in data["secrets"]["helm_repository"]:
                helm_repo["user"] = data["secrets"]["helm_repository"]["user"]
                helm_repo["pass"] = data["secrets"]["helm_repository"]["pass"]
            else:
                print("[ERROR] Helm repository credentials not found in secrets file")
                sys.exit(1)

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

    # EKS LoadBalancer Controller
    if config["enable_lb_controller"]:
        if provider == "aws" and managed:
            account_id = data["secrets"]["aws"]["credentials"]["account_id"]
            install_lb_controller(cluster_name, account_id, config["dry_run"])
        else:
            print("[WARN] AWS LoadBalancer Controller is only supported for EKS managed clusters")
            sys.exit(0)
    if not config["yes"]:
        request_confirmation()

    # CAPX
    upgrade_capx(kubeconfig, managed, provider, namespace, version, env_vars, config["dry_run"])
    if not config["yes"]:
        request_confirmation()

    # Cluster Operator
    cluster_operator(kubeconfig, helm_repo, provider, credentials, cluster_name, config["dry_run"])
    if not config["yes"]:
        request_confirmation()

    # Restore capsule
    if not config["disable_prepare_capsule"]:
        restore_capsule(config["dry_run"])

    print("[INFO] Upgrade process finished successfully")
