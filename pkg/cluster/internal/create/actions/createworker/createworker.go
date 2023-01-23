/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package createworker implements the create worker action
package createworker

import (
	"bytes"
	"os"

	"gopkg.in/yaml.v3"

	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions"
	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions/cluster"
	"sigs.k8s.io/kind/pkg/errors"
)

type action struct{}

// SecretsFile represents the YAML structure in the secrets.yaml file
type SecretsFile struct {
	Secrets struct {
		AWS struct {
			Credentials struct {
				AccessKey string `yaml:"access_key"`
				SecretKey string `yaml:"secret_key"`
				Region    string `yaml:"region"`
				AccountID string `yaml:"account_id"`
			} `yaml:"credentials"`
			B64Credentials string `yaml:"b64_credentials"`
		} `yaml:"aws"`
		GithubToken string `yaml:"github_token"`
	} `yaml:"secrets"`
}

const allowAllEgressNetPol = `
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-egress
spec:
  egress:
  - {}
  podSelector: {}
  policyTypes:
  - Egress`

const kubeconfigPath = "/kind/worker-cluster.kubeconfig"

// NewAction returns a new action for installing default CAPI
func NewAction() actions.Action {
	return &action{}
}

// Execute runs the action
func (a *action) Execute(ctx *actions.ActionContext) error {
	var err error
	// Parse the cluster descriptor
	descriptorFile, err := cluster.GetClusterDescriptor()
	if err != nil {
		return errors.Wrap(err, "failed to parse cluster descriptor")
	}

	// Get the target node
	node, err := getNodeForCAPA(ctx)

	// Read secrets.yaml file
	secretRAW, err := os.ReadFile("./secrets.yaml.clear")
	if err != nil {
		return err
	}

	var secretsFile SecretsFile
	err = yaml.Unmarshal(secretRAW, &secretsFile)
	if err != nil {
		return err
	}

	var envVars []string

	// AWS specific
	if descriptorFile.InfraProvider == "aws" {
		ctx.Status.Start("[CAPA] Ensuring IAM security 👮")
		defer ctx.Status.End(false)

		envVars = GetAWSEnvVars(secretsFile)
		createCloudFormationStack(envVars, node, kubeconfigPath)

		ctx.Status.End(true) // End [CAPA] Ensuring IAM security
	}

	// Install CAPx in local
	ctx.Status.Start("Installing CAPx in local 🎖️")
	defer ctx.Status.End(false)

	err = installCAPALocal(envVars, node, descriptorFile.InfraProvider)
	if err != nil {
		return err
	}

	ctx.Status.End(true) // End Installing CAPx in local

	ctx.Status.Start("Generating worker cluster manifests 📝")
	defer ctx.Status.End(false)

	capiClustersNamespace := "capi-clusters"

	// Generate the cluster manifest
	descriptorData, err := cluster.GetClusterManifest(*descriptorFile)
	if err != nil {
		return errors.Wrap(err, "failed to generate cluster manifests")
	}

	// Create the cluster manifests file in the container
	descriptorPath := "/kind/manifests/cluster_" + descriptorFile.ClusterID + ".yaml"
	raw := bytes.Buffer{}
	cmd := node.Command("sh", "-c", "echo \""+descriptorData+"\" > "+descriptorPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to write the cluster manifests")
	}

	ctx.Status.End(true) // End Generating worker cluster manifests

	ctx.Status.Start("Creating the worker cluster 💥")
	defer ctx.Status.End(false)

	// Create namespace for CAPI clusters (it must exists)
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "create", "ns", capiClustersNamespace)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to create cluster's Namespace")
	}
	// fmt.Println("RAW STRING: " + raw.String())

	// Apply cluster manifests
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "create", "-n", capiClustersNamespace, "-f", descriptorPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to apply manifests")
	}
	// fmt.Println("RAW STRING: " + raw.String())

	var machineHealthCheck = `
apiVersion: cluster.x-k8s.io/v1alpha3
kind: MachineHealthCheck
metadata:
  name: ` + descriptorFile.ClusterID + `-node-unhealthy
spec:
  clusterName: ` + descriptorFile.ClusterID + `
  nodeStartupTimeout: 120s
  selector:
    matchLabels:
      cluster.x-k8s.io/cluster-name: ` + descriptorFile.ClusterID + `
  unhealthyConditions:
    - type: Ready
      status: Unknown
      timeout: 60s
    - type: Ready
      status: 'False'
      timeout: 60s`

	// Create the MachineHealthCheck manifest file in the container
	machineHealthCheckPath := "/kind/machinehealthcheck.yaml"
	raw = bytes.Buffer{}
	cmd = node.Command("sh", "-c", "echo \""+machineHealthCheck+"\" > "+machineHealthCheckPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to write the MachineHealthCheck manifest")
	}

	// Enable the cluster's self-healing
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "-n", capiClustersNamespace, "apply", "-f", machineHealthCheckPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to apply the MachineHealthCheck manifest")
	}

	// Wait for the worker cluster creation
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "-n", capiClustersNamespace, "wait", "--for=condition=ready", "--timeout", "25m", "cluster", descriptorFile.ClusterID)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to create the worker Cluster")
	}

	// Wait for machines creation
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "-n", capiClustersNamespace, "wait", "--for=condition=ready", "--timeout", "20m", "--all", "md")
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to create the Machines")
	}

	ctx.Status.End(true) // End Creating the worker cluster

	ctx.Status.Start("Installing CAPx 🎖️")
	defer ctx.Status.End(false)

	// Create the allow-all-egress network policy file in the container
	allowAllEgressNetPolPath := "/kind/allow-all-egress_netpol.yaml"
	raw = bytes.Buffer{}
	cmd = node.Command("sh", "-c", "echo \""+allowAllEgressNetPol+"\" > "+allowAllEgressNetPolPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to write the allow-all-egress network policy")
	}

	// Get worker cluster's kubeconfig file (in EKS the token last 10m, which should be enough)
	raw = bytes.Buffer{}
	cmd = node.Command("sh", "-c", "clusterctl -n "+capiClustersNamespace+" get kubeconfig "+descriptorFile.ClusterID+" > "+kubeconfigPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to get the kubeconfig file")
	}

	err = installCAPAWorker(envVars, node, kubeconfigPath, descriptorFile.InfraProvider, allowAllEgressNetPolPath)
	if err != nil {
		return err
	}

	//Scale CAPI to 2 replicas
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "-n", "capi-system", "scale", "--replicas", "2", "deploy", "capi-controller-manager")
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to scale the CAPI Deployment")
	}

	// Allow egress in CAPI's Namespaces
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "-n", "capi-system", "apply", "-f", allowAllEgressNetPolPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to apply CAPI's NetworkPolicy")
	}
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "-n", "capi-kubeadm-bootstrap-system", "apply", "-f", allowAllEgressNetPolPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to apply CAPI's NetworkPolicy")
	}
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "-n", "capi-kubeadm-control-plane-system", "apply", "-f", allowAllEgressNetPolPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to apply CAPI's NetworkPolicy")
	}

	// Allow egress in cert-manager Namespace
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "-n", "cert-manager", "apply", "-f", allowAllEgressNetPolPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to apply cert-manager's NetworkPolicy")
	}

	ctx.Status.End(true) // End Installing CAPx in worker cluster

	ctx.Status.Start("Transfering the management role 🗝️")
	defer ctx.Status.End(false)

	// Create namespace for CAPI clusters (it must exists) in worker cluster
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "create", "ns", capiClustersNamespace)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to create manifests Namespace")
	}

	// EKS specific: Pivot management role to worker cluster
	raw = bytes.Buffer{}
	cmd = node.Command("sh", "-c", "clusterctl move -n "+capiClustersNamespace+" --to-kubeconfig "+kubeconfigPath)
	cmd.SetEnv("AWS_REGION="+secretsFile.Secrets.AWS.Credentials.Region,
		"AWS_ACCESS_KEY_ID="+secretsFile.Secrets.AWS.Credentials.AccessKey,
		"AWS_SECRET_ACCESS_KEY="+secretsFile.Secrets.AWS.Credentials.SecretKey,
		"AWS_B64ENCODED_CREDENTIALS="+secretsFile.Secrets.AWS.B64Credentials,
		"GITHUB_TOKEN="+secretsFile.Secrets.GithubToken)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to pivot management role to worker cluster")
	}

	ctx.Status.End(true) // End Transfering the management role

	return nil
}
