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

	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/errors"
)

func GetAWSEnvVars(secretsFile SecretsFile) []string {
	e := []string{
		"AWS_REGION=" + secretsFile.Secrets.AWS.Credentials.Region,
		"AWS_ACCESS_KEY_ID=" + secretsFile.Secrets.AWS.Credentials.AccessKey,
		"AWS_SECRET_ACCESS_KEY=" + secretsFile.Secrets.AWS.Credentials.SecretKey,
		"AWS_B64ENCODED_CREDENTIALS=" + secretsFile.Secrets.AWS.B64Credentials,
		"GITHUB_TOKEN=" + secretsFile.Secrets.GithubToken,
		"CAPA_EKS_IAM=true"}
	return e
}

func createCloudFormationStack(envVars []string, node nodes.Node, kubeconfigPath string) error {

	eksConfigData := `
	apiVersion: bootstrap.aws.infrastructure.cluster.x-k8s.io/v1alpha1
	kind: AWSIAMConfiguration
	spec:
	  bootstrapUser:
		enable: true
	  eks:
		enable: true
		iamRoleCreation: false
		defaultControlPlaneRole:
			disable: false
	  controlPlane:
		enableCSIPolicy: true
	  nodes:
		extraPolicyAttachments:
		- arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy`

	// Create the eks.config file in the container
	var raw bytes.Buffer
	eksConfigPath := "/kind/eks.config"
	cmd := node.Command("sh", "-c", "echo \""+eksConfigData+"\" > "+eksConfigPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to create eks.config")
	}

	// Run clusterawsadm with the eks.config file previously created
	// (this will create or update the CloudFormation stack in AWS)
	raw = bytes.Buffer{}
	cmd = node.Command("clusterawsadm", "bootstrap", "iam", "create-cloudformation-stack", "--config", eksConfigPath)
	cmd.SetEnv(envVars...)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to run clusterawsadm")
	}
	return nil
}
