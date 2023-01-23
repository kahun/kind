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

	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
	"sigs.k8s.io/kind/pkg/errors"
)

func getNodeForCAPA(ctx *actions.ActionContext) (nodes.Node, error) {
	allNodes, err := ctx.Nodes()
	if err != nil {
		return nil, err
	}

	controlPlanes, err := nodeutils.ControlPlaneNodes(allNodes)
	if err != nil {
		return nil, err
	}
	return controlPlanes[0], nil
}

// installCAPAWorker install CAPA in the worker cluster
func installCAPAWorker(envVars []string, node nodes.Node, kubeconfigPath string, provider, allowAllEgressNetPolPath string) error {

	// Install CAPA in worker cluster
	raw := bytes.Buffer{}
	cmd := node.Command("sh", "-c", "clusterctl --kubeconfig "+kubeconfigPath+" init --infrastructure "+provider+" --wait-providers")
	cmd.SetEnv(envVars...)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to install CAPA")
	}

	// Scale CAPA to 2 replicas
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "-n", "capa-system", "scale", "--replicas", "2", "deploy", "capa-controller-manager")
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to scale the CAPA Deployment")
	}

	// Allow egress in CAPA's Namespace
	raw = bytes.Buffer{}
	cmd = node.Command("kubectl", "--kubeconfig", kubeconfigPath, "-n", "capa-system", "apply", "-f", allowAllEgressNetPolPath)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to apply CAPA's NetworkPolicy")
	}

	// TODO STG: Disable OIDC provider

	return nil
}

// installCAPALocal installs CAPA in the local cluster
func installCAPALocal(envVars []string, node nodes.Node, provider string) error {

	// Install CAPA
	raw := bytes.Buffer{}
	cmd := node.Command("sh", "-c", "clusterctl init --infrastructure "+provider+" --wait-providers")
	cmd.SetEnv(envVars...)
	if err := cmd.SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to install CAPA")
	}
	return nil
}
