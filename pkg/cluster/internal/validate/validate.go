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

package validate

import (
	"sigs.k8s.io/kind/pkg/commons"
)

// TODO: return providerSecrets

type ClusterOptions struct {
	KeosCluster   commons.KeosCluster
	SecretsPath   string
	VaultPassword string
}

func Cluster(opts *ClusterOptions) error {
	var err error

	providerSecrets, err := validateSecrets(*opts)
	if err != nil {
		return err
	}

	if err := validateCommon(opts.KeosCluster.Spec); err != nil {
		return err
	}

	switch opts.KeosCluster.Spec.InfraProvider {
	case "aws":
		err = validateAWS(opts.KeosCluster, providerSecrets)
	case "gcp":
		err = validateGCP(opts.KeosCluster.Spec)
	case "azure":
		err = validateAzure(opts.KeosCluster.Spec, providerSecrets)
	}
	if err != nil {
		return err
	}

	return nil
}
