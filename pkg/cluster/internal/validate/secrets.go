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
	"os"
	"reflect"
	"strings"

	"github.com/fatih/structs"
	"github.com/oleiade/reflections"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
)

func validateSecrets(opts ClusterOptions) (map[string]string, error) {
	var secrets commons.Secrets

	// Get secrets file if exists
	_, err := os.Stat(opts.SecretsPath)
	if err == nil {
		secretsFile, err := commons.GetSecretsFile(opts.SecretsPath, opts.VaultPassword)
		if err != nil {
			return nil, err
		}
		secrets = secretsFile.Secrets
	}

	providerSecrets, err := validateProviderCredentials(secrets, opts)
	if err != nil {
		return nil, err
	}

	if err := validateRegistryCredentials(secrets, opts.KeosCluster.Spec); err != nil {
		return nil, err
	}

	return providerSecrets, nil
}

func validateProviderCredentials(secrets interface{}, opts ClusterOptions) (map[string]string, error) {
	infraProvider := opts.KeosCluster.Spec.InfraProvider
	credentialsProvider, err := reflections.GetField(secrets, strings.ToUpper(infraProvider))
	if err != nil || reflect.DeepEqual(credentialsProvider, reflect.Zero(reflect.TypeOf(credentialsProvider)).Interface()) {
		credentialsProvider, err = reflections.GetField(opts.KeosCluster.Spec.Credentials, strings.ToUpper(infraProvider))
		if err != nil || reflect.DeepEqual(credentialsProvider, reflect.Zero(reflect.TypeOf(credentialsProvider)).Interface()) {
			return nil, errors.New("there is not " + infraProvider + " credentials in descriptor or secrets file")
		}
	} else {
		credentialsProvider, _ = reflections.GetField(credentialsProvider, "Credentials")

	}
	err = validateStruct(credentialsProvider)
	if err != nil {
		return nil, err
	}
	resultCredsMap := structs.Map(credentialsProvider)
	resultCreds := convertToMapStringString(resultCredsMap)
	return resultCreds, nil
}

func validateRegistryCredentials(secrets commons.Secrets, spec commons.Spec) error {
	var dockerRegistries []commons.DockerRegistryCredentials
	var secretsFileExists bool

	if len(secrets.DockerRegistries) > 0 {
		dockerRegistries = secrets.DockerRegistries
		secretsFileExists = true
	} else {
		dockerRegistries = spec.Credentials.DockerRegistries
		secretsFileExists = false
	}

	keosCount := 0
	for i, dockerRegistry := range spec.DockerRegistries {
		// Check if there are more than one docker_registry with the same URL
		for j, dockerRegistry2 := range spec.DockerRegistries {
			if i != j && dockerRegistry.URL == dockerRegistry2.URL {
				return errors.New("there is more than one docker_registry with the same URL: " + dockerRegistry.URL)
			}
		}
		if dockerRegistry.AuthRequired {
			existCredentials := false
			for l, dockerRegistryCredential := range dockerRegistries {
				// Check if there are more than one credential for the same registry
				for k, dockerRegistryCredential2 := range dockerRegistries {
					if l != k && dockerRegistryCredential.URL == dockerRegistryCredential2.URL {
						return errors.New("there is more than one credential for the registry: " + dockerRegistry.URL)
					}
				}
				// Check if there are valid credentials for the registry
				if dockerRegistryCredential.URL == dockerRegistry.URL {
					existCredentials = true
					err := validateStruct(dockerRegistryCredential)
					if err != nil {
						return errors.Wrap(err, "there aren't valid credentials for the registry: "+dockerRegistry.URL)
					}
				}
			}

			if !existCredentials {
				return errors.New("there aren't valid credentials for the registry: " + dockerRegistry.URL)
			}

			if dockerRegistry.KeosRegistry {
				// Check if there are more than one docker_registry defined as keos_registry
				keosCount++
				if keosCount > 1 {
					return errors.New("there are more than one docker_registry defined as keos_registry")
				}
				// Check if there are credentials for the external registry
				if secretsFileExists {
					if secrets.ExternalRegistry.User == "" || secrets.ExternalRegistry.Pass == "" {
						return errors.New("there aren't credentials for the external registry: " + dockerRegistry.URL)
					}
				}
			}
		}
	}
	return nil
}
