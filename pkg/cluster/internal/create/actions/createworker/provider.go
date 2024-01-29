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

package createworker

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
	"sigs.k8s.io/kind/pkg/exec"
)

//go:embed templates/*/*
var ctel embed.FS

//go:embed files/*/deny-all-egress-imds_gnetpol.yaml
var denyAllEgressIMDSgnpFiles embed.FS

//go:embed files/*/allow-egress-imds_gnetpol.yaml
var allowEgressIMDSgnpFiles embed.FS

//go:embed files/*/*_pdb.yaml
var commonsPDBFile embed.FS

const (
	CAPICoreProvider         = "cluster-api:v1.5.1"
	CAPIBootstrapProvider    = "kubeadm:v1.5.1"
	CAPIControlPlaneProvider = "kubeadm:v1.5.1"

	scName = "keos"

	keosClusterChart = "0.1.7-717f326"
	keosClusterImage = "0.1.7-717f326"

	postInstallAnnotation = "cluster-autoscaler.kubernetes.io/safe-to-evict-local-volumes"
	corednsPdbPath        = "/kind/coredns-pdb.yaml"
)

const machineHealthCheckWorkerNodePath = "/kind/manifests/machinehealthcheckworkernode.yaml"
const machineHealthCheckControlPlaneNodePath = "/kind/manifests/machinehealthcheckcontrolplane.yaml"
const defaultScAnnotation = "storageclass.kubernetes.io/is-default-class"

//go:embed files/common/calico-metrics.yaml
var calicoMetrics string

type PBuilder interface {
	setCapx(managed bool)
	setCapxEnvVars(p ProviderParams)
	setSC(p ProviderParams)
	installCloudProvider(n nodes.Node, k string, keosCluster commons.KeosCluster) error
	installCSI(n nodes.Node, k string) error
	getProvider() Provider
	configureStorageClass(n nodes.Node, k string) error
	getAzs(p ProviderParams, networks commons.Networks) ([]string, error)
	internalNginx(p ProviderParams, networks commons.Networks) (bool, error)
	getOverrideVars(p ProviderParams, networks commons.Networks) (map[string][]byte, error)
	postInstallPhase(n nodes.Node, k string) error
}

type Provider struct {
	capxProvider     string
	capxVersion      string
	capxImageVersion string
	capxManaged      bool
	capxName         string
	capxTemplate     string
	capxEnvVars      []string
	scParameters     commons.SCParameters
	scProvisioner    string
	csiNamespace     string
}

type Node struct {
	AZ      string
	QA      int
	MaxSize int
	MinSize int
}

type Infra struct {
	builder PBuilder
}

type ProviderParams struct {
	ClusterName  string
	Region       string
	Managed      bool
	Credentials  map[string]string
	GithubToken  string
	StorageClass commons.StorageClass
}

type DefaultStorageClass struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Annotations map[string]string `yaml:"annotations,omitempty"`
		Name        string            `yaml:"name"`
	} `yaml:"metadata"`
	AllowVolumeExpansion bool                 `yaml:"allowVolumeExpansion"`
	Provisioner          string               `yaml:"provisioner"`
	Parameters           commons.SCParameters `yaml:"parameters"`
	VolumeBindingMode    string               `yaml:"volumeBindingMode"`
}

type helmRepository struct {
	url  string
	user string
	pass string
}

type calicoHelmParams struct {
	Spec        commons.Spec
	Annotations map[string]string
}

var scTemplate = DefaultStorageClass{
	APIVersion: "storage.k8s.io/v1",
	Kind:       "StorageClass",
	Metadata: struct {
		Annotations map[string]string `yaml:"annotations,omitempty"`
		Name        string            `yaml:"name"`
	}{
		Annotations: map[string]string{
			defaultScAnnotation: "true",
		},
		Name: scName,
	},
	AllowVolumeExpansion: true,
	VolumeBindingMode:    "WaitForFirstConsumer",
}

func getBuilder(builderType string) PBuilder {
	if builderType == "aws" {
		return newAWSBuilder()
	}

	if builderType == "gcp" {
		return newGCPBuilder()
	}

	if builderType == "azure" {
		return newAzureBuilder()
	}
	return nil
}

func newInfra(b PBuilder) *Infra {
	return &Infra{
		builder: b,
	}
}

func (i *Infra) buildProvider(p ProviderParams) Provider {
	i.builder.setCapx(p.Managed)
	i.builder.setCapxEnvVars(p)
	i.builder.setSC(p)
	return i.builder.getProvider()
}

func (i *Infra) installCloudProvider(n nodes.Node, k string, keosCluster commons.KeosCluster) error {
	return i.builder.installCloudProvider(n, k, keosCluster)
}

func (i *Infra) installCSI(n nodes.Node, k string) error {
	return i.builder.installCSI(n, k)
}

func (i *Infra) configureStorageClass(n nodes.Node, k string) error {
	return i.builder.configureStorageClass(n, k)
}

func (i *Infra) internalNginx(p ProviderParams, networks commons.Networks) (bool, error) {
	return i.builder.internalNginx(p, networks)
}

func (i *Infra) getOverrideVars(p ProviderParams, networks commons.Networks) (map[string][]byte, error) {
	return i.builder.getOverrideVars(p, networks)
}

func (i *Infra) getAzs(p ProviderParams, networks commons.Networks) ([]string, error) {
	return i.builder.getAzs(p, networks)
}

func (i *Infra) postInstallPhase(n nodes.Node, k string) error {
	c := "kubectl --kubeconfig " + kubeconfigPath + " get pdb coredns -n kube-system"
	_, err := commons.ExecuteCommand(n, c, 5)
	if err != nil {
		err = installCorednsPdb(n, k)
		if err != nil {
			return err
		}
	}
	return i.builder.postInstallPhase(n, k)
}

func (p *Provider) getDenyAllEgressIMDSGNetPol() (string, error) {
	denyAllEgressIMDSGNetPolLocalPath := "files/" + p.capxProvider + "/deny-all-egress-imds_gnetpol.yaml"
	denyAllEgressIMDSgnpFile, err := denyAllEgressIMDSgnpFiles.Open(denyAllEgressIMDSGNetPolLocalPath)
	if err != nil {
		return "", errors.Wrap(err, "error opening the deny all egress IMDS file")
	}
	defer denyAllEgressIMDSgnpFile.Close()
	denyAllEgressIMDSgnpContent, err := ioutil.ReadAll(denyAllEgressIMDSgnpFile)
	if err != nil {
		return "", err
	}

	return string(denyAllEgressIMDSgnpContent), nil
}

func (p *Provider) getAllowCAPXEgressIMDSGNetPol() (string, error) {
	allowEgressIMDSGNetPolLocalPath := "files/" + p.capxProvider + "/allow-egress-imds_gnetpol.yaml"
	allowEgressIMDSgnpFile, err := allowEgressIMDSgnpFiles.Open(allowEgressIMDSGNetPolLocalPath)
	if err != nil {
		return "", errors.Wrap(err, "error opening the allow egress IMDS file")
	}
	defer allowEgressIMDSgnpFile.Close()
	allowEgressIMDSgnpContent, err := ioutil.ReadAll(allowEgressIMDSgnpFile)
	if err != nil {
		return "", err
	}

	return string(allowEgressIMDSgnpContent), nil
}

func getcapxPDB(commonsPDBLocalPath string) (string, error) {
	commonsPDBFile, err := commonsPDBFile.Open(commonsPDBLocalPath)
	if err != nil {
		return "", errors.Wrap(err, "error opening the PodDisruptionBudget file")
	}
	defer commonsPDBFile.Close()
	capaPDBContent, err := ioutil.ReadAll(commonsPDBFile)
	if err != nil {
		return "", err
	}

	return string(capaPDBContent), nil
}

func deployClusterOperator(n nodes.Node, keosCluster commons.KeosCluster, clusterCredentials commons.ClusterCredentials, keosRegistry keosRegistry, kubeconfigPath string, firstInstallation bool) error {
	var c string
	var err error
	var helmRepository helmRepository

	if kubeconfigPath == "" {
		// Clean keoscluster file
		keosCluster.Spec.Credentials = commons.Credentials{}
		keosCluster.Spec.StorageClass = commons.StorageClass{}
		keosCluster.Spec.Security.AWS = struct {
			CreateIAM bool "yaml:\"create_iam\" validate:\"boolean\""
		}{}
		if keosCluster.Spec.InfraProvider != "azure" || (keosCluster.Spec.InfraProvider == "azure" && !keosCluster.Spec.ControlPlane.Managed) {
			keosCluster.Spec.ControlPlane.Azure = commons.AzureCP{}
		}
		if keosCluster.Spec.InfraProvider != "aws" || (keosCluster.Spec.InfraProvider == "aws" && !keosCluster.Spec.ControlPlane.Managed) {
			keosCluster.Spec.ControlPlane.AWS = commons.AWSCP{}
		}
		if keosCluster.Spec.ControlPlane.Managed {
			keosCluster.Spec.ControlPlane.HighlyAvailable = nil
		}
		keosCluster.Spec.Keos = struct {
			Flavour string `yaml:"flavour,omitempty"`
			Version string `yaml:"version,omitempty"`
		}{}
		keosClusterYAML, err := yaml.Marshal(keosCluster)
		if err != nil {
			return err
		}
		// Write keoscluster file
		c = "echo '" + string(keosClusterYAML) + "' > " + manifestsPath + "/keoscluster.yaml"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to write the keoscluster file")
		}
		// Add helm repository
		helmRepository.url = keosCluster.Spec.HelmRepository.URL
		if keosCluster.Spec.HelmRepository.AuthRequired {
			helmRepository.user = clusterCredentials.HelmRepositoryCredentials["User"]
			helmRepository.pass = clusterCredentials.HelmRepositoryCredentials["Pass"]
			c = "helm repo add stratio-helm-repo " + helmRepository.url + " --username " + helmRepository.user + " --password " + helmRepository.pass
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to add and authenticate to helm repository: "+helmRepository.url)
			}
		} else {
			c = "helm repo add stratio-helm-repo " + helmRepository.url
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to add helm repository: "+helmRepository.url)
			}
		}
		if firstInstallation {
			// Pull cluster operator helm chart
			c = "helm pull stratio-helm-repo/cluster-operator --version " + keosClusterChart +
				" --untar --untardir /stratio/helm"
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to pull cluster operator helm chart")
			}
		}
	}

	// Create the docker registries credentials secret for keoscluster-controller-manager
	if clusterCredentials.DockerRegistriesCredentials != nil && firstInstallation {
		jsonDockerRegistriesCredentials, err := json.Marshal(clusterCredentials.DockerRegistriesCredentials)
		if err != nil {
			return errors.Wrap(err, "failed to marshal docker registries credentials")
		}
		c = "kubectl -n kube-system create secret generic keoscluster-registries --from-literal=credentials='" + string(jsonDockerRegistriesCredentials) + "'"
		if kubeconfigPath != "" {
			c = c + " --kubeconfig " + kubeconfigPath
		}
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create keoscluster-registries secret")
		}
	}

	// Deploy keoscluster-controller-manager chart
	c = "helm install --wait cluster-operator /stratio/helm/cluster-operator" +
		" --namespace kube-system" +
		" --set app.containers.controllerManager.image.registry=" + keosRegistry.url +
		" --set app.containers.controllerManager.image.repository=stratio/cluster-operator" +
		" --set app.containers.controllerManager.image.tag=" + keosClusterImage
	if kubeconfigPath == "" {
		c = c +
			" --set app.containers.controllerManager.imagePullSecrets.enabled=true" +
			" --set app.containers.controllerManager.imagePullSecrets.name=regcred"
	} else {
		c = c + " --set app.replicas=2" + " --kubeconfig " + kubeconfigPath
	}
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to deploy keoscluster-controller-manager chart")
	}

	// Wait for keoscluster-controller-manager deployment
	c = "kubectl -n kube-system rollout status deploy/keoscluster-controller-manager --timeout=3m"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to wait for keoscluster-controller-manager deployment")
	}

	// TODO: Change this when status is available in keoscluster-controller-manager
	time.Sleep(10 * time.Second)

	return nil
}

func installCalico(n nodes.Node, k string, keosCluster commons.KeosCluster, allowCommonEgressNetPolPath string) error {
	var c string
	var cmd exec.Cmd
	var err error

	calicoTemplate := "/kind/calico-helm-values.yaml"

	calicoHelmParams := calicoHelmParams{
		Spec: keosCluster.Spec,
		Annotations: map[string]string{
			postInstallAnnotation: "var-lib-calico",
		},
	}

	// Generate the calico helm values
	calicoHelmValues, err := getManifest("common", "calico-helm-values.tmpl", calicoHelmParams)
	if err != nil {
		return errors.Wrap(err, "failed to generate calico helm values")
	}

	c = "echo '" + calicoHelmValues + "' > " + calicoTemplate
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create Calico Helm chart values file")
	}

	c = "helm install calico /stratio/helm/tigera-operator" +
		" --kubeconfig " + k +
		" --namespace tigera-operator" +
		" --create-namespace" +
		" --values " + calicoTemplate
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to deploy Calico Helm Chart")
	}

	// Allow egress in tigera-operator namespace
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n tigera-operator apply -f " + allowCommonEgressNetPolPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply tigera-operator egress NetworkPolicy")
	}

	// Wait for calico-system namespace to be created
	c = "timeout 300s bash -c 'until kubectl --kubeconfig " + kubeconfigPath + " get ns calico-system; do sleep 2s ; done'"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to wait for calico-system namespace")
	}

	// Allow egress in calico-system namespace
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n calico-system apply -f " + allowCommonEgressNetPolPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply calico-system egress NetworkPolicy")
	}

	// Create calico metrics services
	cmd = n.Command("kubectl", "--kubeconfig", k, "apply", "-f", "-")
	if err = cmd.SetStdin(strings.NewReader(calicoMetrics)).Run(); err != nil {
		return errors.Wrap(err, "failed to create calico metrics services")
	}

	return nil
}

func customCoreDNS(n nodes.Node, k string, keosCluster commons.KeosCluster) error {
	var c string
	var err error

	coreDNSPatchFile := "coredns"
	coreDNSTemplate := "/kind/coredns-configmap.yaml"
	coreDNSSuffix := ""

	if keosCluster.Spec.InfraProvider == "azure" && keosCluster.Spec.ControlPlane.Managed {
		coreDNSPatchFile = "coredns-custom"
		coreDNSSuffix = "-aks"
	}

	coreDNSConfigmap, err := getManifest(keosCluster.Spec.InfraProvider, "coredns_configmap"+coreDNSSuffix+".tmpl", keosCluster.Spec)
	if err != nil {
		return errors.Wrap(err, "failed to get CoreDNS file")
	}

	c = "echo '" + coreDNSConfigmap + "' > " + coreDNSTemplate
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create CoreDNS configmap file")
	}

	// Patch configmap
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n kube-system patch cm " + coreDNSPatchFile + " --patch-file " + coreDNSTemplate
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to customize coreDNS patching ConfigMap")
	}

	// Rollout restart to catch the made changes
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n kube-system rollout restart deploy coredns"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to redeploy coreDNS")
	}

	// Wait until CoreDNS completely rollout
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n kube-system rollout status deploy coredns --timeout=3m"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to wait for the customatization of CoreDNS configmap")
	}

	return nil
}

// installCAPXWorker installs CAPX in the worker cluster
func (p *Provider) installCAPXWorker(n nodes.Node, kubeconfigPath string, allowAllEgressNetPolPath string) error {
	var c string
	var err error

	capxPDBPath := "/kind/" + p.capxName + "_pdb.yaml"

	if p.capxProvider == "azure" {
		// Create capx namespace
		c = "kubectl --kubeconfig " + kubeconfigPath + " create namespace " + p.capxName + "-system"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create CAPx namespace")
		}

		// Create capx secret
		secret := strings.Split(p.capxEnvVars[0], "AZURE_CLIENT_SECRET=")[1]
		c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system create secret generic cluster-identity-secret --from-literal=clientSecret='" + string(secret) + "'"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create CAPx secret")
		}
	}

	// Install CAPX in worker cluster
	c = "clusterctl --kubeconfig " + kubeconfigPath + " init --wait-providers" +
		" --core " + CAPICoreProvider +
		" --bootstrap " + CAPIBootstrapProvider +
		" --control-plane " + CAPIControlPlaneProvider +
		" --infrastructure " + p.capxProvider + ":" + p.capxVersion
	_, err = commons.ExecuteCommand(n, c, 5, p.capxEnvVars)
	if err != nil {
		return errors.Wrap(err, "failed to install CAPX in workload cluster")
	}

	// Manually assign PriorityClass to capa service
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system patch deploy " + p.capxName + "-controller-manager -p '{\"spec\": {\"template\": {\"spec\": {\"priorityClassName\": \"system-node-critical\"}}}}' --type=merge"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to assigned priorityClass to "+p.capxName+"-controller-manager")
	}
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system rollout status deploy " + p.capxName + "-controller-manager --timeout 60s"
	if err != nil {
		return errors.Wrap(err, "failed to check rollout status for "+p.capxName+"-controller-manager")
	}

	// Scale CAPX to 2 replicas
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system scale --replicas 2 deploy " + p.capxName + "-controller-manager"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to scale CAPX in workload cluster")
	}
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system rollout status deploy " + p.capxName + "-controller-manager --timeout 60s"
	if err != nil {
		return errors.Wrap(err, "failed to check rollout status for "+p.capxName+"-controller-manager")
	}

	// Define PodDisruptionBudget for capa service
	capxPDBLocalPath := "files/" + p.capxProvider + "/" + p.capxName + "_pdb.yaml"
	capxPDB, err := getcapxPDB(capxPDBLocalPath)
	if err != nil {
		return err
	}

	c = "echo \"" + capxPDB + "\" > " + capxPDBPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create "+p.capxName+"PodDisruptionBudget file")
	}

	c = "kubectl --kubeconfig " + kubeconfigPath + " apply -f " + capxPDBPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply "+p.capxName+" PodDisruptionBudget")
	}

	// Allow egress in CAPX's Namespace
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system apply -f " + allowAllEgressNetPolPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply CAPX's NetworkPolicy in workload cluster")
	}

	return nil
}

func (p *Provider) configCAPIWorker(n nodes.Node, keosCluster commons.KeosCluster, kubeconfigPath string, allowCommonEgressNetPolPath string) error {
	var c string
	var err error
	var capiKubeadmReplicas int

	capiDeployments := []struct {
		name      string
		namespace string
	}{
		{name: "capi-controller-manager", namespace: "capi-system"},
		{name: "capi-kubeadm-control-plane-controller-manager", namespace: "capi-kubeadm-control-plane-system"},
		{name: "capi-kubeadm-bootstrap-controller-manager", namespace: "capi-kubeadm-bootstrap-system"},
	}

	allowedNamePattern := regexp.MustCompile(`^capi-kubeadm-(control-plane|bootstrap)-controller-manager$`)
	capiPDBPath := "/kind/capi_pdb.yaml"

	// Determine the number of replicas for capi-kubeadm deployments
	if p.capxManaged {
		capiKubeadmReplicas = 0
	} else {
		capiKubeadmReplicas = 2
	}

	// Manually assign PriorityClass to capi services
	for _, deployment := range capiDeployments {
		if !p.capxManaged || (p.capxManaged && !allowedNamePattern.MatchString(deployment.name)) {
			c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + deployment.namespace + " patch deploy " + deployment.name + " -p '{\"spec\": {\"template\": {\"spec\": {\"priorityClassName\": \"system-node-critical\"}}}}' --type=merge"
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to assigned priorityClass to "+deployment.name)
			}
		}
	}

	// Manually assign PriorityClass to nmi
	if p.capxProvider == "azure" {
		c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system patch ds capz-nmi -p '{\"spec\": {\"template\": {\"spec\": {\"priorityClassName\": \"system-node-critical\"}}}}' --type=merge"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to assigned priorityClass to nmi")
		}
		c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system rollout status ds capz-nmi --timeout 60s"
		if err != nil {
			return errors.Wrap(err, "failed to check rollout status for nmi")
		}
	}

	// Scale number of replicas to 2 for capi service
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n capi-system scale deploy capi-controller-manager --replicas 2"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to scale the CAPI Deployment")
	}
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n capi-system rollout status deploy capi-controller-manager --timeout 60s"
	if err != nil {
		return errors.Wrap(err, "failed to check rollout status for capi-controller-manager")
	}

	// Scale number of required replicas for capi kubeadm services
	for _, deployment := range capiDeployments {
		if deployment.name != "capi-controller-manager" {
			c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + deployment.namespace + " scale --replicas " + strconv.Itoa(capiKubeadmReplicas) + " deploy " + deployment.name
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to scale the "+deployment.name+" deployment")
			}
			c = "kubectl --kubeconfig " + kubeconfigPath + " -n capi-system rollout status deploy " + deployment.name + " --timeout 60s"
			if err != nil {
				return errors.Wrap(err, "failed to check rollout status for "+deployment.name)
			}
		}
	}

	// Define PodDisruptionBudget for capi services
	capxPDB, err := getManifest("common", "capi_pdb.tmpl", keosCluster.Spec)
	if err != nil {
		return errors.Wrap(err, "failed to get PodDisruptionBudget file")
	}
	c = "echo '" + capxPDB + "' > " + capiPDBPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create PodDisruptionBudget file")
	}

	c = "kubectl --kubeconfig " + kubeconfigPath + " apply -f " + capiPDBPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply "+p.capxName+" PodDisruptionBudget")
	}

	// Allow egress in CAPI's Namespaces
	for _, deployment := range capiDeployments {
		if !p.capxManaged || (p.capxManaged && !allowedNamePattern.MatchString(deployment.name)) {
			c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + deployment.namespace + " apply -f " + allowCommonEgressNetPolPath
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to apply CAPI's egress NetworkPolicy in namespace "+deployment.namespace)
			}
		}
	}

	// Allow egress in cert-manager Namespace
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n cert-manager apply -f " + allowCommonEgressNetPolPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply cert-manager's NetworkPolicy")
	}

	return nil
}

func (p *Provider) configHACAPI(n nodes.Node, kubeconfigPath string) error {
	var c string
	var err error
	var capiKubeadmReplicas int

	// Determine the number of replicas for capi-kubeadm deployments
	if p.capxManaged {
		capiKubeadmReplicas = 0
	} else {
		capiKubeadmReplicas = 2
	}

	// Scale capi-controller-manager to 2 replicas
	c = fmt.Sprintf("kubectl --kubeconfig %s -n capi-system scale --replicas 2 deploy capi-controller-manager", kubeconfigPath)
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to scale the CAPI Deployment")
	}

	// Scale capi-kubeadm-control-plane to 2 replicas
	c = fmt.Sprintf("kubectl --kubeconfig %s -n capi-kubeadm-control-plane-system scale --replicas %d deploy capi-kubeadm-control-plane-controller-manager", kubeconfigPath, capiKubeadmReplicas)
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to scale the capi-kubeadm-control-plane Deployment")
	}

	// Scale capi-kubeadm-bootstrap to 2 replicas
	c = fmt.Sprintf("kubectl --kubeconfig %s -n capi-kubeadm-bootstrap-system scale --replicas %d deploy capi-kubeadm-bootstrap-controller-manager", kubeconfigPath, capiKubeadmReplicas)
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to scale the capi-kubeadm-bootstrap Deployment")
	}
	return nil
}

// installCAPXLocal installs CAPX in the local cluster
func (p *Provider) installCAPXLocal(n nodes.Node) error {
	var c string
	var err error

	if p.capxProvider == "azure" {
		// Create capx namespace
		c = "kubectl create namespace " + p.capxName + "-system"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create CAPx namespace")
		}

		// Create capx secret
		secret := strings.Split(p.capxEnvVars[0], "AZURE_CLIENT_SECRET=")[1]
		c = "kubectl -n " + p.capxName + "-system create secret generic cluster-identity-secret --from-literal=clientSecret='" + string(secret) + "'"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create CAPx secret")
		}
	}

	c = "clusterctl init --wait-providers" +
		" --core " + CAPICoreProvider +
		" --bootstrap " + CAPIBootstrapProvider +
		" --control-plane " + CAPIControlPlaneProvider +
		" --infrastructure " + p.capxProvider + ":" + p.capxVersion
	_, err = commons.ExecuteCommand(n, c, 5, p.capxEnvVars)
	if err != nil {
		return errors.Wrap(err, "failed to install CAPX in local cluster")
	}

	if p.capxProvider == "azure" {
		c = "kubectl -n " + p.capxName + "-system patch ds capz-nmi -p '{\"spec\": {\"template\": {\"spec\": {\"priorityClassName\": \"system-node-critical\"}}}}' --type=merge"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to assigned priorityClass to nmi")
		}
		c = "kubectl -n " + p.capxName + "-system rollout status ds capz-nmi --timeout 30s"
		if err != nil {
			return errors.Wrap(err, "failed to check rollout status for nmi")
		}
	}

	return nil
}

func enableSelfHealing(n nodes.Node, keosCluster commons.KeosCluster, namespace string) error {
	var c string
	var err error

	if !keosCluster.Spec.ControlPlane.Managed {
		machineRole := "-control-plane-node"
		generateMHCManifest(n, keosCluster.Metadata.Name, namespace, machineHealthCheckControlPlaneNodePath, machineRole)

		c = "kubectl -n " + namespace + " apply -f " + machineHealthCheckControlPlaneNodePath
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to apply the MachineHealthCheck manifest")
		}
	}

	machineRole := "-worker-node"
	generateMHCManifest(n, keosCluster.Metadata.Name, namespace, machineHealthCheckWorkerNodePath, machineRole)

	c = "kubectl -n " + namespace + " apply -f " + machineHealthCheckWorkerNodePath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply the MachineHealthCheck manifest")
	}

	return nil
}

func generateMHCManifest(n nodes.Node, clusterID string, namespace string, manifestPath string, machineRole string) error {
	var c string
	var err error
	var machineHealthCheck = `
apiVersion: cluster.x-k8s.io/v1beta1
kind: MachineHealthCheck
metadata:
  name: ` + clusterID + machineRole + `-unhealthy
  namespace: cluster-` + clusterID + `
spec:
  clusterName: ` + clusterID + `
  nodeStartupTimeout: 300s
  selector:
    matchLabels:
      keos.stratio.com/machine-role: ` + clusterID + machineRole + `
  unhealthyConditions:
    - type: Ready
      status: Unknown
      timeout: 180s
    - type: Ready
      status: 'False'
      timeout: 180s`

	c = "echo \"" + machineHealthCheck + "\" > " + manifestPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to write the MachineHealthCheck manifest")
	}

	return nil
}

func resto(n int, i int, azs int) int {
	var r int
	r = (n % azs) / (i + 1)
	if r > 1 {
		r = 1
	}
	return r
}

func GetClusterManifest(params commons.TemplateParams) (string, error) {
	funcMap := template.FuncMap{
		"loop": func(az string, zd string, qa int, maxsize int, minsize int) <-chan Node {
			ch := make(chan Node)
			go func() {
				var q int
				var mx int
				var mn int
				if az != "" {
					ch <- Node{AZ: az, QA: qa, MaxSize: maxsize, MinSize: minsize}
				} else {
					for i, a := range params.ProviderAZs {
						if zd == "unbalanced" {
							q = qa/len(params.ProviderAZs) + resto(qa, i, len(params.ProviderAZs))
							mx = maxsize/len(params.ProviderAZs) + resto(maxsize, i, len(params.ProviderAZs))
							mn = minsize/len(params.ProviderAZs) + resto(minsize, i, len(params.ProviderAZs))
							ch <- Node{AZ: a, QA: q, MaxSize: mx, MinSize: mn}
						} else {
							ch <- Node{AZ: a, QA: qa / len(params.ProviderAZs), MaxSize: maxsize / len(params.ProviderAZs), MinSize: minsize / len(params.ProviderAZs)}
						}
					}
				}
				close(ch)
			}()
			return ch
		},
		"hostname": func(s string) string {
			return strings.Split(s, "/")[0]
		},
		"inc": func(i int) int {
			return i + 1
		},
		"base64": func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
		"sub":   func(a, b int) int { return a - b },
		"split": strings.Split,
	}
	templatePath := filepath.Join("templates", params.KeosCluster.Spec.InfraProvider, params.Flavor)

	var tpl bytes.Buffer
	t, err := template.New("").Funcs(funcMap).ParseFS(ctel, templatePath)
	if err != nil {
		return "", err
	}

	err = t.ExecuteTemplate(&tpl, params.Flavor, params)
	if err != nil {
		return "", err
	}

	return tpl.String(), nil
}

func getManifest(parentPath string, name string, params interface{}) (string, error) {
	templatePath := filepath.Join("templates", parentPath, name)

	var tpl bytes.Buffer
	t, err := template.New("").ParseFS(ctel, templatePath)
	if err != nil {
		return "", err
	}

	err = t.ExecuteTemplate(&tpl, name, params)
	if err != nil {
		return "", err
	}
	return tpl.String(), nil
}

func patchDeploy(n nodes.Node, k string, ns string, deployName string, patch string) error {
	c := "kubectl --kubeconfig " + k + " patch deploy -n " + ns + " " + deployName + " -p '" + patch + "'"
	_, err := commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return err
	}
	return rolloutStatus(n, k, ns, deployName)
}

func rolloutStatus(n nodes.Node, k string, ns string, deployName string) error {
	c := "kubectl --kubeconfig " + k + " rollout status deploy -n " + ns + " " + deployName + " --timeout=5m"
	_, err := commons.ExecuteCommand(n, c, 5)
	return err
}

func installCorednsPdb(n nodes.Node, k string) error {

	// Define PodDisruptionBudget for coredns service
	corednsPDBLocalPath := "files/common/coredns_pdb.yaml"
	corednsPDB, err := getcapxPDB(corednsPDBLocalPath)
	if err != nil {
		return err
	}

	c := "echo \"" + corednsPDB + "\" > " + corednsPdbPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create coredns PodDisruptionBudget file")
	}

	c = "kubectl --kubeconfig " + kubeconfigPath + " apply -f " + corednsPdbPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply coredns PodDisruptionBudget")
	}
	return nil
}
