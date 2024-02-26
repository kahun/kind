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
	"io"
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

var stratio_helm_repo string

//go:embed files/*/*_pdb.yaml
var commonsPDBFile embed.FS

const (
	CAPICoreProvider         = "cluster-api"
	CAPIBootstrapProvider    = "kubeadm"
	CAPIControlPlaneProvider = "kubeadm"
	CAPIVersion              = "v1.5.3"

	scName = "keos"

	certManagerVersion = "v1.12.3"

	postInstallAnnotation = "cluster-autoscaler.kubernetes.io/safe-to-evict-local-volumes"
	corednsPdbPath        = "/kind/coredns_pdb.yaml"

	machineHealthCheckWorkerNodePath       = "/kind/manifests/machinehealthcheckworkernode.yaml"
	machineHealthCheckControlPlaneNodePath = "/kind/manifests/machinehealthcheckcontrolplane.yaml"
	defaultScAnnotation                    = "storageclass.kubernetes.io/is-default-class"
)

//go:embed files/common/calico-metrics.yaml
var calicoMetrics string

type PrivateParams struct {
	KeosCluster commons.KeosCluster
	KeosRegUrl  string
	Private     bool
}

type PBuilder interface {
	setCapx(managed bool)
	setCapxEnvVars(p ProviderParams)
	setSC(p ProviderParams)
	installCloudProvider(n nodes.Node, k string, privateParams PrivateParams) error
	installCSI(n nodes.Node, k string, privateParams PrivateParams) error
	getProvider() Provider
	configureStorageClass(n nodes.Node, k string) error
	internalNginx(p ProviderParams, networks commons.Networks) (bool, error)
	getOverrideVars(p ProviderParams, networks commons.Networks) (map[string][]byte, error)
	getRegistryCredentials(p ProviderParams, u string) (string, string, error)
	postInstallPhase(n nodes.Node, k string) error
}

type Provider struct {
	capxProvider     string
	capxVersion      string
	capxImageVersion string
	capxManaged      bool
	capxName         string
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
	Spec        commons.KeosSpec
	KeosRegUrl  string
	Private     bool
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

func (i *Infra) installCloudProvider(n nodes.Node, k string, privateParams PrivateParams) error {
	return i.builder.installCloudProvider(n, k, privateParams)
}

func (i *Infra) installCSI(n nodes.Node, k string, privateParams PrivateParams) error {
	return i.builder.installCSI(n, k, privateParams)
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

func (i *Infra) getRegistryCredentials(p ProviderParams, u string) (string, string, error) {
	return i.builder.getRegistryCredentials(p, u)
}

func (i *Infra) postInstallPhase(n nodes.Node, k string) error {
	return i.builder.postInstallPhase(n, k)
}

func (p *Provider) getDenyAllEgressIMDSGNetPol() (string, error) {
	denyAllEgressIMDSGNetPolLocalPath := "files/" + p.capxProvider + "/deny-all-egress-imds_gnetpol.yaml"
	denyAllEgressIMDSgnpFile, err := denyAllEgressIMDSgnpFiles.Open(denyAllEgressIMDSGNetPolLocalPath)
	if err != nil {
		return "", errors.Wrap(err, "error opening the deny all egress IMDS file")
	}
	defer denyAllEgressIMDSgnpFile.Close()
	denyAllEgressIMDSgnpContent, err := io.ReadAll(denyAllEgressIMDSgnpFile)
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
	allowEgressIMDSgnpContent, err := io.ReadAll(allowEgressIMDSgnpFile)
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
	capaPDBContent, err := io.ReadAll(commonsPDBFile)
	if err != nil {
		return "", err
	}

	return string(capaPDBContent), nil
}

func (p *Provider) deployCertManager(n nodes.Node, keosRegistryUrl string, kubeconfigPath string) error {
	c := "kubectl create -f " + CAPILocalRepository + "/cert-manager/" + certManagerVersion + "/cert-manager.crds.yaml"
	if kubeconfigPath != "" {
		c += " --kubeconfig " + kubeconfigPath
	}
	_, err := commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create cert-manager crds")
	}

	c = "kubectl create ns cert-manager"
	if kubeconfigPath != "" {
		c += " --kubeconfig " + kubeconfigPath
	}
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create cert-manager namespace")
	}

	c = "helm install --wait cert-manager /stratio/helm/cert-manager" +
		" --set namespace=cert-manager" +
		" --set cainjector.image.repository=" + keosRegistryUrl + "/jetstack/cert-manager-cainjector" +
		" --set webhook.image.repository=" + keosRegistryUrl + "/jetstack/cert-manager-webhook" +
		" --set acmesolver.image.repository=" + keosRegistryUrl + "/jetstack/cert-manager-acmesolver" +
		" --set startupapicheck.image.repository=" + keosRegistryUrl + "/jetstack/cert-manager-ctl" +
		" --set image.repository=" + keosRegistryUrl + "/jetstack/cert-manager-controller"

	if kubeconfigPath != "" {
		c += " --kubeconfig " + kubeconfigPath
	}

	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to deploy cert-manager Helm Chart")
	}
	return nil
}

func (p *Provider) deployClusterOperator(n nodes.Node, privateParams PrivateParams, clusterCredentials commons.ClusterCredentials, keosRegistry KeosRegistry, clusterConfig *commons.ClusterConfig, kubeconfigPath string, firstInstallation bool, helmRepoCreds HelmRegistry) error {
	var c string
	var err error
	var helmRepository helmRepository
	var chartVersion string
	clusterOperatorImage := ""
	keosCluster := privateParams.KeosCluster

	if clusterConfig != nil {
		if clusterConfig.Spec.ClusterOperatorVersion != "" {
			chartVersion = clusterConfig.Spec.ClusterOperatorVersion
		} else {
			chartVersion, err = getLastChartVersion(helmRepoCreds)
			if err != nil {
				return errors.Wrap(err, "failed to get the last chart version")
			}
			if clusterConfig == nil {
				clusterConfig = &commons.ClusterConfig{}
			}
			clusterConfig.Spec.ClusterOperatorVersion = chartVersion
		}
		if clusterConfig.Spec.ClusterOperatorImageVersion != "" {
			clusterOperatorImage = clusterConfig.Spec.ClusterOperatorImageVersion
		}
	}

	if firstInstallation && keosCluster.Spec.InfraProvider == "aws" && strings.HasPrefix(keosCluster.Spec.HelmRepository.URL, "s3://") {
		c = "mkdir -p ~/.aws"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create aws config file")
		}
		c = "echo [default] > ~/.aws/config && " +
			"echo region = " + keosCluster.Spec.Region + " >>  ~/.aws/config"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create aws config file")
		}
		awsCredentials := "[default]\naws_access_key_id = " + clusterCredentials.ProviderCredentials["AccessKey"] + "\naws_secret_access_key = " + clusterCredentials.ProviderCredentials["SecretKey"] + "\n"
		c = "echo '" + awsCredentials + "' > ~/.aws/credentials"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create aws credentials file")
		}
	}

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
		keosCluster.Spec.Keos = commons.Keos{}

		clusterConfigYAML, err := yaml.Marshal(clusterConfig)
		if err != nil {
			return err
		}
		// Write keoscluster file
		c = "echo '" + string(clusterConfigYAML) + "' > " + manifestsPath + "/clusterconfig.yaml"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to write the keoscluster file")
		}
		keosCluster.Spec.ClusterConfigRef.Name = clusterConfig.Metadata.Name

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
		if strings.HasPrefix(keosCluster.Spec.HelmRepository.URL, "oci://") {
			stratio_helm_repo = helmRepoCreds.URL
			urlLogin := strings.Split(strings.Split(keosCluster.Spec.HelmRepository.URL, "//")[1], "/")[0]

			c = "helm registry login " + urlLogin + " --username " + helmRepoCreds.User + " --password " + helmRepoCreds.Pass
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to add and authenticate to helm repository: "+helmRepoCreds.URL)
			}
		} else if keosCluster.Spec.HelmRepository.AuthRequired {
			helmRepository.user = clusterCredentials.HelmRepositoryCredentials["User"]
			helmRepository.pass = clusterCredentials.HelmRepositoryCredentials["Pass"]
			stratio_helm_repo = "stratio-helm-repo"
			c = "helm repo add " + stratio_helm_repo + " " + helmRepoCreds.URL + " --username " + helmRepoCreds.User + " --password " + helmRepoCreds.Pass
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to add and authenticate to helm repository: "+helmRepository.url)
			}
		} else {
			stratio_helm_repo = "stratio-helm-repo"
			c = "helm repo add " + stratio_helm_repo + " " + helmRepoCreds.URL
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to add helm repository: "+helmRepoCreds.URL)
			}
		}

		if firstInstallation {
			// Pull cluster-operator helm chart
			c = "helm pull " + stratio_helm_repo + "/cluster-operator --version " + chartVersion +
				" --untar --untardir /stratio/helm"
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to pull cluster-operator helm chart")
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

	// Deploy cluster-operator chart
	c = "helm install --wait cluster-operator /stratio/helm/cluster-operator" +
		" --namespace kube-system" +
		" --set provider=" + keosCluster.Spec.InfraProvider +
		" --set app.containers.controllerManager.image.registry=" + keosRegistry.url +
		" --set app.containers.controllerManager.image.repository=stratio/cluster-operator"
	if clusterOperatorImage != "" {
		c += " --set app.containers.controllerManager.image.tag=" + clusterOperatorImage
	}
	if privateParams.Private {
		c += " --set app.containers.kubeRbacProxy.image=" + keosRegistry.url + "/stratio/kube-rbac-proxy:v0.13.1"
	}
	if keosCluster.Spec.InfraProvider == "azure" {
		c += " --set secrets.azure.clientIDBase64=" + strings.Split(p.capxEnvVars[1], "AZURE_CLIENT_ID_B64=")[1] +
			" --set secrets.azure.clientSecretBase64=" + strings.Split(p.capxEnvVars[0], "AZURE_CLIENT_SECRET_B64=")[1] +
			" --set secrets.azure.subscriptionIDBase64=" + strings.Split(p.capxEnvVars[2], "AZURE_SUBSCRIPTION_ID_B64=")[1] +
			" --set secrets.azure.tenantIDBase64=" + strings.Split(p.capxEnvVars[3], "AZURE_TENANT_ID_B64=")[1]
	} else if keosCluster.Spec.InfraProvider == "gcp" {
		c += " --set secrets.common.credentialsBase64=" + strings.Split(p.capxEnvVars[0], "GCP_B64ENCODED_CREDENTIALS=")[1]
	} else if keosCluster.Spec.InfraProvider == "aws" {
		c += " --set secrets.common.credentialsBase64=" + strings.Split(p.capxEnvVars[3], "AWS_B64ENCODED_CREDENTIALS=")[1]
	}
	if kubeconfigPath == "" {
		c += " --set app.containers.controllerManager.imagePullSecrets.enabled=true" +
			" --set app.containers.controllerManager.imagePullSecrets.name=regcred"
	} else {
		c += " --set app.replicas=2" + " --kubeconfig " + kubeconfigPath
	}

	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to deploy cluster-operator chart")
	}

	// Wait for cluster-operator deployment
	c = "kubectl -n kube-system rollout status deploy/keoscluster-controller-manager --timeout=3m"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to wait for cluster-operator deployment")
	}

	// TODO: Change this when status is available in cluster-operator
	time.Sleep(10 * time.Second)

	return nil
}

func installCalico(n nodes.Node, k string, privateParams PrivateParams, allowCommonEgressNetPolPath string) error {
	var c string
	var cmd exec.Cmd
	var err error
	keosCluster := privateParams.KeosCluster

	calicoTemplate := "/kind/calico-helm-values.yaml"

	calicoHelmParams := calicoHelmParams{
		Spec:       keosCluster.Spec,
		KeosRegUrl: privateParams.KeosRegUrl,
		Private:    privateParams.Private,
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
func (p *Provider) installCAPXWorker(n nodes.Node, keosCluster commons.KeosCluster, kubeconfigPath string, allowAllEgressNetPolPath string) error {
	var c string
	var err error

	capxPDBPath := "/kind/capi_pdb.yaml"

	if p.capxProvider == "azure" {
		// Create capx namespace
		c = "kubectl --kubeconfig " + kubeconfigPath + " create namespace " + p.capxName + "-system"
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create CAPx namespace")
		}

		// Create capx secret
		namespace := p.capxName + "-system"
		clientSecret, _ := base64.StdEncoding.DecodeString(strings.Split(p.capxEnvVars[0], "AZURE_CLIENT_SECRET_B64=")[1])

		c := fmt.Sprintf(
			"kubectl --kubeconfig %s -n %s create secret generic cluster-identity-secret "+
				"--from-literal=clientSecret='%s'",
			kubeconfigPath, namespace, clientSecret)
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create CAPx secret")
		}
	}

	// Install CAPX in worker cluster
	c = "clusterctl --kubeconfig " + kubeconfigPath + " init --wait-providers" +
		" --core " + CAPICoreProvider + ":" + CAPIVersion +
		" --bootstrap " + CAPIBootstrapProvider + ":" + CAPIVersion +
		" --control-plane " + CAPIControlPlaneProvider + ":" + CAPIVersion +
		" --infrastructure " + p.capxProvider + ":" + p.capxVersion
	_, err = commons.ExecuteCommand(n, c, 5, p.capxEnvVars)
	if err != nil {
		return errors.Wrap(err, "failed to install CAPX in workload cluster")
	}

	// Manually assign PriorityClass to capx service
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system patch deploy " + p.capxName + "-controller-manager -p '{\"spec\": {\"template\": {\"spec\": {\"priorityClassName\": \"system-node-critical\"}}}}' --type=merge"
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to assigned priorityClass to "+p.capxName+"-controller-manager")
	}
	c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system rollout status deploy " + p.capxName + "-controller-manager --timeout 60s"
	_, err = commons.ExecuteCommand(n, c, 5)
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
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to check rollout status for "+p.capxName+"-controller-manager")
	}

	// Define PodDisruptionBudget for capx services
	capxPDB, err := getManifest("common", "capx_pdb.tmpl", keosCluster.Spec)
	if err != nil {
		return errors.Wrap(err, "failed to get PodDisruptionBudget file")
	}

	c = "echo '" + capxPDB + "' > " + capxPDBPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create PodDisruptionBudget file")
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
		c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + p.capxName + "-system rollout status ds capz-nmi --timeout 90s"
		_, err = commons.ExecuteCommand(n, c, 5)
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
	_, err = commons.ExecuteCommand(n, c, 5)
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
			c = "kubectl --kubeconfig " + kubeconfigPath + " -n " + deployment.namespace + " rollout status deploy " + deployment.name + " --timeout 60s"
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to check rollout status for "+deployment.name)
			}
		}
	}

	// Define PodDisruptionBudget for capi services
	capiPDB, err := getManifest("common", "capi_pdb.tmpl", keosCluster.Spec)
	if err != nil {
		return errors.Wrap(err, "failed to get PodDisruptionBudget file")
	}
	c = "echo '" + capiPDB + "' > " + capiPDBPath
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
		namespace := p.capxName + "-system"
		clientSecret, _ := base64.StdEncoding.DecodeString(strings.Split(p.capxEnvVars[0], "AZURE_CLIENT_SECRET_B64=")[1])

		c := fmt.Sprintf(
			"kubectl -n %s create secret generic cluster-identity-secret "+
				"--from-literal=clientSecret='%s' ",
			namespace, clientSecret)
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to create CAPx secret")
		}
	}

	c = "clusterctl init --wait-providers" +
		" --core " + CAPICoreProvider + ":" + CAPIVersion +
		" --bootstrap " + CAPIBootstrapProvider + ":" + CAPIVersion +
		" --control-plane " + CAPIControlPlaneProvider + ":" + CAPIVersion +
		" --infrastructure " + p.capxProvider + ":" + p.capxVersion
	_, err = commons.ExecuteCommand(n, c, 5, p.capxEnvVars)
	if err != nil {
		return errors.Wrap(err, "failed to install CAPX in local cluster")
	}

	return nil
}

func enableSelfHealing(n nodes.Node, keosCluster commons.KeosCluster, namespace string, clusterConfig *commons.ClusterConfig) error {
	var c string
	var err error

	if !keosCluster.Spec.ControlPlane.Managed {
		machineRole := "-control-plane-node"
		controlplane_maxunhealty := 34
		if clusterConfig != nil {
			if clusterConfig.Spec.ControlplaneConfig.MaxUnhealthy != nil {
				controlplane_maxunhealty = *clusterConfig.Spec.ControlplaneConfig.MaxUnhealthy
			}
		}

		generateMHCManifest(n, keosCluster.Metadata.Name, namespace, machineHealthCheckControlPlaneNodePath, machineRole, controlplane_maxunhealty)

		c = "kubectl -n " + namespace + " apply -f " + machineHealthCheckControlPlaneNodePath
		_, err = commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to apply the MachineHealthCheck manifest")
		}
	}

	machineRole := "-worker-node"
	workernode_maxunhealty := 34
	if clusterConfig != nil {
		if clusterConfig.Spec.WorkersConfig.MaxUnhealthy != nil {
			workernode_maxunhealty = *clusterConfig.Spec.WorkersConfig.MaxUnhealthy
		}
	}
	generateMHCManifest(n, keosCluster.Metadata.Name, namespace, machineHealthCheckWorkerNodePath, machineRole, workernode_maxunhealty)

	c = "kubectl -n " + namespace + " apply -f " + machineHealthCheckWorkerNodePath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to apply the MachineHealthCheck manifest")
	}

	return nil
}

func generateMHCManifest(n nodes.Node, clusterID string, namespace string, manifestPath string, machineRole string, maxunhealthy int) error {
	var c string
	var err error
	var maxUnhealthy = strconv.Itoa(maxunhealthy) + "%"

	var machineHealthCheck = `
apiVersion: cluster.x-k8s.io/v1beta1
kind: MachineHealthCheck
metadata:
  name: ` + clusterID + machineRole + `-unhealthy
  namespace: cluster-` + clusterID + `
spec:
  clusterName: ` + clusterID + `
  nodeStartupTimeout: 300s
  maxUnhealthy: ` + maxUnhealthy + `
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
