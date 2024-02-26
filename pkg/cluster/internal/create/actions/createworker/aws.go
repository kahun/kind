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
	"context"
	_ "embed"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"gopkg.in/yaml.v3"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
	"sigs.k8s.io/kind/pkg/exec"
)

//go:embed files/aws/internal-ingress-nginx.yaml
var awsInternalIngress []byte
//go:embed files/aws/public-ingress-nginx.yaml
var awsPublicIngress []byte

type AWSBuilder struct {
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

func newAWSBuilder() *AWSBuilder {
	return &AWSBuilder{}
}

func (b *AWSBuilder) setCapx(managed bool) {
	b.capxProvider = "aws"
	b.capxVersion = "v2.2.1"
	b.capxImageVersion = "v2.2.1"
	b.capxName = "capa"
	b.capxManaged = managed
	b.csiNamespace = "kube-system"
}

func (b *AWSBuilder) setCapxEnvVars(p ProviderParams) {
	awsCredentials := "[default]\naws_access_key_id = " + p.Credentials["AccessKey"] + "\naws_secret_access_key = " + p.Credentials["SecretKey"] + "\nregion = " + p.Region + "\n"
	b.capxEnvVars = []string{
		"AWS_REGION=" + p.Region,
		"AWS_ACCESS_KEY_ID=" + p.Credentials["AccessKey"],
		"AWS_SECRET_ACCESS_KEY=" + p.Credentials["SecretKey"],
		"AWS_B64ENCODED_CREDENTIALS=" + base64.StdEncoding.EncodeToString([]byte(awsCredentials)),
		"CAPA_EKS_IAM=true",
	}
	if p.GithubToken != "" {
		b.capxEnvVars = append(b.capxEnvVars, "GITHUB_TOKEN="+p.GithubToken)
	}
}

func (b *AWSBuilder) setSC(p ProviderParams) {
	if (p.StorageClass.Parameters != commons.SCParameters{}) {
		b.scParameters = p.StorageClass.Parameters
	}

	b.scProvisioner = "ebs.csi.aws.com"

	if b.scParameters.Type == "" {
		if p.StorageClass.Class == "premium" {
			b.scParameters.Type = "io2"
			b.scParameters.IopsPerGB = "64000"
		} else {
			b.scParameters.Type = "gp3"
		}
	}

	if p.StorageClass.EncryptionKey != "" {
		b.scParameters.Encrypted = "true"
		b.scParameters.KmsKeyId = p.StorageClass.EncryptionKey
	}
}

func (b *AWSBuilder) getProvider() Provider {
	return Provider{
		capxProvider:     b.capxProvider,
		capxVersion:      b.capxVersion,
		capxImageVersion: b.capxImageVersion,
		capxManaged:      b.capxManaged,
		capxName:         b.capxName,
		capxEnvVars:      b.capxEnvVars,
		scParameters:     b.scParameters,
		scProvisioner:    b.scProvisioner,
		csiNamespace:     b.csiNamespace,
	}
}

func (b *AWSBuilder) installCloudProvider(n nodes.Node, k string, privateParams PrivateParams) error {
	var podsCidrBlock string
	keosCluster := privateParams.KeosCluster
	if keosCluster.Spec.Networks.PodsCidrBlock != "" {
		podsCidrBlock = keosCluster.Spec.Networks.PodsCidrBlock
	} else {
		podsCidrBlock = "192.168.0.0/16"
	}
	c := "helm install aws-cloud-controller-manager /stratio/helm/aws-cloud-controller-manager" +
		" --kubeconfig " + k +
		" --namespace kube-system" +
		" --set args[0]=\"--v=2\"" +
		" --set args[1]=\"--cloud-provider=aws\"" +
		" --set args[2]=\"--cluster-cidr=" + podsCidrBlock + "\"" +
		" --set args[3]=\"--cluster-name=" + keosCluster.Metadata.Name + "\""

	if privateParams.Private {
		c += " --set image.repository=" + privateParams.KeosRegUrl + "/provider-aws/cloud-controller-manager"
	}

	_, err := commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to deploy aws-cloud-controller-manager Helm Chart")
	}
	return nil
}

func (b *AWSBuilder) installCSI(n nodes.Node, k string, privateParams PrivateParams) error {
	c := "helm install aws-ebs-csi-driver /stratio/helm/aws-ebs-csi-driver" +
		" --kubeconfig " + k +
		" --namespace " + b.csiNamespace +
		" --set controller.podAnnotations.\"cluster-autoscaler\\.kubernetes\\.io/safe-to-evict-local-volumes=socket-dir\""

	if privateParams.Private {
		c += " --set image.repository=" + privateParams.KeosRegUrl + "/ebs-csi-driver/aws-ebs-csi-driver" +
			" --set sidecars.provisioner.image.repository=" + privateParams.KeosRegUrl + "/eks-distro/kubernetes-csi/external-provisioner" +
			" --set sidecars.attacher.image.repository=" + privateParams.KeosRegUrl + "/eks-distro/kubernetes-csi/external-attacher" +
			" --set sidecars.snapshotter.image.repository=" + privateParams.KeosRegUrl + "/eks-distro/kubernetes-csi/external-snapshotter/csi-snapshotter" +
			" --set sidecars.livenessProbe.image.repository=" + privateParams.KeosRegUrl + "/eks-distro/kubernetes-csi/livenessprobe" +
			" --set sidecars.resizer.image.repository=" + privateParams.KeosRegUrl + "/eks-distro/kubernetes-csi/external-resizer" +
			" --set sidecars.nodeDriverRegistrar.image.repository=" + privateParams.KeosRegUrl + "/eks-distro/kubernetes-csi/node-driver-registrar" +
			" --set sidecars.volumemodifier.image.repository=" + privateParams.KeosRegUrl + "/ebs-csi-driver/volume-modifier-for-k8s"

	}
	_, err := commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to deploy AWS EBS CSI driver Helm Chart")
	}
	return nil
}

func installLBController(n nodes.Node, k string, privateParams PrivateParams, p ProviderParams) error {
	clusterName := p.ClusterName
	roleName := p.ClusterName + "-lb-controller-manager"
	accountID := p.Credentials["AccountID"]

	c := "helm install aws-load-balancer-controller /stratio/helm/aws-load-balancer-controller" +
	" --kubeconfig " + k +
	" --namespace kube-system" +
	" --set clusterName=" + clusterName +
	" --set podDisruptionBudget.minAvailable=1" +
	" --set serviceAccount.annotations.\"eks\\.amazonaws\\.com/role-arn\"=arn:aws:iam::" + accountID + ":role/" + roleName
	if privateParams.Private {
		c += " --set image.repository=" + privateParams.KeosRegUrl + "/eks/aws-load-balancer-controller"
	}

	_, err := commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to deploy aws-load-balancer-controller Helm Chart")
	}

	return nil
}

func createCloudFormationStack(n nodes.Node, envVars []string) error {
	var c string
	var err error

	eksConfigData := `
apiVersion: bootstrap.aws.infrastructure.cluster.x-k8s.io/v1beta1
kind: AWSIAMConfiguration
spec:
  bootstrapUser:
    enable: false
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
	eksConfigPath := "/kind/eks.config"
	c = "echo \"" + eksConfigData + "\" > " + eksConfigPath
	_, err = commons.ExecuteCommand(n, c, 5)
	if err != nil {
		return errors.Wrap(err, "failed to create eks.config")
	}

	// Run clusterawsadm with the eks.config file previously created (this will create or update the CloudFormation stack in AWS)
	c = "clusterawsadm bootstrap iam create-cloudformation-stack --config " + eksConfigPath
	_, err = commons.ExecuteCommand(n, c, 5, envVars)
	if err != nil {
		return errors.Wrap(err, "failed to run clusterawsadm")
	}
	return nil
}

func (b *AWSBuilder) internalNginx(p ProviderParams, networks commons.Networks) (bool, error) {
	var err error
	var ctx = context.TODO()

	cfg, err := commons.AWSGetConfig(ctx, p.Credentials, p.Region)
	if err != nil {
		return false, err
	}
	svc := ec2.NewFromConfig(cfg)
	if len(networks.Subnets) > 0 {
		for _, s := range networks.Subnets {
			isPrivate, err := commons.AWSIsPrivateSubnet(ctx, svc, &s.SubnetId)
			if err != nil {
				return false, err
			}
			if !isPrivate {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

func (b *AWSBuilder) getRegistryCredentials(p ProviderParams, u string) (string, string, error) {
	var registryUser = "AWS"
	var registryPass string
	var ctx = context.Background()

	region := strings.Split(u, ".")[3]
	cfg, err := commons.AWSGetConfig(ctx, p.Credentials, region)
	if err != nil {
		return "", "", err
	}
	svc := ecr.NewFromConfig(cfg)
	token, err := svc.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", "", err
	}
	authData := token.AuthorizationData[0].AuthorizationToken
	data, err := base64.StdEncoding.DecodeString(*authData)
	if err != nil {
		return "", "", err
	}
	registryPass = strings.SplitN(string(data), ":", 2)[1]
	return registryUser, registryPass, nil
}

func (b *AWSBuilder) configureStorageClass(n nodes.Node, k string) error {
	var c string
	var err error
	var cmd exec.Cmd

	if b.capxManaged {
		// Remove annotation from default storage class
		c = "kubectl --kubeconfig " + k + ` get sc -o jsonpath='{.items[?(@.metadata.annotations.storageclass\.kubernetes\.io/is-default-class=="true")].metadata.name}'`
		output, err := commons.ExecuteCommand(n, c, 5)
		if err != nil {
			return errors.Wrap(err, "failed to get default storage class")
		}
		if strings.TrimSpace(output) != "" && strings.TrimSpace(output) != "No resources found" {
			c = "kubectl --kubeconfig " + k + " annotate sc " + strings.TrimSpace(output) + " " + defaultScAnnotation + "-"
			_, err = commons.ExecuteCommand(n, c, 5)
			if err != nil {
				return errors.Wrap(err, "failed to remove annotation from default storage class")
			}
		}
	}

	scTemplate.Parameters = b.scParameters
	scTemplate.Provisioner = b.scProvisioner

	scBytes, err := yaml.Marshal(scTemplate)
	if err != nil {
		return err
	}
	storageClass := strings.Replace(string(scBytes), "fsType", "csi.storage.k8s.io/fstype", -1)

	if b.scParameters.Labels != "" {
		var tags string
		re := regexp.MustCompile(`\s*labels: (.*,?)`)
		labels := re.FindStringSubmatch(storageClass)[1]
		for i, label := range strings.Split(labels, ",") {
			tags += "\n    tagSpecification_" + strconv.Itoa(i+1) + ": \"" + strings.TrimSpace(label) + "\""
		}
		storageClass = re.ReplaceAllString(storageClass, tags)
	}

	cmd = n.Command("kubectl", "--kubeconfig", k, "apply", "-f", "-")
	if err = cmd.SetStdin(strings.NewReader(storageClass)).Run(); err != nil {
		return errors.Wrap(err, "failed to create default storage class")
	}

	return nil
}

func (b *AWSBuilder) getOverrideVars(p ProviderParams, networks commons.Networks) (map[string][]byte, error) {
	var overrideVars = make(map[string][]byte)

	// Add override vars internal nginx
	requiredInternalNginx, err := b.internalNginx(p, networks)
	if err != nil {
		return nil, err
	}
	if requiredInternalNginx {
		overrideVars = addOverrideVar("ingress-nginx.yaml", awsInternalIngress, overrideVars)
	} else if !requiredInternalNginx && p.Managed {
		overrideVars = addOverrideVar("ingress-nginx.yaml", awsPublicIngress, overrideVars)
	}
	// Add override vars for storage class
	if commons.Contains([]string{"io1", "io2"}, b.scParameters.Type) {
		overrideVars = addOverrideVar("storage-class.yaml", []byte("storage_class_pvc_size: 4Gi"), overrideVars)
	}
	if commons.Contains([]string{"st1", "sc1"}, b.scParameters.Type) {
		overrideVars = addOverrideVar("storage-class.yaml", []byte("storage_class_pvc_size: 125Gi"), overrideVars)
	}
	return overrideVars, nil
}

func (b *AWSBuilder) postInstallPhase(n nodes.Node, k string) error {
	var coreDNSPDBName = "coredns"

	c := "kubectl --kubeconfig " + kubeconfigPath + " get pdb " + coreDNSPDBName + " -n kube-system"
	_, err := commons.ExecuteCommand(n, c, 5)
	if err != nil {
		err = installCorednsPdb(n, k)
		if err != nil {
			return errors.Wrap(err, "failed to add core dns PDB")
		}
	}
	if b.capxManaged {
		err := patchDeploy(n, k, "kube-system", "coredns", "{\"spec\": {\"template\": {\"metadata\": {\"annotations\": {\""+postInstallAnnotation+"\": \"tmp\"}}}}}")
		if err != nil {
			return errors.Wrap(err, "failed to add podAnnotation to coredns")
		}

		err = patchDeploy(n, k, "kube-system", "ebs-csi-controller", "{\"spec\": {\"template\": {\"metadata\": {\"annotations\": {\""+postInstallAnnotation+"\": \"socket-dir\"}}}}}")
		if err != nil {
			return errors.Wrap(err, "failed to add podAnnotation to ebs-csi-controller")
		}
	}

	return nil
}
