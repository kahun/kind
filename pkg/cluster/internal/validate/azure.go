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
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v3"
	"golang.org/x/exp/slices"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
)

// TODO: validate provider storage class fields

const (
	AKSMaxNodeNameLength = 9
)

var AzureVolumes = []string{"Standard_LRS", "Premium_LRS", "StandardSSD_LRS", "UltraSSD_LRS", "Premium_ZRS", "StandardSSD_ZRS", "PremiumV2_LRS"}
var AzureFSTypes = []string{"xfs", "ext3", "ext4", "ext2", "btrfs"}
var AzureSCFields = []string{"fsType", "kind", "cachingMode", "diskAccessID", "diskEncryptionType", "enableBursting", "enablePerformancePlus", "networkAccessPolicy", "provisioner", "publicNetworkAccess", "resourceGroup", "skuName", "subscriptionID", "tags"}

var isPremium = regexp.MustCompile(`^(Premium|Ultra).*$`).MatchString

func validateAzure(spec commons.Spec, providerSecrets map[string]string) error {
	var err error

	creds, err := validateAzureCredentials(providerSecrets)
	if err != nil {
		return err
	}

	if spec.Security.NodesIdentity != "" {
		if err = validateAzureIdentity(spec.Security.NodesIdentity); err != nil {
			return err
		}
	}

	if (spec.StorageClass != commons.StorageClass{}) {
		if err = validateAzureStorageClass(spec.StorageClass, spec.WorkerNodes); err != nil {
			return errors.Wrap(err, "invalid storage class")
		}
	}

	if spec.ControlPlane.Managed {
		if err = validateAKSVersion(spec, creds, providerSecrets["SubscriptionID"]); err != nil {
			return err
		}
		if err = validateAKSNodesName(spec.WorkerNodes); err != nil {
			return err
		}
	}

	if !spec.ControlPlane.Managed {
		if err = validateAzureVolumes(spec); err != nil {
			return err
		}
	}

	return nil
}

func validateAzureCredentials(secrets map[string]string) (*azidentity.ClientSecretCredential, error) {
	creds, err := azidentity.NewClientSecretCredential(secrets["TenantID"], secrets["ClientID"], secrets["ClientSecret"], nil)
	if err != nil {
		return &azidentity.ClientSecretCredential{}, err
	}
	return creds, nil
}

func validateAzureIdentity(identity string) error {
	var isIdentity = regexp.MustCompile(`^\/subscriptions\/[\w-]+\/resourcegroups\/[\w\.-]+\/providers\/Microsoft\.ManagedIdentity\/userAssignedIdentities\/[\w\.-]+$`).MatchString
	if !isIdentity(identity) {
		return errors.New("incorrect identity format. It must have the format /subscriptions/[SUBSCRIPTION_ID]/resourceGroups/[RESOURCE_GROUP]/providers/Microsoft.ManagedIdentity/userAssignedIdentities/[IDENTITY_NAME]")
	}
	return nil
}

func validateAzureStorageClass(sc commons.StorageClass, wn commons.WorkerNodes) error {
	var err error
	var isKeyValid = regexp.MustCompile(`^\/subscriptions\/[\w-]+\/resourceGroups\/[\w\.-]+\/providers\/Microsoft\.Compute\/diskEncryptionSets\/[\w\.-]+$`).MatchString

	// Validate encryptionKey format
	if sc.EncryptionKey != "" {
		if !isKeyValid(sc.EncryptionKey) {
			return errors.New("incorrect encryptionKey format. It must have the format /subscriptions/[SUBSCRIPTION_ID]/resourceGroups/[RESOURCE_GROUP]/providers/Microsoft.ManagedIdentity/diskEncryptionSets/[DISK_ENCRYPION_SETS_NAME]")
		}
	}
	// Validate diskEncryptionSetID format
	if sc.Parameters.DiskEncryptionSetID != "" {
		if !isKeyValid(sc.Parameters.DiskEncryptionSetID) {
			return errors.New("incorrect diskEncryptionSetID format. It must have the format /subscriptions/[SUBSCRIPTION_ID]/resourceGroups/[RESOURCE_GROUP]/providers/Microsoft.ManagedIdentity/diskEncryptionSets/[DISK_ENCRYPION_SETS_NAME]")
		}
	}
	// Validate type
	if sc.Parameters.SkuName != "" && !commons.Contains(AzureVolumes, sc.Parameters.SkuName) {
		return errors.New("unsupported skuname: " + sc.Parameters.SkuName)
	}
	// Validate fsType
	if sc.Parameters.FsType != "" && !commons.Contains(AzureFSTypes, sc.Parameters.FsType) {
		return errors.New("unsupported fsType: " + sc.Parameters.FsType + ". Supported types: " + fmt.Sprint(strings.Join(AzureFSTypes, ", ")))
	}
	// Validate size support premium storage
	if sc.Class == "premium" || isPremium(sc.Parameters.SkuName) {
		hasPremium := false
		for _, n := range wn {
			if isAzurePremiumSize(n.Size) {
				hasPremium = true
				break
			}
		}
		if !hasPremium {
			return errors.New("premium storage is not supported in any workers nodes")
		}
	}
	// Validate cachingMode
	if sc.Parameters.CachingMode == "ReadOnly" && sc.Parameters.SkuName == "PremiumV2_LRS" {
		return errors.New("with skuName PremiumV2_LRS, CachingMode only can be none")
	}
	// Validate tags
	if sc.Parameters.Tags != "" {
		if err = validateLabel(sc.Parameters.Tags); err != nil {
			return errors.Wrap(err, "invalid tags")
		}
	}
	return nil
}

func validateAKSVersion(spec commons.Spec, creds *azidentity.ClientSecretCredential, subscription string) error {
	var availableVersions []string
	ctx := context.Background()
	clientFactory, err := armcontainerservice.NewClientFactory(subscription, creds, nil)
	if err != nil {
		return err
	}
	res, err := clientFactory.NewManagedClustersClient().ListKubernetesVersions(ctx, spec.Region, nil)
	if err != nil {
		return err
	}
	for _, v := range res.KubernetesVersionListResult.Values {
		for _, p := range v.PatchVersions {
			for _, u := range p.Upgrades {
				availableVersions = append(availableVersions, *u)
			}
		}
	}
	if !slices.Contains(availableVersions, strings.ReplaceAll(spec.K8SVersion, "v", "")) {
		a, _ := json.Marshal(availableVersions)
		return errors.New("AKS only supports Kubernetes versions: " + string(a))
	}
	return nil
}

func validateAKSNodesName(workerNodes commons.WorkerNodes) error {
	var isLetter = regexp.MustCompile(`^[a-z0-9]+$`).MatchString
	for _, node := range workerNodes {
		if !isLetter(node.Name) || len(node.Name) >= AKSMaxNodeNameLength {
			return errors.New("AKS node names must be " + strconv.Itoa(AKSMaxNodeNameLength) + " characters or less & contain only lowercase alphanumeric characters")
		}
	}
	return nil
}

func validateAzureVolumes(spec commons.Spec) error {
	var err error
	if (spec.ControlPlane.RootVolume != commons.RootVolume{}) {
		// Validate control plane root volume
		if err = validateVolumeType(spec.ControlPlane.RootVolume.Type, AzureVolumes); err != nil {
			return errors.Wrap(err, "invalid control plane root volume")
		}
		// Validate control plane premium storage
		if isPremium(spec.ControlPlane.RootVolume.Type) && !isAzurePremiumSize(spec.ControlPlane.Size) {
			return errors.New("control plane size doesn't support premium storage")
		}
	}
	// Validate control plane extra volumes
	if err = validateAzureExtraVolumes(spec.ControlPlane.ExtraVolumes, spec.ControlPlane.Size); err != nil {
		return errors.Wrap(err, "invalid control plane extra volumes")
	}
	for _, wn := range spec.WorkerNodes {
		if (wn.RootVolume != commons.RootVolume{}) {
			// Validate worker node root volume
			if err = validateVolumeType(wn.RootVolume.Type, AzureVolumes); err != nil {
				return errors.Wrap(err, "invalid worker node "+wn.Name+" root volume")
			}
			// Validate worker node premium storage
			if isPremium(wn.RootVolume.Type) && !isAzurePremiumSize(wn.Size) {
				return errors.New("worker node " + wn.Name + " size doesn't support premium storage")
			}
		}
		// Validate worker node extra volumes
		if err = validateAzureExtraVolumes(wn.ExtraVolumes, wn.Size); err != nil {
			return errors.Wrap(err, "invalid worker node "+wn.Name+" extra volumes")
		}
	}
	return nil
}

func validateAzureExtraVolumes(extraVolumes []commons.ExtraVolume, s string) error {
	var err error
	for i, v := range extraVolumes {
		// Validate extra volume name
		if v.Name == "" {
			return errors.New("name cannot be empty")
		}
		// Validate extra volume unique name
		for _, v2 := range extraVolumes[i+1:] {
			if v.Name == v2.Name {
				return errors.New("name is duplicated")
			}
		}
		// Validate extra volume type
		if err = validateVolumeType(v.Type, AzureVolumes); err != nil {
			return err
		}
		// Validate extra volume premium storage
		if isPremium(v.Type) && !strings.Contains(strings.ToLower(strings.ReplaceAll(s, "Standard_", "")), "s") {
			return errors.New("size doesn't support premium storage")
		}
	}
	return nil
}

func isAzurePremiumSize(s string) bool {
	return strings.Contains(strings.ToLower(strings.ReplaceAll(s, "Standard_", "")), "s")
}
