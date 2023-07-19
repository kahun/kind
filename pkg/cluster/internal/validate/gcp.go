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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
)

// TODO: validate provider storage class fields

var GCPVolumes = []string{"pd-balanced", "pd-ssd", "pd-standard", "pd-extreme"}
var GCPFSTypes = []string{"xfs", "ext3", "ext4", "ext2"}
var GCPSCFields = []string{"type", "fsType", "labels", "provisioned-iops-on-create", "provisioned-throughput-on-create", "replication-type"}

func validateGCP(spec commons.Spec) error {
	var err error

	if (spec.StorageClass != commons.StorageClass{}) {
		if err = validateGCPStorageClass(spec); err != nil {
			return errors.Wrap(err, "invalid storage class")
		}
	}

	if !spec.ControlPlane.Managed {
		if err = validateGCPNodeImage(spec); err != nil {
			return errors.Wrap(err, "invalid node image")
		}
		if err = validateGCPVolumes(spec); err != nil {
			return err
		}
	}

	return nil
}

func validateGCPStorageClass(spec commons.Spec) error {
	var err error
	var isKeyValid = regexp.MustCompile(`^projects/[a-zA-Z0-9-]+/locations/[a-zA-Z0-9-]+/keyRings/[a-zA-Z0-9-]+/cryptoKeys/[a-zA-Z0-9-]+$`).MatchString
	var sc = spec.StorageClass

	// Validate encryptionKey format
	if sc.EncryptionKey != "" {
		if !isKeyValid(sc.EncryptionKey) {
			return errors.New("incorrect encryptionKey format. It must have the format projects/[PROJECT_ID]/locations/[REGION]/keyRings/[RING_NAME]/cryptoKeys/[KEY_NAME]")
		}
	}
	// Validate disk-encryption-kms-key format
	if sc.Parameters.DiskEncryptionKmsKey != "" {
		if !isKeyValid(sc.Parameters.DiskEncryptionKmsKey) {
			return errors.New("incorrect disk-encryption-kms-key format. It must have the format projects/[PROJECT_ID]/locations/[REGION]/keyRings/[RING_NAME]/cryptoKeys/[KEY_NAME]")
		}
	}
	// Validate type
	if sc.Parameters.Type != "" && !commons.Contains(GCPVolumes, sc.Parameters.Type) {
		return errors.New("unsupported type: " + sc.Parameters.Type)
	}
	// Validate fsType
	if sc.Parameters.FsType != "" && !commons.Contains(GCPFSTypes, sc.Parameters.FsType) {
		return errors.New("unsupported fsType: " + sc.Parameters.FsType + ". Supported types: " + fmt.Sprint(strings.Join(GCPFSTypes, ", ")))
	}

	if spec.ControlPlane.Managed {
		version, _ := strconv.ParseFloat(regexp.MustCompile(".[0-9]+$").Split(strings.ReplaceAll(spec.K8SVersion, "v", ""), -1)[0], 64)
		if sc.Parameters.Type == "pd-extreme" && version < 1.26 {
			return errors.New("pd-extreme is only supported in GKE 1.26 or later")
		}
	}
	// Validate provisioned-iops-on-create
	if sc.Parameters.ProvisionedIopsOnCreate != "" {
		if sc.Parameters.Type != "pd-extreme" {
			return errors.New("provisioned-iops-on-create is only supported for pd-extreme")
		}
		if _, err = strconv.Atoi(sc.Parameters.ProvisionedIopsOnCreate); err != nil {
			return errors.New("provisioned-iops-on-create must be an integer")
		}
	}
	// Validate replication-type
	if sc.Parameters.ReplicationType != "" && !regexp.MustCompile(`^(none|regional-pd)$`).MatchString(sc.Parameters.ReplicationType) {
		return errors.New("incorrect replication-type. Supported values are 'none' or 'regional-pd'")
	}
	// Validate labels
	if sc.Parameters.Labels != "" {
		if err = validateLabel(sc.Parameters.Labels); err != nil {
			return errors.Wrap(err, "invalid labels")
		}
	}
	return nil
}

func validateGCPNodeImage(spec commons.Spec) error {
	var isImageValid = regexp.MustCompile(`^projects/[\w-]+/global/images/[\w-]+$`).MatchString
	var format = "projects/[PROJECT_ID]/global/images/[IMAGE_NAME]"
	// Validate control plane node_image
	if spec.ControlPlane.NodeImage == "" || !isImageValid(spec.ControlPlane.NodeImage) {
		return errors.New("incorrect control plane node_image. It must exist & have the format " + format)
	}
	// Validate workers nodes node_image
	for _, wn := range spec.WorkerNodes {
		if wn.NodeImage == "" || !isImageValid(wn.NodeImage) {
			return errors.New("incorrect worker node " + wn.Name + " node_image. It must exist & have the format " + format)
		}
	}
	return nil
}

func validateGCPVolumes(spec commons.Spec) error {
	var err error
	if (spec.ControlPlane.RootVolume != commons.RootVolume{}) {
		// Validate control plane root volume type
		if err = validateVolumeType(spec.ControlPlane.RootVolume.Type, GCPVolumes); err != nil {
			return errors.Wrap(err, "invalid control plane root volume")
		}
	}
	// Validate control plane extra volumes
	if err = validateGCPExtraVolumes(spec.ControlPlane.ExtraVolumes); err != nil {
		return errors.Wrap(err, "invalid control plane extra volumes")
	}
	for _, wn := range spec.WorkerNodes {
		if (wn.RootVolume != commons.RootVolume{}) {
			// Validate worker node root volume type
			if err = validateVolumeType(wn.RootVolume.Type, GCPVolumes); err != nil {
				return errors.Wrap(err, "invalid worker node "+wn.Name+" root volume")
			}
		}
		// Validate worker node extra volumes
		if err = validateGCPExtraVolumes(wn.ExtraVolumes); err != nil {
			return errors.Wrap(err, "invalid worker node "+wn.Name+" extra volumes")
		}
	}
	return nil
}

func validateGCPExtraVolumes(extraVolumes []commons.ExtraVolume) error {
	var err error
	for _, v := range extraVolumes {
		// Validate extra volume type
		if err = validateVolumeType(v.Type, GCPVolumes); err != nil {
			return err
		}
	}
	return nil
}
