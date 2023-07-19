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
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/apparentlymart/go-cidr/cidr"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"golang.org/x/exp/slices"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
)

// TODO: validate provider storage class fields
// TODO: validate AZs

const (
	cidrSizeMax = 65536
	cidrSizeMin = 16
)

var AWSVolumes = []string{"io1", "io2", "gp2", "gp3", "sc1", "st1", "standard", "sbp1", "sbg1"}
var AWSFSTypes = []string{"xfs", "ext3", "ext4", "ext2"}
var AWSSCFields = []string{"type", "fsType", "labels", "allowAutoIOPSPerGBIncrease", "blockExpress", "blockSize", "iops", "iopsPerGB", "encrypted", "throughput"}

func validateAWS(cluster commons.KeosCluster, providerSecrets map[string]string) error {
	var err error

	cfg, err := getAWSConfig(providerSecrets, cluster.Spec.Region)
	if err != nil {
		return err
	}

	if (cluster.Spec.StorageClass != commons.StorageClass{}) {
		if err = validateAWSStorageClass(cluster.Spec.StorageClass, cluster.Spec.WorkerNodes); err != nil {
			return errors.Wrap(err, "invalid storage class")
		}
	}

	if err = validateAWSNetwork(cluster.Spec, cfg); err != nil {
		return errors.Wrap(err, "invalid network")
	}

	return nil
}

func getAWSConfig(secrets map[string]string, region string) (aws.Config, error) {
	customProvider := credentials.NewStaticCredentialsProvider(
		secrets["AccessKey"], secrets["SecretKey"], "",
	)
	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithCredentialsProvider(customProvider),
		config.WithRegion(region),
	)
	if err != nil {
		return aws.Config{}, err
	}
	return cfg, nil
}

func validateAWSNetwork(spec commons.Spec, cfg aws.Config) error {
	var err error
	if spec.Networks.PodsCidrBlock != "" {
		if err = validateAWSPodsNetwork(spec.Networks.PodsCidrBlock); err != nil {
			return err
		}
	}
	if err = validateAWSAZs(spec, cfg); err != nil {
		return err
	}
	return nil
}

func validateAWSPodsNetwork(podsNetwork string) error {
	// Minimum cidr range: 100.64.0.0/10
	validRange1 := net.IPNet{
		IP:   net.ParseIP("100.64.0.0"),
		Mask: net.IPv4Mask(255, 192, 0, 0),
	}
	// Maximum cidr range: 198.19.0.0/16
	validRange2 := net.IPNet{
		IP:   net.ParseIP("198.19.0.0"),
		Mask: net.IPv4Mask(255, 255, 0, 0),
	}

	_, ipv4Net, err := net.ParseCIDR(podsNetwork)
	if err != nil {
		return errors.New("invalid parameter pods_cidr, CIDR block must be a valid IPv4 CIDR block")
	}

	cidrSize := cidr.AddressCount(ipv4Net)
	if cidrSize > cidrSizeMax || cidrSize < cidrSizeMin {
		return errors.New("invalid parameter pods_cidr, CIDR block sizes must be between a /16 and /28 netmask")
	}

	start, end := cidr.AddressRange(ipv4Net)
	if (!validRange1.Contains(start) || !validRange1.Contains(end)) && (!validRange2.Contains(start) || !validRange2.Contains(end)) {
		return errors.New("invalid parameter pods_cidr, CIDR block must be between " + validRange1.String() + " and " + validRange2.String())
	}
	return nil
}

func validateAWSStorageClass(sc commons.StorageClass, wn commons.WorkerNodes) error {
	var err error
	var isKeyValid = regexp.MustCompile(`^arn:aws:kms:[a-zA-Z0-9-]+:\d{12}:key/[\w-]+$`).MatchString
	var typesSupportedForIOPS = []string{"io1", "io2", "gp3"}
	var iopsValue string
	var iopsKey string

	// Validate encryptionKey format
	if sc.EncryptionKey != "" {
		if !isKeyValid(sc.EncryptionKey) {
			return errors.New("incorrect encryptionKey format. It must have the format arn:aws:kms:[REGION]:[ACCOUNT_ID]:key/[KEY_ID]")
		}
	}
	// Validate diskEncryptionSetID format
	if sc.Parameters.KmsKeyId != "" {
		if !isKeyValid(sc.Parameters.KmsKeyId) {
			return errors.New("incorrect kmsKeyId format. It must have the format arn:aws:kms:[REGION]:[ACCOUNT_ID]:key/[KEY_ID]")
		}
	}
	// Validate type
	if sc.Parameters.Type != "" && !commons.Contains(AWSVolumes, sc.Parameters.Type) {
		return errors.New("unsupported type: " + sc.Parameters.Type)
	}
	// Validate fsType
	if sc.Parameters.FsType != "" && !commons.Contains(AWSFSTypes, sc.Parameters.FsType) {
		return errors.New("unsupported fsType: " + sc.Parameters.FsType + ". Supported types: " + fmt.Sprint(strings.Join(AWSFSTypes, ", ")))
	}
	// Validate iops
	if sc.Parameters.Iops != "" {
		iopsValue = sc.Parameters.Iops
		iopsKey = "iops"
	}
	if sc.Parameters.IopsPerGB != "" {
		iopsValue = sc.Parameters.IopsPerGB
		iopsKey = "iopsPerGB"
	}
	if iopsValue != "" && sc.Parameters.Type != "" && !slices.Contains(typesSupportedForIOPS, sc.Parameters.Type) {
		return errors.New(iopsKey + " only can be specified for " + fmt.Sprint(strings.Join(typesSupportedForIOPS, ", ")) + " types")
	}
	if iopsValue != "" {
		iops, err := strconv.Atoi(iopsValue)
		if err != nil {
			return errors.New("invalid " + iopsKey + " parameter. It must be a number in string format")
		}
		if (sc.Class == "standard" && sc.Parameters.Type == "") || sc.Parameters.Type == "gp3" {
			if iops < 3000 || iops > 16000 {
				return errors.New("invalid " + iopsKey + " parameter. It must be greater than 3000 and lower than 16000 for gp3 type")
			}
		}
		if (sc.Class == "premium" && sc.Parameters.Type == "") || sc.Parameters.Type == "io1" || sc.Parameters.Type == "io2" {
			if iops < 16000 || iops > 64000 {
				return errors.New("invalid " + iopsKey + " parameter. It must be greater than 16000 and lower than 64000 for io1 and io2 types")
			}
		}
	}
	// Validate labels
	if sc.Parameters.Labels != "" {
		if err = validateLabel(sc.Parameters.Labels); err != nil {
			return errors.Wrap(err, "invalid labels")
		}
	}
	return nil
}

func validateAWSAZs(spec commons.Spec, cfg aws.Config) error {
	// svc := ec2.NewFromConfig(cfg)
	// ctx := context.TODO()
	// 	if spec.Networks.Subnets != nil {
	// 		privateAZs := []string{}
	// 		for _, subnet := range spec.Networks.Subnets {
	// 			privateSubnetID, _ := filterPrivateSubnet(svc, &subnet.SubnetId)
	// 			fmt.Println(privateSubnetID)
	// 			if len(privateSubnetID) > 0 {
	// 				sid := &ec2.DescribeSubnetsInput{
	// 					SubnetIds: []string{subnet.SubnetId},
	// 				}
	// 				ds, err := svc.DescribeSubnets(ctx, sid)
	// 				if err != nil {
	// 					return err
	// 				}
	// 				for _, describeSubnet := range ds.Subnets {
	// 					if !slices.Contains(privateAZs, *describeSubnet.AvailabilityZone) {
	// 						privateAZs = append(privateAZs, *describeSubnet.AvailabilityZone)
	// 					}
	// 				}
	// 			}
	// 		}
	// 		if len(privateAZs) < 3 {
	// 			return errors.New("Insufficient Availability Zones in region " + spec.Region + ". Please add at least 3 private subnets in different Availability Zones")
	// 		}
	// 		for _, node := range spec.WorkerNodes {
	// 			if node.ZoneDistribution == "unbalanced" && node.AZ != "" {
	// 				if !slices.Contains(privateAZs, node.AZ) {
	// 					return errors.New("Worker node " + node.Name + " whose AZ is defined in " + node.AZ + " must match with the AZs associated to the defined subnets in descriptor")
	// 				}
	// 			}
	// 		}
	// 	} else {
	// 		result, err := svc.DescribeAvailabilityZones(&ec2.DescribeAvailabilityZonesInput{})
	// 		if err != nil {
	// 			return err
	// 		}
	// 		if len(result.AvailabilityZones) < 3 {
	// 			return errors.New("Insufficient Availability Zones in region " + spec.Region + ". Must have at least 3")
	// 		}
	// 		azs := make([]string, 3)
	// 		for i, az := range result.AvailabilityZones {
	// 			if i == 3 {
	// 				break
	// 			}
	// 			azs[i] = *az.ZoneName
	// 		}
	// 		for _, node := range spec.WorkerNodes {
	// 			if node.ZoneDistribution == "unbalanced" && node.AZ != "" {
	// 				if !slices.Contains(azs, node.AZ) {
	// 					return errors.New("Worker node " + node.Name + " whose AZ is defined in " + node.AZ + " must match with the first three AZs in region " + spec.Region)
	// 				}
	// 			}
	// 		}
	// 	}
	return nil
}

// func filterPrivateSubnet(svc *ec2.EC2, subnetID *string) (string, error) {
// 	keyname := "association.subnet-id"
// 	filters := make([]*ec2.Filter, 0)
// 	filter := ec2.Filter{
// 		Name: &keyname, Values: []*string{subnetID}}
// 	filters = append(filters, &filter)

// 	drti := &ec2.DescribeRouteTablesInput{Filters: filters}
// 	drto, err := svc.DescribeRouteTables(drti)
// 	if err != nil {
// 		return "", err
// 	}

// 	var isPublic bool
// 	for _, associatedRouteTable := range drto.RouteTables {
// 		for i := range associatedRouteTable.Routes {
// 			route := associatedRouteTable.Routes[i]

// 			if route.DestinationCidrBlock != nil &&
// 				route.GatewayId != nil &&
// 				*route.DestinationCidrBlock == "0.0.0.0/0" &&
// 				strings.Contains(*route.GatewayId, "igw") {
// 				isPublic = true
// 			}
// 		}
// 	}
// 	if !isPublic {
// 		return *subnetID, nil
// 	} else {
// 		return "", nil
// 	}
// }
