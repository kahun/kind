package validation

import (
	"errors"
	"net"

	"github.com/apparentlymart/go-cidr/cidr"
	"sigs.k8s.io/kind/pkg/commons"
)

var awsInstance *AWSValidator

const (
	cidrSizeMax = 65536
	cidrSizeMin = 16
)

type AWSValidator struct {
	commonValidator
	managed bool
}

func newAWSValidator(managed bool) *AWSValidator {
	if awsInstance == nil {
		awsInstance = new(AWSValidator)
	}
	awsInstance.managed = managed
	return awsInstance
}

func (v *AWSValidator) DescriptorFile(descriptorFile commons.DescriptorFile) {
	v.descriptor = descriptorFile
}

func (v *AWSValidator) SecretsFile(secrets commons.SecretsFile) {
	v.secrets = secrets
}

func (v *AWSValidator) Validate(fileType string) error {
	switch fileType {
	case "descriptor":
		err := descriptorAwsValidations((*v).descriptor)
		if err != nil {
			return err
		}
	case "secrets":
		err := secretsAwsValidations((*v).secrets)
		if err != nil {
			return err
		}
	default:
		return errors.New("Incorrect filetype validation")
	}
	return nil
}

func (v *AWSValidator) CommonsValidations() error {
	err := commonsValidations((*v).descriptor, (*v).secrets)
	if err != nil {
		return err
	}
	return nil
}

func descriptorAwsValidations(descriptorFile commons.DescriptorFile) error {
	err := commonsDescriptorValidation(descriptorFile)
	if err != nil {
		return err
	}
	err = validateVPCCidr(descriptorFile)
	if err != nil {
		return err
	}
	return nil
}

func secretsAwsValidations(secretsFile commons.SecretsFile) error {
	err := commonsSecretsValidations(secretsFile)
	if err != nil {
		return err
	}
	return nil
}

func validateVPCCidr(descriptorFile commons.DescriptorFile) error {
	if descriptorFile.Networks.VPCCidrBlock != "" {
		_, ipv4Net, _ := net.ParseCIDR(descriptorFile.Networks.VPCCidrBlock)
		cidrSize := cidr.AddressCount(ipv4Net)
		if cidrSize > cidrSizeMax || cidrSize < cidrSizeMin {
			return errors.New("Invalid parameter VPCCidrBlock, CIDR block sizes must be between a /16 netmask and /28 netmask")
		}
	}
	if descriptorFile.Networks.PodsCidrBlock != "" {
		_, validRange1, _ := net.ParseCIDR("100.64.0.0/10")
		_, validRange2, _ := net.ParseCIDR("198.19.0.0/16")

		_, ipv4Net, _ := net.ParseCIDR(descriptorFile.Networks.PodsCidrBlock)

		cidrSize := cidr.AddressCount(ipv4Net)
		if cidrSize > cidrSizeMax || cidrSize < cidrSizeMin {
			return errors.New("Invalid parameter PodsCidrBlock, CIDR block sizes must be between a /16 netmask and /28 netmask")
		}

		start, end := cidr.AddressRange(ipv4Net)
		if (!validRange1.Contains(start) || !validRange1.Contains(end)) && (!validRange2.Contains(start) || !validRange2.Contains(end)) {
			return errors.New("Invalid parameter PodsCidrBlock, CIDR must be within the 100.64.0.0/10 or 198.19.0.0/16 range")
		}
	}
	return nil
}
