package cluster

import (
	"bytes"
	"embed"
	"os"
	"strings"
	"text/template"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*
var ctel embed.FS

// DescriptorFile represents the YAML structure in the cluster.yaml file
type DescriptorFile struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	ClusterID  string `yaml:"cluster_id" validate:"required"`

	Bastion Bastion `yaml:"bastion"`

	Credentials struct {
		AccessKey  string `yaml:"access_key"`
		Account    string `yaml:"account"`
		Region     string `yaml:"region"`
		SecretKey  string `yaml:"secret"`
		AssumeRole string `yaml:"assume_role"`
	} `yaml:"credentials"`

	InfraProvider string `yaml:"infra_provider" validate:"required,oneof='aws' 'gcp' 'azure'"`

	K8SVersion   string `yaml:"k8s_version" validate:"required"`
	Region       string `yaml:"region" validate:"required"`
	SSHKey       string `yaml:"ssh_key"`
	FullyPrivate bool   `yaml:"fully_private" validate:"boolean"`

	// Networks struct {
	// 	VPCID   string `yaml:"vpc_id"`
	// 	subnets []struct {
	// 		AvailabilityZone string `yaml:"availability_zone"`
	// 		Name             string `yaml:"name"`
	// 		PrivateCIDR      string `yaml:"private_cidr"`
	// 		PublicCIDR       string `yaml:"public_cidr"`
	// 	} `yaml:"subnets"`
	// }

	ExternalRegistry struct {
		AuthRequired bool   `yaml: auth_required validate:"boolean"`
		Type         string `yaml: type`
		URL          string `yaml: url validate:"url"`
	} `yaml:"external_registry"`

	Keos struct {
		Domain         string `yaml:"domain"`
		ExternalDomain string `yaml:"external_domain"`
		Flavour        string `yaml:"flavour"`
		Version        string `yaml:"version"`
	} `yaml:"keos"`

	ControlPlane struct {
		Managed         bool   `yaml:"managed" validate:"boolean"`
		Name            string `yaml:"name"`
		AmiID           string `yaml:"ami_id"`
		HighlyAvailable bool   `yaml:"highly_available" validate:"boolean"`
		Size            string `yaml:"size"`
		Image           string `yaml:"image"`
		AWS             AWS    `yaml:"aws"`
	} `yaml:"control_plane"`

	WorkerNodes WorkerNodes `yaml:"worker_nodes"`
}

type AWS struct {
	AssociateOIDCProvider bool `yaml:"associate_oidc_provider" validate:"boolean"`
	Logging               struct {
		ApiServer         bool `yaml:"api_server" validate:"boolean"`
		Audit             bool `yaml:"audit" validate:"boolean"`
		Authenticator     bool `yaml:"authenticator" validate:"boolean"`
		ControllerManager bool `yaml:"controller_manager" validate:"boolean"`
		Scheduler         bool `yaml:"scheduler" validate:"boolean"`
	}
}

type WorkerNodes []struct {
	Name             string `yaml:"name"`
	AmiID            string `yaml:"ami_id"`
	Quantity         int    `yaml:"quantity" validate:"required,numeric"`
	Size             string `yaml:"size" validate:"required"`
	Image            string `yaml:"image"`
	ZoneDistribution string `yaml:"zone_distribution" validate:"oneof='balanced' 'unbalanced'"`
	AZ               string `yaml:"az"`
	SSHKey           string `yaml:"ssh_key"`
	Spot             bool   `yaml:"spot" validate:"boolean"`
	RootVolume       struct {
		Size      int    `yaml:"size" validate:"numeric"`
		Type      string `yaml:"type"`
		Encrypted bool   `yaml:"encrypted" validate:"boolean"`
	} `yaml:"root_volume"`
}

// Bastion represents the bastion VM
type Bastion struct {
	AmiID             string   `yaml:"ami_id"`
	VMSize            string   `yaml:"vm_size"`
	AllowedCIDRBlocks []string `yaml:"allowedCIDRBlocks"`
}

// Init sets default values for the DescriptorFile
func (d DescriptorFile) Init() DescriptorFile {
	d.FullyPrivate = false
	d.ControlPlane.HighlyAvailable = true

	// AWS
	d.ControlPlane.AWS.AssociateOIDCProvider = true
	d.ControlPlane.AWS.Logging.ApiServer = false
	d.ControlPlane.AWS.Logging.Audit = false
	d.ControlPlane.AWS.Logging.Authenticator = false
	d.ControlPlane.AWS.Logging.ControllerManager = false
	d.ControlPlane.AWS.Logging.Scheduler = false
	return d
}

// Read cluster.yaml file
func GetClusterDescriptor() (*DescriptorFile, error) {
	descriptorRAW, err := os.ReadFile("./cluster.yaml")
	if err != nil {
		return nil, err
	}
	descriptorFile := new(DescriptorFile).Init()
	err = yaml.Unmarshal(descriptorRAW, &descriptorFile)
	if err != nil {
		return nil, err
	}

	validate := validator.New()
	err = validate.Struct(descriptorFile)
	if err != nil {
		return nil, err
	}
	return &descriptorFile, nil
}

func GetClusterManifest(d DescriptorFile) (string, error) {

	var flavor string
	switch d.InfraProvider {
	case "aws":
		if d.ControlPlane.Managed {
			flavor = "templates/aws.eks.tmpl"
		} else {
			flavor = "templates/aws.tmpl"
		}
	}

	funcMap := template.FuncMap{
		"loop": func(az string) <-chan string {
			ch := make(chan string)
			go func() {
				var azs []string
				if az != "" {
					azs = []string{az}

				} else {
					azs = []string{"a", "b", "c"}
				}
				for _, v := range azs {
					ch <- v
				}
				close(ch)
			}()
			return ch
		},
	}

	var tpl bytes.Buffer
	t, err := template.New("").Funcs(funcMap).ParseFS(ctel, flavor)
	if err != nil {
		return "", err
	}

	err = t.ExecuteTemplate(&tpl, strings.Split(flavor, "/")[1], d)
	if err != nil {
		return "", err
	}
	return tpl.String(), nil
}
