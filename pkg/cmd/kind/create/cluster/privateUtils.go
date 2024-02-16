package cluster

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"golang.org/x/oauth2/google"
	"sigs.k8s.io/kind/pkg/commons"
	"sigs.k8s.io/kind/pkg/errors"
)

//go:embed privatefiles/*
var clusterConfig embed.FS

type RegistryParams struct {
	Url  string
	User string
	Pass string
}

func getConfigFile(keosCluster *commons.KeosCluster, clusterCredentials commons.ClusterCredentials) (string, error) {
	registryParams := RegistryParams{}

	var tpl bytes.Buffer
	funcMap := template.FuncMap{
		"hostname": func(s string) string {
			return strings.Split(s, "/")[0]
		},
	}

	templatePath := filepath.Join("privatefiles", "privateconfig.tmpl")
	t, err := template.New("").Funcs(funcMap).ParseFS(clusterConfig, templatePath)
	if err != nil {
		return "", err
	}
	for _, registry := range keosCluster.Spec.DockerRegistries {
		if registry.KeosRegistry {
			registryParams.Url = registry.URL
			switch registry.Type {
			case "ecr":
				user, pass, err := getECRCredentials(clusterCredentials, registry.URL)
				if err != nil {
					return "", err
				}
				registryParams.User = user
				registryParams.Pass = pass
			case "acr":
				user, pass, err := getACRCredentials(clusterCredentials, registry.URL)
				if err != nil {
					return "", err
				}
				registryParams.User = user
				registryParams.Pass = pass
			case "gcr":
				user, pass, err := getGARCredentials(clusterCredentials, registry.URL)
				if err != nil {
					return "", err
				}
				registryParams.User = user
				registryParams.Pass = pass
			case "gar":
				user, pass, err := getGARCredentials(clusterCredentials, registry.URL)
				if err != nil {
					return "", err
				}
				registryParams.User = user
				registryParams.Pass = pass
			default:
				if registry.AuthRequired {
					registryParams.User = clusterCredentials.KeosRegistryCredentials["User"]
					registryParams.Pass = clusterCredentials.KeosRegistryCredentials["Pass"]
				}
			}

			break
		}
	}

	if registryParams.Url != "" {
		c := "docker"
		args := []string{"login", "-u", registryParams.User, "-p", registryParams.Pass, registryParams.Url}

		cmd := exec.Command(c, args...)
		_, err := cmd.CombinedOutput()
		if err != nil {
			errors.Wrap(err, "Failed in docker login: ")
			return "", err
		}
	}

	err = t.ExecuteTemplate(&tpl, "privateconfig.tmpl", registryParams)
	if err != nil {
		return "", err
	}
	tempFile, err := os.CreateTemp("", "configfile")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	_, err = tempFile.WriteString(tpl.String())
	if err != nil {
		return "", err
	}
	return tempFile.Name(), nil
}

func getECRCredentials(clusterCredentials commons.ClusterCredentials, keosRegUrl string) (string, string, error) {
	var registryUser = "AWS"
	var registryPass string
	var ctx = context.Background()

	credentials := map[string]string{
		"AccessKey": clusterCredentials.ProviderCredentials["AccessKey"],
		"SecretKey": clusterCredentials.ProviderCredentials["SecretKey"],
	}
	region := strings.Split(keosRegUrl, ".")[3]
	cfg, err := commons.AWSGetConfig(ctx, credentials, region)
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

func getACRCredentials(clusterCredentials commons.ClusterCredentials, keosRegUrl string) (string, string, error) {
	var registryUser = "00000000-0000-0000-0000-000000000000"
	var registryPass string
	var ctx = context.Background()
	var response map[string]interface{}

	cfg, err := commons.AzureGetConfig(clusterCredentials.ProviderCredentials)
	if err != nil {
		return "", "", err
	}
	aadToken, err := cfg.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://management.azure.com/.default"}})
	if err != nil {
		return "", "", err
	}
	acrService := strings.Split(keosRegUrl, "/")[0]
	formData := url.Values{
		"grant_type":   {"access_token"},
		"service":      {acrService},
		"tenant":       {clusterCredentials.ProviderCredentials["TenantID"]},
		"access_token": {aadToken.Token},
	}
	jsonResponse, err := http.PostForm(fmt.Sprintf("https://%s/oauth2/exchange", acrService), formData)
	if err != nil {
		return "", "", err
	} else if jsonResponse.StatusCode == http.StatusUnauthorized {
		return "", "", errors.New("Failed to obtain the ACR token with the provided credentials, please check the roles assigned to the correspondent Azure AD app")
	}
	json.NewDecoder(jsonResponse.Body).Decode(&response)
	if response["access_token"] != nil {
		registryPass = response["access_token"].(string)
	} else if response["refresh_token"] != nil {
		registryPass = response["refresh_token"].(string)
	} else {
		return "", "", errors.New("Failed to obtain the ACR token with the provided credentials, please check the roles assigned to the correspondent Azure AD app")
	}
	return registryUser, registryPass, nil
}

func getGARCredentials(clusterCredentials commons.ClusterCredentials, keosRegUrl string) (string, string, error) {
	var registryUser = "oauth2accesstoken"
	var ctx = context.Background()
	scope := "https://www.googleapis.com/auth/cloud-platform"
	data := map[string]interface{}{
		"type":                        "service_account",
		"project_id":                  clusterCredentials.ProviderCredentials["ProjectID"],
		"private_key_id":              clusterCredentials.ProviderCredentials["PrivateKeyID"],
		"private_key":                 clusterCredentials.ProviderCredentials["PrivateKey"],
		"client_email":                clusterCredentials.ProviderCredentials["ClientEmail"],
		"client_id":                   clusterCredentials.ProviderCredentials["ClientID"],
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://accounts.google.com/o/oauth2/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/" + url.QueryEscape(clusterCredentials.ProviderCredentials["ClientEmail"]),
	}
	jsonData, _ := json.Marshal(data)

	creds, err := google.CredentialsFromJSON(ctx, jsonData, scope)
	if err != nil {
		return "", "", err
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return "", "", err
	}
	return registryUser, token.AccessToken, nil
}
