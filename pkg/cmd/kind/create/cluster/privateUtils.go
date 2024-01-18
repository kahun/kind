package cluster

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"sigs.k8s.io/kind/pkg/commons"
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
			if keosCluster.Spec.InfraProvider != "aws" {
				registryParams.User = clusterCredentials.KeosRegistryCredentials["User"]
				registryParams.Pass = clusterCredentials.KeosRegistryCredentials["Pass"]
			} else {
				user, pass, err := getRegistryCredentials(clusterCredentials, registry.URL)
				if err != nil {
					return "", err
				}
				registryParams.User = user
				registryParams.Pass = pass
			}

			break
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

func getRegistryCredentials(clusterCredentials commons.ClusterCredentials, keosRegUrl string) (string, string, error) {
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
