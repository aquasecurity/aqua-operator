package aqualightning

import (
	"fmt"
	"github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/yaml"
	"strconv"
	"strings"
)

const (
	WebhookTimeout int32 = 5
)

// EnforcerParameters :
type LightningParameters struct {
	Lightning *v1alpha1.AquaLightning
}

// AquaEnforcerHelper :
type AquaLightningHelper struct {
	Parameters LightningParameters
}

func newAquaLightningHelper(cr *v1alpha1.AquaLightning) *AquaLightningHelper {
	params := LightningParameters{
		Lightning: cr,
	}

	return &AquaLightningHelper{
		Parameters: params,
	}
}

func (lightning *AquaLightningHelper) newAquaKubeEnforcer(cr *v1alpha1.AquaLightning) *v1alpha1.AquaKubeEnforcer {
	registry := consts.Registry
	if cr.Spec.KubeEnforcer.RegistryData != nil {
		if len(cr.Spec.KubeEnforcer.RegistryData.URL) > 0 {
			registry = cr.Spec.KubeEnforcer.RegistryData.URL
		}
	}
	tag := consts.LatestVersion
	if cr.Spec.KubeEnforcer.Infrastructure.Version != "" {
		tag = cr.Spec.KubeEnforcer.Infrastructure.Version
	}

	resources, err := yamlToResourceRequirements(consts.LightningKubeEnforcerResources)
	if err != nil {
		panic(err)
	}
	if cr.Spec.KubeEnforcer.KubeEnforcerService.Resources != nil {
		resources = cr.Spec.KubeEnforcer.KubeEnforcerService.Resources
	}

	sbResources, err := yamlToResourceRequirements(consts.LightningStarboardResources)
	if err != nil {
		panic(err)
	}
	if cr.Spec.KubeEnforcer.DeployStarboard.Resources != nil {
		sbResources = cr.Spec.KubeEnforcer.DeployStarboard.Resources
	}

	labels := map[string]string{
		"app":                cr.Name + "-lightning",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"aqua.component":     "kubeenforcer",
	}
	annotations := map[string]string{
		"description": "Deploy Aqua KubeEnforcer",
	}

	AquaStarboardDetails := v1alpha1.AquaStarboardDetails{
		AllowAnyVersion: true,
		Infrastructure: &v1alpha1.AquaInfrastructure{
			Version:        consts.StarboardVersion,
			ServiceAccount: "starboard-operator",
		},
		Config: v1alpha1.AquaStarboardConfig{
			ImagePullSecret: "starboard-registry",
		},
		StarboardService: &v1alpha1.AquaService{
			Replicas: 1,
			ImageData: &v1alpha1.AquaImage{
				Registry:   "docker.io/aquasec",
				Repository: "starboard-operator",
				PullPolicy: "IfNotPresent",
			},
			Resources: sbResources,
		},
	}
	aquaKubeEnf := &v1alpha1.AquaKubeEnforcer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaKubeEnforcer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: v1alpha1.AquaKubeEnforcerSpec{
			Config: v1alpha1.AquaKubeEnforcerConfig{
				GatewayAddress:  cr.Spec.Global.GatewayAddress,
				ClusterName:     cr.Spec.Global.ClusterName,
				ImagePullSecret: cr.Spec.Common.ImagePullSecret,
			},
			Token:                  cr.Spec.KubeEnforcer.Token,
			EnforcerUpdateApproved: cr.Spec.KubeEnforcer.EnforcerUpdateApproved,
			AllowAnyVersion:        cr.Spec.KubeEnforcer.AllowAnyVersion,
			ImageData: &v1alpha1.AquaImage{
				Registry:   registry,
				Repository: "kube-enforcer",
				Tag:        tag,
				PullPolicy: "Always",
			},

			KubeEnforcerService: &v1alpha1.AquaService{
				Resources: resources,
			},

			DeployStarboard: &AquaStarboardDetails,
		},
	}

	return aquaKubeEnf
}

func (lightning *AquaLightningHelper) newAquaEnforcer(cr *v1alpha1.AquaLightning) *v1alpha1.AquaEnforcer {
	registry := consts.Registry
	if cr.Spec.Enforcer.EnforcerService.ImageData != nil {
		if len(cr.Spec.Enforcer.EnforcerService.ImageData.Registry) > 0 {
			registry = cr.Spec.Enforcer.EnforcerService.ImageData.Registry
		}
	}
	tag := consts.LatestVersion
	if cr.Spec.Enforcer.Infrastructure.Version != "" {
		tag = cr.Spec.Enforcer.Infrastructure.Version
	}

	resources, err := yamlToResourceRequirements(consts.LightningEnforcerResources)
	if err != nil {
		panic(err)
	}
	if cr.Spec.Enforcer.EnforcerService.Resources != nil {
		resources = cr.Spec.Enforcer.EnforcerService.Resources
	}

	gwParts := strings.Split(cr.Spec.Global.GatewayAddress, ":")
	gatewayHost := gwParts[0]
	gatewayPort, _ := strconv.ParseInt(gwParts[1], 10, 64)

	labels := map[string]string{
		"app":                cr.Name + "-enforcer",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"aqua.component":     "enforcer",
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Enforcer",
	}
	aquaenf := &v1alpha1.AquaEnforcer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaEnforcer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: v1alpha1.AquaEnforcerSpec{
			Infrastructure: cr.Spec.Enforcer.Infrastructure,
			Common:         cr.Spec.Common,
			Gateway: &v1alpha1.AquaGatewayInformation{
				Host: gatewayHost,
				Port: gatewayPort,
			},
			Token: cr.Spec.Enforcer.Token,
			Secret: &v1alpha1.AquaSecret{
				Name: cr.Spec.Enforcer.Secret.Name,
				Key:  cr.Spec.Enforcer.Secret.Key,
			},
			EnforcerService: &v1alpha1.AquaService{
				ImageData: &v1alpha1.AquaImage{
					Registry:   registry,
					Repository: "enforcer",
					Tag:        tag,
					PullPolicy: "Always",
				},
				Resources: resources,
			},
			RunAsNonRoot:           cr.Spec.Enforcer.RunAsNonRoot,
			EnforcerUpdateApproved: cr.Spec.Enforcer.EnforcerUpdateApproved,
		},
	}
	return aquaenf
}

func yamlToResourceRequirements(yamlString string) (*v1.ResourceRequirements, error) {
	var yamlData map[string]map[string]map[string]string

	err := yaml.Unmarshal([]byte(yamlString), &yamlData)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling YAML: %w", err)
	}

	limits := make(map[v1.ResourceName]resource.Quantity)
	requests := make(map[v1.ResourceName]resource.Quantity)

	for k, v := range yamlData["resources"]["limits"] {
		limits[v1.ResourceName(k)] = resource.MustParse(v)
	}
	for k, v := range yamlData["resources"]["requests"] {
		requests[v1.ResourceName(k)] = resource.MustParse(v)
	}

	resourceRequirements := &v1.ResourceRequirements{
		Limits:   limits,
		Requests: requests,
	}

	return resourceRequirements, nil
}
