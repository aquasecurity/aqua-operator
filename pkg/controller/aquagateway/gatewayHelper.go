package aquagateway

import (
	"fmt"
	"os"

	routev1 "github.com/openshift/api/route/v1"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/controller/common"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/services"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type GatewayParameters struct {
	Gateway *operatorv1alpha1.AquaGateway
}

type AquaGatewayHelper struct {
	Parameters GatewayParameters
}

func newAquaGatewayHelper(cr *operatorv1alpha1.AquaGateway) *AquaGatewayHelper {
	params := GatewayParameters{
		Gateway: cr,
	}

	return &AquaGatewayHelper{
		Parameters: params,
	}
}

func (gw *AquaGatewayHelper) newDeployment(cr *operatorv1alpha1.AquaGateway) *appsv1.Deployment {
	pullPolicy, registry, repository, tag := extra.GetImageData("gateway", cr.Spec.Infrastructure.Version, cr.Spec.GatewayService.ImageData, cr.Spec.Common.AllowAnyVersion)

	image := os.Getenv("RELATED_IMAGE_GATEWAY")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                cr.Name + "-gateway",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"type":               "aqua-gateway",
	}
	annotations := map[string]string{
		"description": "Deploy the aqua gateway server",
	}

	envVars := gw.getEnvVars(cr)

	privileged := true

	if cr.Spec.RunAsNonRoot {
		privileged = false
	}

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf(consts.GatewayDeployName, cr.Name),
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: extra.Int32Ptr(int32(cr.Spec.GatewayService.Replicas)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: cr.Spec.Infrastructure.ServiceAccount,
					Containers: []corev1.Container{
						{
							Name:            "aqua-gateway",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							Ports: []corev1.ContainerPort{
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 3622,
								},
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 8443,
								},
							},
							Env: envVars,
						},
					},
				},
			},
		},
	}

	if cr.Spec.GatewayService.Resources != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *cr.Spec.GatewayService.Resources
	}

	if cr.Spec.GatewayService.LivenessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].LivenessProbe = cr.Spec.GatewayService.LivenessProbe
	}

	if cr.Spec.GatewayService.ReadinessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = cr.Spec.GatewayService.ReadinessProbe
	}

	if cr.Spec.GatewayService.NodeSelector != nil {
		if len(cr.Spec.GatewayService.NodeSelector) > 0 {
			deployment.Spec.Template.Spec.NodeSelector = cr.Spec.GatewayService.NodeSelector
		}
	}

	if cr.Spec.GatewayService.Affinity != nil {
		deployment.Spec.Template.Spec.Affinity = cr.Spec.GatewayService.Affinity
	}

	if cr.Spec.GatewayService.Tolerations != nil {
		if len(cr.Spec.GatewayService.Tolerations) > 0 {
			deployment.Spec.Template.Spec.Tolerations = cr.Spec.GatewayService.Tolerations
		}
	}

	if cr.Spec.Common != nil {
		if len(cr.Spec.Common.ImagePullSecret) != 0 {
			deployment.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				corev1.LocalObjectReference{
					Name: cr.Spec.Common.ImagePullSecret,
				},
			}
		}
	}

	if cr.Spec.RunAsNonRoot {
		runAsUser := int64(11431)
		runAsGroup := int64(11433)
		fsGroup := int64(11433)
		deployment.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{
			RunAsUser:    &runAsUser,
			RunAsGroup:   &runAsGroup,
			RunAsNonRoot: &cr.Spec.RunAsNonRoot,
			FSGroup:      &fsGroup,
		}
	}

	if cr.Spec.GatewayService.VolumeMounts != nil {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, cr.Spec.GatewayService.VolumeMounts...)
	}

	if cr.Spec.GatewayService.Volumes != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, cr.Spec.GatewayService.Volumes...)
	}

	if cr.Spec.Mtls {
		mtlsAquaGatewayVolumeMount := []corev1.VolumeMount{
			{
				Name:      "aqua-grpc-gateway",
				MountPath: "/opt/aquasec/ssl",
				ReadOnly:  true,
			},
		}

		secretVolumeSource := corev1.SecretVolumeSource{
			SecretName: "aqua-grpc-gateway",
			Items: []corev1.KeyToPath{
				{
					Key:  "aqua_gateway.crt",
					Path: "cert.pem",
				},
				{
					Key:  "aqua_gateway.key",
					Path: "key.pem",
				},
				{
					Key:  "rootCA.crt",
					Path: "ca.pem",
				},
			},
		}

		mtlsAquaGatewayVolume := []corev1.Volume{
			{
				Name: "aqua-grpc-gateway",
				VolumeSource: corev1.VolumeSource{
					Secret: &secretVolumeSource,
				},
			},
		}
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, mtlsAquaGatewayVolumeMount...)
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, mtlsAquaGatewayVolume...)
	}

	return deployment
}

func (gw *AquaGatewayHelper) getEnvVars(cr *operatorv1alpha1.AquaGateway) []corev1.EnvVar {
	envsHelper := common.NewAquaEnvsHelper(cr.Spec.Infrastructure, cr.Spec.Common, cr.Spec.ExternalDb, cr.Name, cr.Spec.AuditDB)
	result, _ := envsHelper.GetDbEnvVars()

	result = append(result, corev1.EnvVar{
		Name:  "HEALTH_MONITOR",
		Value: "0.0.0.0:8082",
	})

	result = append(result, corev1.EnvVar{
		Name:  "AQUA_CONSOLE_SECURE_ADDRESS",
		Value: fmt.Sprintf("%s:443", fmt.Sprintf(consts.ServerServiceName, cr.Name)),
	})

	result = append(result, corev1.EnvVar{
		Name:  "SCALOCK_GATEWAY_PUBLIC_IP",
		Value: fmt.Sprintf(consts.GatewayServiceName, cr.Name),
	})

	if cr.Spec.Mtls {
		mtlsServerEnv := []corev1.EnvVar{
			{
				Name:  "AQUA_PRIVATE_KEY",
				Value: "/opt/aquasec/ssl/key.pem",
			},
			{
				Name:  "AQUA_PUBLIC_KEY",
				Value: "/opt/aquasec/ssl/cert.pem",
			},
			{
				Name:  "AQUA_ROOT_CA",
				Value: "/opt/aquasec/ssl/ca.pem",
			},
			{
				Name:  "AQUA_VERIFY_ENFORCER",
				Value: "1",
			},
		}
		result = append(result, mtlsServerEnv...)
	}

	if cr.Spec.Envs != nil {
		for _, env := range cr.Spec.Envs {
			result = extra.AppendEnvVar(result, env)
		}
	}

	return result
}

func (gw *AquaGatewayHelper) newService(cr *operatorv1alpha1.AquaGateway) *corev1.Service {
	selectors := map[string]string{
		"app": fmt.Sprintf("%s-gateway", cr.Name),
	}

	ports := []corev1.ServicePort{
		{
			Port:       3622,
			TargetPort: intstr.FromInt(3622),
			Name:       "aqua-gate",
		},
		{
			Port:       8443,
			TargetPort: intstr.FromInt(8443),
			Name:       "aqua-gate-ssl",
		},
	}

	service := services.CreateService(cr.Name,
		cr.Namespace,
		fmt.Sprintf(consts.GatewayServiceName, cr.Name),
		fmt.Sprintf("%s-gateway", cr.Name),
		"Service for aqua gateway components",
		cr.Spec.GatewayService.ServiceType,
		selectors,
		ports)

	return service
}

func (gw *AquaGatewayHelper) newRoute(cr *operatorv1alpha1.AquaGateway) *routev1.Route {

	gwServiceName := fmt.Sprintf(consts.GatewayServiceName, cr.Name)

	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      gwServiceName,
			Namespace: cr.Namespace,
		},
		Spec: routev1.RouteSpec{
			TLS: &routev1.TLSConfig{
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyNone,
				Termination:                   routev1.TLSTerminationPassthrough,
			},
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: gwServiceName,
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromInt(8443),
			},
		},
	}
}
