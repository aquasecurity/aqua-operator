package aquaserver

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/services"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/controller/common"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/util/intstr"
)

type ServerParameters struct {
	Server *operatorv1alpha1.AquaServer
}

type AquaServerHelper struct {
	Parameters ServerParameters
}

func newAquaServerHelper(cr *operatorv1alpha1.AquaServer) *AquaServerHelper {
	params := ServerParameters{
		Server: cr,
	}

	return &AquaServerHelper{
		Parameters: params,
	}
}

func (sr *AquaServerHelper) newDeployment(cr *operatorv1alpha1.AquaServer) *appsv1.Deployment {
	pullPolicy, registry, repository, tag := extra.GetImageData("server", cr.Spec.Infrastructure.Version, cr.Spec.ServerService.ImageData)

	image := os.Getenv("RELATED_IMAGE_SERVER")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                cr.Name + "-server",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"type":               "aqua-server",
	}
	annotations := map[string]string{
		"description": "Deploy the aqua console server",
	}
	envvars := sr.getEnvVars(cr)
	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf(consts.ServerDeployName, cr.Name),
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: extra.Int32Ptr(int32(cr.Spec.ServerService.Replicas)),
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
							Name:            "aqua-server",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
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
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "aqua-web-pvc",
									MountPath: "/opt/aquasec/raw-scan-results",
								},
							},
							Env: envvars,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "aqua-web-pvc",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: fmt.Sprintf(consts.ServerPvcName, cr.Name),
								},
							},
						},
					},
				},
			},
		},
	}

	if cr.Spec.ServerService.Resources != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *cr.Spec.ServerService.Resources
	}

	if cr.Spec.ServerService.LivenessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].LivenessProbe = cr.Spec.ServerService.LivenessProbe
	}

	if cr.Spec.ServerService.ReadinessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = cr.Spec.ServerService.ReadinessProbe
	}

	if cr.Spec.ServerService.NodeSelector != nil {
		if len(cr.Spec.ServerService.NodeSelector) > 0 {
			deployment.Spec.Template.Spec.NodeSelector = cr.Spec.ServerService.NodeSelector
		}
	}

	if cr.Spec.ServerService.Affinity != nil {
		deployment.Spec.Template.Spec.Affinity = cr.Spec.ServerService.Affinity
	}

	if cr.Spec.ServerService.Tolerations != nil {
		if len(cr.Spec.ServerService.Tolerations) > 0 {
			deployment.Spec.Template.Spec.Tolerations = cr.Spec.ServerService.Tolerations
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

	return deployment
}

func (sr *AquaServerHelper) getEnvVars(cr *operatorv1alpha1.AquaServer) []corev1.EnvVar {
	envsHelper := common.NewAquaEnvsHelper(cr.Spec.Infrastructure, cr.Spec.Common, cr.Spec.ExternalDb, cr.Name)
	result, _ := envsHelper.GetDbEnvVars()

	if cr.Spec.Common.AquaLicense != nil {
		result = append(result, corev1.EnvVar{
			Name: "LICENSE_TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cr.Spec.Common.AquaLicense.Name,
					},
					Key: cr.Spec.Common.AquaLicense.Key,
				},
			},
		})
	}

	if cr.Spec.Common.AdminPassword != nil {
		result = append(result, corev1.EnvVar{
			Name: "ADMIN_PASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: cr.Spec.Common.AdminPassword.Name,
					},
					Key: cr.Spec.Common.AdminPassword.Key,
				},
			},
		})
	}

	if cr.Spec.Common.CyberCenterAddress != consts.CyberCenterAddress {
		result = append(result, corev1.EnvVar{
			Name:  "CYBERCENTER_ADDR",
			Value: cr.Spec.Common.CyberCenterAddress,
		})
	}

	if cr.Spec.Common.ClusterMode {
		result = append(result, corev1.EnvVar{
			Name:  "CLUSTER_MODE",
			Value: "enable",
		})
	}

	result = append(result, corev1.EnvVar{
		Name:  "AQUA_DOCKERLESS_SCANNING",
		Value: "1",
	})

	result = append(result, corev1.EnvVar{
		Name:  "AQUA_CONSOLE_RAW_SCAN_RESULTS_STORAGE_SIZE",
		Value: fmt.Sprintf("%d", cr.Spec.Common.ServerDiskSize),
	})

	if cr.Spec.Enforcer != nil {
		enforcerEnvs := []corev1.EnvVar{
			{
				Name:  "BATCH_INSTALL_GATEWAY",
				Value: cr.Spec.Enforcer.Gateway,
			},
			{
				Name:  "BATCH_INSTALL_NAME",
				Value: cr.Spec.Enforcer.Name,
			},
			{
				Name: "BATCH_INSTALL_TOKEN",
				ValueFrom: &corev1.EnvVarSource{
					SecretKeyRef: &corev1.SecretKeySelector{
						LocalObjectReference: corev1.LocalObjectReference{
							Name: fmt.Sprintf("%s-enforcer-token", cr.Name),
						},
						Key: "token",
					},
				},
			},
		}

		if cr.Spec.Enforcer.EnforceMode {
			enforcerEnvs = append(enforcerEnvs, corev1.EnvVar{
				Name:  "BATCH_INSTALL_ENFORCE_MODE",
				Value: "true",
			})
		}

		orcType := "Kubernetes"
		if strings.ToLower(cr.Spec.Infrastructure.Platform) == "openshift" || strings.ToLower(cr.Spec.Infrastructure.Platform) == "pks" {
			orcType = strings.ToLower(cr.Spec.Infrastructure.Platform)
		}

		enforcerEnvs = append(enforcerEnvs, corev1.EnvVar{
			Name:  "BATCH_INSTALL_ORCHESTRATOR",
			Value: orcType,
		})

		result = append(result, enforcerEnvs...)
	}

	return result
}

func (sr *AquaServerHelper) newService(cr *operatorv1alpha1.AquaServer) *corev1.Service {
	selectors := map[string]string{
		"app": fmt.Sprintf("%s-server", cr.Name),
	}

	ports := []corev1.ServicePort{
		{
			Port:       8080,
			TargetPort: intstr.FromInt(8080),
			Name:       "aqua-web",
		},
		{
			Port:       443,
			TargetPort: intstr.FromInt(8443),
			Name:       "aqua-web-ssl",
		},
	}

	service := services.CreateService(cr.Name,
		cr.Namespace,
		fmt.Sprintf(consts.ServerServiceName, cr.Name),
		fmt.Sprintf("%s-server", cr.Name),
		"Service for aqua server deployment",
		cr.Spec.ServerService.ServiceType,
		selectors,
		ports)

	return service
}
