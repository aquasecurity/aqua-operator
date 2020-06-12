package aquascanner

import (
	"fmt"
	"os"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ScannerParameters struct {
	Scanner *operatorv1alpha1.AquaScanner
}

type AquaScannerHelper struct {
	Parameters ScannerParameters
}

func newAquaScannerHelper(cr *operatorv1alpha1.AquaScanner) *AquaScannerHelper {
	params := ScannerParameters{
		Scanner: cr,
	}

	return &AquaScannerHelper{
		Parameters: params,
	}
}

func (as *AquaScannerHelper) newDeployment(cr *operatorv1alpha1.AquaScanner) *appsv1.Deployment {
	pullPolicy, registry, repository, tag := extra.GetImageData("scanner", cr.Spec.Infrastructure.Version, cr.Spec.ScannerService.ImageData)

	image := os.Getenv("RELATED_IMAGE_SCANNER")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                cr.Name + "-scanner",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}

	annotations := map[string]string{
		"description": "Deploy the aqua scanner",
	}

	privileged := true

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf(consts.ScannerDeployName, cr.Name),
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: extra.Int32Ptr(int32(cr.Spec.ScannerService.Replicas)),
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Name:   fmt.Sprintf(consts.ScannerDeployName, cr.Name),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: cr.Spec.Infrastructure.ServiceAccount,
					Containers: []corev1.Container{
						{
							Name:            "aqua-scanner",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							Args: []string{
								"daemon",
								"--user",
								cr.Spec.Login.Username,
								"--password",
								cr.Spec.Login.Password,
								"--host",
								cr.Spec.Login.Host,
							},
							Ports: []corev1.ContainerPort{
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 8080,
								},
							},
							/*VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "docker-socket-mount",
									MountPath: "/var/run/docker.sock",
								},
							},*/
						},
					},
					/*Volumes: []corev1.Volume{
						{
							Name: "docker-socket-mount",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run/docker.sock",
								},
							},
						},
					},*/
				},
			},
		},
	}

	if cr.Spec.ScannerService.Resources != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *cr.Spec.ScannerService.Resources
	}

	if cr.Spec.ScannerService.LivenessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].LivenessProbe = cr.Spec.ScannerService.LivenessProbe
	}

	if cr.Spec.ScannerService.ReadinessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = cr.Spec.ScannerService.ReadinessProbe
	}

	if cr.Spec.ScannerService.NodeSelector != nil {
		if len(cr.Spec.ScannerService.NodeSelector) > 0 {
			deployment.Spec.Template.Spec.NodeSelector = cr.Spec.ScannerService.NodeSelector
		}
	}

	if cr.Spec.ScannerService.Affinity != nil {
		deployment.Spec.Template.Spec.Affinity = cr.Spec.ScannerService.Affinity
	}

	if cr.Spec.ScannerService.Tolerations != nil {
		if len(cr.Spec.ScannerService.Tolerations) > 0 {
			deployment.Spec.Template.Spec.Tolerations = cr.Spec.ScannerService.Tolerations
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
