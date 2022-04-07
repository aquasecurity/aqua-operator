package aquascanner

import (
	"fmt"
	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
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

func (as *AquaScannerHelper) CreateConfigMap(cr *operatorv1alpha1.AquaScanner) *corev1.ConfigMap {

	labels := map[string]string{
		"app":                "aqua-scanner-config",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}

	annotations := map[string]string{
		"description": "Deploy Aqua aqua-csp-scanner ConfigMap",
	}

	data := map[string]string{
		"AQUA_SERVER": cr.Spec.Login.Host,
	}

	configMap := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        consts.ScannerConfigMapName,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: data,
	}
	return configMap
}

func (as *AquaScannerHelper) CreateTokenSecret(cr *operatorv1alpha1.AquaScanner) *corev1.Secret {
	labels := map[string]string{
		"app":                cr.Name + "-requirments",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Aqua Scanner username and password",
	}
	token := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        consts.ScannerSecretName,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"AQUA_SCANNER_USERNAME": []byte(cr.Spec.Login.Username),
			"AQUA_SCANNER_PASSWORD": []byte(cr.Spec.Login.Password),
		},
	}

	return token
}

func (as *AquaScannerHelper) newDeployment(cr *operatorv1alpha1.AquaScanner) *appsv1.Deployment {
	pullPolicy, registry, repository, tag := extra.GetImageData("scanner", cr.Spec.Infrastructure.Version, cr.Spec.ScannerService.ImageData, cr.Spec.Common.AllowAnyVersion)

	image := os.Getenv("RELATED_IMAGE_SCANNER")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                cr.Name + "-scanner",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"aqua.component":     "scanner",
	}

	annotations := map[string]string{
		"description": "Deploy the aqua scanner",
	}

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
							Env: []corev1.EnvVar{
								{
									Name: "AQUA_SCANNER_LOGICAL_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
							},
							EnvFrom: []corev1.EnvFromSource{
								{
									SecretRef: &corev1.SecretEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: consts.ScannerSecretName,
										},
									},
								},
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: consts.ScannerConfigMapName,
										},
									},
								},
							},
							Args: []string{
								"-c",
								"/opt/aquasec/scannercli daemon --user ${AQUA_SCANNER_USERNAME} --password ${AQUA_SCANNER_PASSWORD} --host ${AQUA_SERVER}",
							},
							Command: []string{
								"/bin/sh",
							},
							Ports: []corev1.ContainerPort{
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 8080,
								},
							},
						},
					},
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

	if cr.Spec.ScannerService.VolumeMounts != nil {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, cr.Spec.ScannerService.VolumeMounts...)
	}

	if cr.Spec.ScannerService.Volumes != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, cr.Spec.ScannerService.Volumes...)
	}

	if cr.Spec.Login.Insecure {
		deployment.Spec.Template.Spec.Containers[0].Args = append(deployment.Spec.Template.Spec.Containers[0].Args, "--no-verify")
	}

	return deployment
}
