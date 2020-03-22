package aquaenforcer

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

// EnforcerParameters :
type EnforcerParameters struct {
	Privileged bool
	Enforcer   *operatorv1alpha1.AquaEnforcer
}

// AquaEnforcerHelper :
type AquaEnforcerHelper struct {
	Parameters EnforcerParameters
}

func newAquaEnforcerHelper(cr *operatorv1alpha1.AquaEnforcer) *AquaEnforcerHelper {
	params := EnforcerParameters{
		Privileged: true,
		Enforcer:   cr,
	}

	return &AquaEnforcerHelper{
		Parameters: params,
	}
}

// CreateTokenSecret : Create Enforcer Token Secret For The Enforcer connection to the aqua csp environment
func (enf *AquaEnforcerHelper) CreateTokenSecret(cr *operatorv1alpha1.AquaEnforcer) *corev1.Secret {
	labels := map[string]string{
		"app":                cr.Name + "-requirments",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Secret for aqua database password",
	}
	token := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf(consts.EnforcerTokenSecretName, cr.Name),
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			consts.EnforcerTokenSecretKey: []byte(cr.Spec.Token),
		},
	}

	return token
}

// CreateDaemonSet :
func (enf *AquaEnforcerHelper) CreateDaemonSet(cr *operatorv1alpha1.AquaEnforcer) *appsv1.DaemonSet {
	pullPolicy, registry, repository, tag := extra.GetImageData("enforcer", cr.Spec.Infrastructure.Version, cr.Spec.EnforcerService.ImageData)

	image := os.Getenv("RELATED_IMAGE_ENFORCER")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                cr.Name + "-requirments",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Secret for aqua database password",
	}
	ds := &appsv1.DaemonSet{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "DaemonSet",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf(consts.EnforcerDeamonsetName, cr.Name),
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Name:   fmt.Sprintf(consts.EnforcerDeamonsetName, cr.Name),
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: cr.Spec.Infrastructure.ServiceAccount,
					HostPID:            true,
					Containers: []corev1.Container{
						{
							Name:            "aqua-enforcer",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "var-run",
									MountPath: "/var/run",
								},
								{
									Name:      "dev",
									MountPath: "/dev",
								},
								{
									Name:      "sys",
									MountPath: "/host/sys",
									ReadOnly:  true,
								},
								{
									Name:      "proc",
									MountPath: "/host/proc",
									ReadOnly:  true,
								},
								{
									Name:      "etc",
									MountPath: "/host/etc",
									ReadOnly:  true,
								},
								{
									Name:      "aquasec",
									MountPath: "/host/opt/aquasec",
									ReadOnly:  true,
								},
								{
									Name:      "aquasec-tmp",
									MountPath: "/opt/aquasec/tmp",
								},
								{
									Name:      "aquasec-audit",
									MountPath: "/opt/aquasec/audit",
								},
								{
									Name:      "aquasec-data",
									MountPath: "/data",
								},
							},
							Env: []corev1.EnvVar{
								{
									Name: "AQUA_TOKEN",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: cr.Spec.Secret.Name,
											},
											Key: cr.Spec.Secret.Key,
										},
									},
								},
								{
									Name:  "AQUA_SERVER",
									Value: fmt.Sprintf("%s:%d", cr.Spec.Gateway.Host, cr.Spec.Gateway.Port),
								},
								{
									Name:  "AQUA_INSTALL_PATH",
									Value: "/var/lib/aquasec",
								},
								{
									Name:  "AQUA_GRPC_ONLY_MODE",
									Value: "true",
								},
								{
									Name:  "RESTART_CONTAINERS",
									Value: "no",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "var-run",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/run",
								},
							},
						},
						{
							Name: "dev",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/dev",
								},
							},
						},
						{
							Name: "sys",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/sys",
								},
							},
						},
						{
							Name: "proc",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/proc",
								},
							},
						},
						{
							Name: "etc",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/etc",
								},
							},
						},
						{
							Name: "aquasec",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/aquasec",
								},
							},
						},
						{
							Name: "aquasec-tmp",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/aquasec/tmp",
								},
							},
						},
						{
							Name: "aquasec-audit",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/aquasec/audit",
								},
							},
						},
						{
							Name: "aquasec-data",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/var/lib/aquasec/data",
								},
							},
						},
					},
				},
			},
		},
	}

	if cr.Spec.EnforcerService.Resources != nil {
		ds.Spec.Template.Spec.Containers[0].Resources = *cr.Spec.EnforcerService.Resources
	}

	if cr.Spec.EnforcerService.LivenessProbe != nil {
		ds.Spec.Template.Spec.Containers[0].LivenessProbe = cr.Spec.EnforcerService.LivenessProbe
	}

	if cr.Spec.EnforcerService.ReadinessProbe != nil {
		ds.Spec.Template.Spec.Containers[0].ReadinessProbe = cr.Spec.EnforcerService.ReadinessProbe
	}

	if cr.Spec.EnforcerService.NodeSelector != nil {
		if len(cr.Spec.EnforcerService.NodeSelector) > 0 {
			ds.Spec.Template.Spec.NodeSelector = cr.Spec.EnforcerService.NodeSelector
		}
	}

	if enf.Parameters.Privileged {
		ds.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			Privileged: &enf.Parameters.Privileged,
		}
	} else {
		ds.Spec.Template.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{
			Privileged: &enf.Parameters.Privileged,
			Capabilities: &corev1.Capabilities{
				Add: []corev1.Capability{
					"SYS_ADMIN",
					"NET_ADMIN",
					"NET_RAW",
					"SYS_PTRACE",
					"KILL",
					"MKNOD",
					"SETGID",
					"SETUID",
					"SYS_MODULE",
					"AUDIT_CONTROL",
					"SYSLOG",
					"SYS_CHROOT",
				},
			},
		}
	}

	if cr.Spec.Common != nil {
		if len(cr.Spec.Common.ImagePullSecret) != 0 {
			ds.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
				corev1.LocalObjectReference{
					Name: cr.Spec.Common.ImagePullSecret,
				},
			}
		}
	}

	return ds
}
