package aquadatabase

import (
	"fmt"
	"os"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/services"

	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type AquaDatabaseParameters struct {
	Database *operatorv1alpha1.AquaDatabase
}

type AquaDatabaseHelper struct {
	Parameters AquaDatabaseParameters
}

func newAquaDatabaseHelper(cr *operatorv1alpha1.AquaDatabase) *AquaDatabaseHelper {
	params := AquaDatabaseParameters{
		Database: cr,
	}

	return &AquaDatabaseHelper{
		Parameters: params,
	}
}

func (db *AquaDatabaseHelper) newDeployment(cr *operatorv1alpha1.AquaDatabase) *appsv1.Deployment {
	pullPolicy, registry, repository, tag := extra.GetImageData("database", cr.Spec.Infrastructure.Version, cr.Spec.DbService.ImageData)

	image := os.Getenv("RELATED_IMAGE_DATABASE")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                cr.Name + "-database",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy the aqua database server",
	}
	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf(consts.DbDeployName, cr.Name),
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: extra.Int32Ptr(int32(cr.Spec.DbService.Replicas)),
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
							Name:            "aqua-db",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "postgres-database",
									MountPath: "/var/lib/postgresql/data",
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 5432,
								},
							},
							Env: []corev1.EnvVar{
								{
									Name:  "PGDATA",
									Value: "/var/lib/postgresql/data/db-files",
								},
								{
									Name: "POSTGRES_PASSWORD",
									ValueFrom: &corev1.EnvVarSource{
										SecretKeyRef: &corev1.SecretKeySelector{
											LocalObjectReference: corev1.LocalObjectReference{
												Name: db.Parameters.Database.Spec.Common.DatabaseSecret.Name,
											},
											Key: db.Parameters.Database.Spec.Common.DatabaseSecret.Key,
										},
									},
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "postgres-database",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: fmt.Sprintf(consts.DbPvcName, cr.Name),
								},
							},
						},
					},
				},
			},
		},
	}

	if cr.Spec.DbService.Resources != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *cr.Spec.DbService.Resources
	}

	if cr.Spec.DbService.LivenessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].LivenessProbe = cr.Spec.DbService.LivenessProbe
	}

	if cr.Spec.DbService.ReadinessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = cr.Spec.DbService.ReadinessProbe
	}

	if cr.Spec.DbService.NodeSelector != nil {
		if len(cr.Spec.DbService.NodeSelector) > 0 {
			deployment.Spec.Template.Spec.NodeSelector = cr.Spec.DbService.NodeSelector
		}
	}

	if cr.Spec.DbService.Affinity != nil {
		deployment.Spec.Template.Spec.Affinity = cr.Spec.DbService.Affinity
	}

	if cr.Spec.DbService.Tolerations != nil {
		if len(cr.Spec.DbService.Tolerations) > 0 {
			deployment.Spec.Template.Spec.Tolerations = cr.Spec.DbService.Tolerations
		}
	}

	if len(cr.Spec.Common.ImagePullSecret) != 0 {
		deployment.Spec.Template.Spec.ImagePullSecrets = []corev1.LocalObjectReference{
			corev1.LocalObjectReference{
				Name: cr.Spec.Common.ImagePullSecret,
			},
		}
	}

	return deployment
}

func (db *AquaDatabaseHelper) newService(cr *operatorv1alpha1.AquaDatabase) *corev1.Service {
	selectors := map[string]string{
		"app": cr.Name + "-database",
	}

	ports := []corev1.ServicePort{
		{
			Port: 5432,
		},
	}

	service := services.CreateService(cr.Name,
		cr.Namespace,
		fmt.Sprintf(consts.DbServiceName, cr.Name),
		fmt.Sprintf("%s-database", cr.Name),
		"Service for aqua database deployment",
		cr.Spec.DbService.ServiceType,
		selectors,
		ports)

	return service
}
