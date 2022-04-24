package aquadatabase

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/aqua-operator/pkg/consts"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/services"

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

func (db *AquaDatabaseHelper) newDeployment(cr *operatorv1alpha1.AquaDatabase, dbSecret *operatorv1alpha1.AquaSecret, deployName, pvcName, app string) *appsv1.Deployment {
	pullPolicy, registry, repository, tag := extra.GetImageData("database", cr.Spec.Infrastructure.Version, cr.Spec.DbService.ImageData, cr.Spec.Common.AllowAnyVersion)

	image := os.Getenv("RELATED_IMAGE_DATABASE")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"aqua.component":     "database",
	}
	annotations := map[string]string{
		"description": "Deploy the aqua database server",
	}

	passwordEnvVar := "POSTGRES_PASSWORD"
	mountPath := "/var/lib/postgresql/data"
	pgData := "/var/lib/postgresql/data/db-files"

	marketplace := extra.IsMarketPlace()
	privileged := true

	if cr.Spec.RunAsNonRoot {
		privileged = false
	}

	if marketplace {
		passwordEnvVar = "POSTGRESQL_ADMIN_PASSWORD"
		mountPath = "/var/lib/pgsql/data"
		pgData = "/var/lib/pgsql/data"
	}

	envVars := []corev1.EnvVar{
		{
			Name:  "PGDATA",
			Value: pgData,
		},
		{
			Name: passwordEnvVar,
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: dbSecret.Name,
					},
					Key: dbSecret.Key,
				},
			},
		},
	}

	volumesMount := []corev1.VolumeMount{
		{
			Name:      "postgres-database",
			MountPath: mountPath,
		},
	}

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        deployName,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: extra.Int32Ptr(int32(cr.Spec.DbService.Replicas)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app":                app,
					"deployedby":         "aqua-operator",
					"aquasecoperator_cr": cr.Name,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: cr.Spec.Infrastructure.ServiceAccount,
					Containers: []corev1.Container{
						{
							Name:            deployName,
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							VolumeMounts: volumesMount,
							Ports: []corev1.ContainerPort{
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 5432,
								},
							},
							Env: envVars,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "postgres-database",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: pvcName,
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

	fsGroupHelper := int64(11433)
	if marketplace {
		fsGroupHelper = int64(26)
		deployment.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{
			FSGroup: &fsGroupHelper,
		}
	}

	if cr.Spec.RunAsNonRoot &&
		strings.ToLower(cr.Spec.Infrastructure.Platform) == "openshift" {
		runAsUser := int64(70)
		runAsGroup := int64(70)
		deployment.Spec.Template.Spec.SecurityContext = &corev1.PodSecurityContext{
			RunAsUser:  &runAsUser,
			RunAsGroup: &runAsGroup,
			FSGroup:    &fsGroupHelper,
		}
		deployment.Spec.Template.Spec.InitContainers = []corev1.Container{
			{
				Name:            fmt.Sprintf("%s-init", deployName),
				Image:           image,
				ImagePullPolicy: corev1.PullPolicy(pullPolicy),
				Env:             envVars,
				VolumeMounts:    volumesMount,
				Command: []string{
					"sh",
					"-c",
					consts.DBInitContainerCommand,
				},
			},
		}
	}

	return deployment
}

func (db *AquaDatabaseHelper) newService(cr *operatorv1alpha1.AquaDatabase, name, app string, servicePort int32) *corev1.Service {
	selectors := map[string]string{
		"app": app,
	}

	ports := []corev1.ServicePort{
		{
			Port: servicePort,
		},
	}

	service := services.CreateService(cr.Name,
		cr.Namespace,
		name,
		fmt.Sprintf("%s-database", cr.Name),
		"Service for aqua database deployment",
		cr.Spec.DbService.ServiceType,
		selectors,
		ports)

	return service
}
