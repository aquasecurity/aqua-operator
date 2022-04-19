package aquaserver

import (
	"fmt"
	routev1 "github.com/openshift/api/route/v1"
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

func (sr *AquaServerHelper) CreateConfigMap(cr *operatorv1alpha1.AquaServer) *corev1.ConfigMap {

	dbuser := "postgres"
	dbhost := fmt.Sprintf(consts.DbDeployName, cr.Name)
	dbport := 5432

	if cr.Spec.ExternalDb != nil {
		dbuser = cr.Spec.ExternalDb.Username
		dbhost = cr.Spec.ExternalDb.Host
		dbport = int(cr.Spec.ExternalDb.Port)
	}

	dbAuditUser := dbuser
	dbAuditHost := dbhost
	dbAuditPort := dbport

	if cr.Spec.Common.SplitDB {
		dbAuditHost = cr.Spec.AuditDB.Data.Host
		dbAuditUser = cr.Spec.AuditDB.Data.Username
		dbAuditPort = int(cr.Spec.AuditDB.Data.Port)
	}

	labels := map[string]string{
		"app":                "aqua-csp-server-config",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua aqua-csp-server-config ConfigMap",
	}

	data := map[string]string{
		//db
		"SCALOCK_DBUSER":       dbuser,
		"SCALOCK_DBNAME":       "scalock",
		"SCALOCK_DBHOST":       dbhost,
		"SCALOCK_DBPORT":       fmt.Sprintf("%d", dbport),
		"SCALOCK_AUDIT_DBUSER": dbAuditUser,
		"SCALOCK_AUDIT_DBNAME": "slk_audit",
		"SCALOCK_AUDIT_DBHOST": dbAuditHost,
		"SCALOCK_AUDIT_DBPORT": fmt.Sprintf("%d", dbAuditPort),
		"SCALOCK_DBSSL":        "require",
		"SCALOCK_AUDIT_DBSSL":  "require",
		//	gw
		"HEALTH_MONITOR":              "0.0.0.0:8082",
		"AQUA_CONSOLE_SECURE_ADDRESS": fmt.Sprintf("%s:443", fmt.Sprintf(consts.ServerServiceName, cr.Name)),
		"SCALOCK_GATEWAY_PUBLIC_IP":   fmt.Sprintf(consts.GatewayServiceName, cr.Name),
		"AQUA_GRPC_MODE":              "1",
	}

	if cr.Spec.Common.ActiveActive {
		data["AQUA_PUBSUB_DBNAME"] = "aqua_pubsub"
		data["AQUA_PUBSUB_DBHOST"] = dbhost
		data["AQUA_PUBSUB_DBPORT"] = fmt.Sprintf("%d", dbport)
		data["AQUA_PUBSUB_DBUSER"] = dbuser
	}

	if cr.Spec.Mtls {
		data["AQUA_PRIVATE_KEY"] = "/opt/aquasec/ssl/key.pem"
		data["AQUA_PUBLIC_KEY"] = "/opt/aquasec/ssl/cert.pem"
		data["AQUA_ROOT_CA"] = "/opt/aquasec/ssl/ca.pem"
		data["AQUA_VERIFY_ENFORCER"] = "1"
	}

	orcType := "Kubernetes"
	if strings.ToLower(cr.Spec.Infrastructure.Platform) == "openshift" || strings.ToLower(cr.Spec.Infrastructure.Platform) == "pks" {
		orcType = strings.ToLower(cr.Spec.Infrastructure.Platform)
	}

	data["BATCH_INSTALL_ORCHESTRATOR"] = orcType

	if cr.Spec.Enforcer != nil {
		data["BATCH_INSTALL_GATEWAY"] = cr.Spec.Enforcer.Gateway
		data["BATCH_INSTALL_NAME"] = cr.Spec.Enforcer.Name
		data["BATCH_INSTALL_TOKEN"] = fmt.Sprintf("%s-enforcer-token", cr.Name)
		data["BATCH_INSTALL_ORCHESTRATOR"] = orcType

		if cr.Spec.Enforcer.EnforceMode {
			data["BATCH_INSTALL_ENFORCE_MODE"] = "true"
		}
	}

	configMap := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        consts.ServerConfigMapName,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: data,
	}

	return configMap
}

func (sr *AquaServerHelper) newDeployment(cr *operatorv1alpha1.AquaServer) *appsv1.Deployment {
	pullPolicy, registry, repository, tag := extra.GetImageData("console", cr.Spec.Infrastructure.Version, cr.Spec.ServerService.ImageData, cr.Spec.Common.AllowAnyVersion)

	image := os.Getenv("RELATED_IMAGE_SERVER")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                cr.Name + "-server",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
		"type":               "aqua-server",
		"aqua.component":     "server",
	}
	annotations := map[string]string{
		"description":       "Deploy the aqua console server",
		"ConfigMapChecksum": cr.Spec.ConfigMapChecksum,
	}

	envVars := sr.getEnvVars(cr)
	privileged := true

	if cr.Spec.RunAsNonRoot {
		privileged = false
	}

	envFromSource := []corev1.EnvFromSource{
		{
			ConfigMapRef: &corev1.ConfigMapEnvSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: consts.ServerConfigMapName,
				},
			},
		},
	}

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
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							Ports: []corev1.ContainerPort{
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 8080,
								},
								{
									Protocol:      corev1.ProtocolTCP,
									ContainerPort: 8443,
								},
							},
							Env:     envVars,
							EnvFrom: envFromSource,
							LivenessProbe: &corev1.Probe{
								FailureThreshold: 3,
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.IntOrString{
											Type:   intstr.Int,
											IntVal: int32(8080),
										},
										Scheme: "HTTP",
									},
								},
								InitialDelaySeconds: 60,
								PeriodSeconds:       30,
								SuccessThreshold:    1,
								TimeoutSeconds:      1,
							},
							ReadinessProbe: &corev1.Probe{
								FailureThreshold: 3,
								Handler: corev1.Handler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/",
										Port: intstr.IntOrString{
											Type:   intstr.Int,
											IntVal: int32(8080),
										},
										Scheme: "HTTP",
									},
								},
								InitialDelaySeconds: 60,
								PeriodSeconds:       30,
								SuccessThreshold:    1,
								TimeoutSeconds:      1,
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

	if cr.Spec.ServerService.VolumeMounts != nil {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, cr.Spec.ServerService.VolumeMounts...)
	}

	if cr.Spec.ServerService.Volumes != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, cr.Spec.ServerService.Volumes...)
	}

	if cr.Spec.Mtls {
		mtlsAquaWebVolumeMount := []corev1.VolumeMount{
			{
				Name:      "aqua-grpc-web",
				MountPath: "/opt/aquasec/ssl",
				ReadOnly:  true,
			},
		}

		secretVolumeSource := corev1.SecretVolumeSource{
			SecretName: "aqua-grpc-web",
			Items: []corev1.KeyToPath{
				{
					Key:  "aqua_web.crt",
					Path: "cert.pem",
				},
				{
					Key:  "aqua_web.key",
					Path: "key.pem",
				},
				{
					Key:  "rootCA.crt",
					Path: "ca.pem",
				},
			},
		}

		mtlsAquaWebVolume := []corev1.Volume{
			{
				Name: "aqua-grpc-web",
				VolumeSource: corev1.VolumeSource{
					Secret: &secretVolumeSource,
				},
			},
		}
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, mtlsAquaWebVolumeMount...)
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, mtlsAquaWebVolume...)
	}

	return deployment
}

func (sr *AquaServerHelper) getEnvVars(cr *operatorv1alpha1.AquaServer) []corev1.EnvVar {
	envsHelper := common.NewAquaEnvsHelper(cr.Spec.Infrastructure, cr.Spec.Common, cr.Spec.ExternalDb, cr.Name, cr.Spec.AuditDB)
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

	result = append(result, corev1.EnvVar{
		Name:  "AQUA_DOCKERLESS_SCANNING",
		Value: "1",
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

func (sr *AquaServerHelper) newRoute(cr *operatorv1alpha1.AquaServer) *routev1.Route {
	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cr.Name,
			Namespace: cr.Namespace,
		},
		Spec: routev1.RouteSpec{
			TLS: &routev1.TLSConfig{
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
				Termination:                   routev1.TLSTerminationEdge,
			},
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: fmt.Sprintf(consts.ServerServiceName, cr.Name),
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromInt(8080),
			},
		},
	}
}
