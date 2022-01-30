package aquakubeenforcer

import (
	"fmt"
	aquasecurity1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/aquasecurity/v1alpha1"
	"os"

	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	WebhookTimeout int32 = 5
)

// EnforcerParameters :
type KubeEnforcerParameters struct {
	KubeEnforcer *operatorv1alpha1.AquaKubeEnforcer
}

// AquaEnforcerHelper :
type AquaKubeEnforcerHelper struct {
	Parameters KubeEnforcerParameters
}

func newAquaKubeEnforcerHelper(cr *operatorv1alpha1.AquaKubeEnforcer) *AquaKubeEnforcerHelper {
	params := KubeEnforcerParameters{
		KubeEnforcer: cr,
	}

	return &AquaKubeEnforcerHelper{
		Parameters: params,
	}
}

func (enf *AquaKubeEnforcerHelper) CreateKubeEnforcerClusterRole(name string, namespace string) *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"pods",
				"nodes",
				"namespaces",
				"deployments",
				"statefulsets",
				"jobs",
				"cronjobs",
				"daemonsets",
				"replicasets",
				"replicationcontrollers",
				"clusterroles",
				"clusterrolebindings",
				"componentstatuses",
				"services",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"secrets",
			},
			Verbs: []string{
				"get", "list", "watch", "update", "create",
			},
		},
		{
			APIGroups: []string{
				"aquasecurity.github.io",
			},
			Resources: []string{
				"configauditreports",
				"clusterconfigauditreports",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"configmaps",
			},
			Verbs: []string{
				"get", "list", "watch", "update", "create",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"roles",
				"rolebindings",
				"clusterroles",
				"clusterrolebindings",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"customresourcedefinitions",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
	}

	crole := rbac.CreateClusterRole(name, namespace, "aqua-kube-enforcer", fmt.Sprintf("%s-rbac", "aqua-ke"), "Deploy Aqua Discovery Cluster Role", rules)

	return crole
}

// CreateServiceAccount Create new service account
func (enf *AquaKubeEnforcerHelper) CreateKEServiceAccount(cr, namespace, app, name string) *corev1.ServiceAccount {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Service account for aqua kube-enforcer",
	}
	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}

	return sa
}

func (enf *AquaKubeEnforcerHelper) CreateClusterRoleBinding(cr, namespace, name, app, sa, clusterrole string) *rbacv1.ClusterRoleBinding {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Cluster Role Binding",
	}
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterrole,
		},
	}

	return crb
}

func (enf *AquaKubeEnforcerHelper) CreateKubeEnforcerRole(cr, namespace, name, app string) *rbacv1.Role {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"pods/log",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"jobs",
			},
			Verbs: []string{
				"create", "delete",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"pods",
			},
			Verbs: []string{
				"create", "delete",
			},
		},
	}
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description":              "KubeEnforcer Role",
		"openshift.io/description": "A user who can search and scan images from an OpenShift integrated registry.",
	}
	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Rules: rules,
	}

	return role
}

func (enf *AquaKubeEnforcerHelper) CreateRoleBinding(cr, namespace, name, app, sa, role string) *rbacv1.RoleBinding {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Cluster Role Binding",
	}
	rb := &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     role,
		},
	}

	return rb
}

func (enf *AquaKubeEnforcerHelper) CreateValidatingWebhook(cr, namespace, name, app, keService string, caBundle []byte) *admissionv1.ValidatingWebhookConfiguration {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua ValidatingWebhookConfiguration",
	}
	rules := []admissionv1.RuleWithOperations{
		{
			Operations: []admissionv1.OperationType{
				admissionv1.Create,
				admissionv1.Update,
			},
			Rule: admissionv1.Rule{
				APIGroups: []string{
					"*",
				},
				APIVersions: []string{
					"*",
				},
				Resources: []string{
					"pods",
					"deployments",
					"replicasets",
					"replicationcontrollers",
					"statefulsets",
					"daemonsets",
					"jobs",
					"cronjobs",
					"configmaps",
					"services",
					"roles",
					"rolebindings",
					"clusterroles",
					"clusterrolebindings",
					"customresourcedefinitions",
				},
			},
		},
	}
	servicePort := int32(443)
	sideEffect := admissionv1.SideEffectClassNone
	failurePolicy := admissionv1.Ignore
	validWebhook := &admissionv1.ValidatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Webhooks: []admissionv1.ValidatingWebhook{
			{
				Name:  "imageassurance.aquasec.com",
				Rules: rules,
				ClientConfig: admissionv1.WebhookClientConfig{
					CABundle: caBundle,
					Service: &admissionv1.ServiceReference{
						Namespace: namespace,
						Name:      keService,
						Port:      &servicePort,
					},
				},
				TimeoutSeconds:          extra.Int32Ptr(WebhookTimeout),
				SideEffects:             &sideEffect,
				AdmissionReviewVersions: []string{"v1beta1"},
				FailurePolicy:           &failurePolicy,
			},
		},
	}

	return validWebhook
}

func (enf *AquaKubeEnforcerHelper) CreateMutatingWebhook(cr, namespace, name, app, keService string, caBundle []byte) *admissionv1.MutatingWebhookConfiguration {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua MutatingWebhookConfiguration",
	}
	rules := []admissionv1.RuleWithOperations{
		{
			Operations: []admissionv1.OperationType{
				admissionv1.Create,
				admissionv1.Update,
			},
			Rule: admissionv1.Rule{
				APIGroups: []string{
					"*",
				},
				APIVersions: []string{
					"v1",
				},
				Resources: []string{
					"pods",
				},
			},
		},
	}
	mutatePath := "/mutate"
	servicePort := int32(443)
	sideEffect := admissionv1.SideEffectClassNone
	failurePolicy := admissionv1.Ignore
	mutateWebhook := &admissionv1.MutatingWebhookConfiguration{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "MutatingWebhookConfiguration",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Webhooks: []admissionv1.MutatingWebhook{
			{
				Name:  "microenforcer.aquasec.com",
				Rules: rules,
				ClientConfig: admissionv1.WebhookClientConfig{
					CABundle: caBundle,
					Service: &admissionv1.ServiceReference{
						Namespace: namespace,
						Name:      keService,
						Path:      &mutatePath,
						Port:      &servicePort,
					},
				},
				TimeoutSeconds:          extra.Int32Ptr(WebhookTimeout),
				SideEffects:             &sideEffect,
				AdmissionReviewVersions: []string{"v1beta1"},
				FailurePolicy:           &failurePolicy,
			},
		},
	}

	return mutateWebhook
}

func (enf *AquaKubeEnforcerHelper) CreateKEConfigMap(cr, namespace, name, app, gwAddress, clusterName string, starboard bool) *corev1.ConfigMap {
	configMapData := map[string]string{
		"AQUA_ENABLE_CACHE":            "yes",
		"AQUA_CACHE_EXPIRATION_PERIOD": "60",
		"TLS_SERVER_CERT_FILEPATH":     "/certs/aqua_ke.crt",
		"TLS_SERVER_KEY_FILEPATH":      "/certs/aqua_ke.key",
		"AQUA_GATEWAY_SECURE_ADDRESS":  gwAddress,
		"AQUA_TLS_PORT":                "8443",
		"CLUSTER_NAME":                 clusterName,
	}
	if starboard {
		configMapData["AQUA_KAP_ADD_ALL_CONTROL"] = "true"
		configMapData["AQUA_WATCH_CONFIG_AUDIT_REPORT"] = "true"
	}

	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua KubeEnfocer ConfigMap",
	}
	configMap := &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: configMapData,
	}

	return configMap
}

func (enf *AquaKubeEnforcerHelper) CreateKETokenSecret(cr, namespace, name, app, token string) *corev1.Secret {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua KubeEnfocer token secret",
	}
	tokenSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: map[string][]byte{
			"token": []byte(token),
		},
	}

	return tokenSecret
}

func (enf *AquaKubeEnforcerHelper) CreateKESSLSecret(cr, namespace, name, app string, secretKey, secretCert []byte) *corev1.Secret {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Kube Enforcer SSL certificates to communicate with Kube API server",
	}
	sslSecret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Data: map[string][]byte{
			"aqua_ke.key": secretKey,
			"aqua_ke.crt": secretCert,
		},
	}

	return sslSecret
}

func (enf *AquaKubeEnforcerHelper) CreateKEService(cr, namespace, name, app string) *corev1.Service {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Kube Enforcer Service",
	}
	selectors := map[string]string{
		"app": "aqua-kube-enforcer",
	}

	ports := []corev1.ServicePort{
		{
			Port:       443,
			TargetPort: intstr.FromInt(8443),
		},
	}
	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceType(enf.Parameters.KubeEnforcer.Spec.KubeEnforcerService.ServiceType),
			Selector: selectors,
			Ports:    ports,
		},
	}

	return service
}

func (enf *AquaKubeEnforcerHelper) CreateKEDeployment(cr *operatorv1alpha1.AquaKubeEnforcer, name, app, registry, tag, pullPolicy, repository string) *appsv1.Deployment {

	image := os.Getenv("RELATED_IMAGE_KUBE_ENFORCER")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Kube Enforcer Deployment",
	}

	envVars := enf.getEnvVars(cr)
	selectors := map[string]string{
		"app": "aqua-kube-enforcer",
	}

	ports := []corev1.ContainerPort{
		{
			ContainerPort: 8443,
			Protocol:      corev1.ProtocolTCP,
		},
		{
			ContainerPort: 8080,
			Protocol:      corev1.ProtocolTCP,
		},
	}
	runAsUser := int64(11431)
	runAsGroup := int64(11433)
	fsGroup := int64(11433)

	deployment := &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: selectors,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: selectors,
				},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:  &runAsUser,
						RunAsGroup: &runAsGroup,
						FSGroup:    &fsGroup,
					},
					ServiceAccountName: cr.Spec.Infrastructure.ServiceAccount,
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: cr.Spec.Config.ImagePullSecret,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "kube-enforcer-ssl",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "kube-enforcer-ssl",
									Items: []corev1.KeyToPath{
										{
											Key:  "aqua_ke.crt",
											Path: "aqua_ke.crt",
										},
										{
											Key:  "aqua_ke.key",
											Path: "aqua_ke.key",
										},
									},
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "kube-enforcer",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							LivenessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(8080),
									},
								},
								InitialDelaySeconds: 60,
								PeriodSeconds:       30,
							},
							ReadinessProbe: &corev1.Probe{
								Handler: corev1.Handler{
									TCPSocket: &corev1.TCPSocketAction{
										Port: intstr.FromInt(8080),
									},
								},
								InitialDelaySeconds: 60,
								PeriodSeconds:       30,
							},
							Ports: ports,
							Env:   envVars,
							EnvFrom: []corev1.EnvFromSource{
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "aqua-csp-kube-enforcer",
										},
									},
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "kube-enforcer-ssl",
									MountPath: "/certs",
								},
							},
						},
					},
				},
			},
		},
	}

	kubeEnforcerExtraData := enf.Parameters.KubeEnforcer.Spec.KubeEnforcerService

	if kubeEnforcerExtraData.Resources != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *kubeEnforcerExtraData.Resources
	}

	if kubeEnforcerExtraData.LivenessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].LivenessProbe = kubeEnforcerExtraData.LivenessProbe
	}

	if kubeEnforcerExtraData.ReadinessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = kubeEnforcerExtraData.ReadinessProbe
	}

	if kubeEnforcerExtraData.VolumeMounts != nil {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, kubeEnforcerExtraData.VolumeMounts...)
	}

	if kubeEnforcerExtraData.Volumes != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, kubeEnforcerExtraData.Volumes...)
	}

	if enf.Parameters.KubeEnforcer.Spec.Envs != nil {
		deployment.Spec.Template.Spec.Containers[0].Env = append(deployment.Spec.Template.Spec.Containers[0].Env, enf.Parameters.KubeEnforcer.Spec.Envs...)
	}

	if cr.Spec.Mtls {
		mtlsAquaKubeEnforcerVolumeMount := []corev1.VolumeMount{
			{
				Name:      "aqua-grpc-kube-enforcer",
				MountPath: "/opt/aquasec/ssl",
			},
		}

		secretVolumeSource := corev1.SecretVolumeSource{
			SecretName: "aqua-grpc-kube-enforcer",
		}

		mtlsAquaKubeEnforcerVolume := []corev1.Volume{
			{
				Name: "aqua-grpc-kube-enforcer",
				VolumeSource: corev1.VolumeSource{
					Secret: &secretVolumeSource,
				},
			},
		}
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, mtlsAquaKubeEnforcerVolumeMount...)
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, mtlsAquaKubeEnforcerVolume...)
	}

	return deployment
}

func (ebf *AquaKubeEnforcerHelper) getEnvVars(cr *operatorv1alpha1.AquaKubeEnforcer) []corev1.EnvVar {
	result := []corev1.EnvVar{
		{
			Name: "AQUA_TOKEN",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: "aqua-kube-enforcer-token",
					},
					Key: "token",
				},
			},
		},
	}

	if cr.Spec.Mtls {
		mtlsKubeEnforcerEnv := []corev1.EnvVar{
			{
				Name:  "AQUA_PRIVATE_KEY",
				Value: "/opt/aquasec/ssl/aqua_kube-enforcer.key",
			},
			{
				Name:  "AQUA_PUBLIC_KEY",
				Value: "/opt/aquasec/ssl/aqua_kube-enforcer.crt",
			},
			{
				Name:  "AQUA_ROOT_CA",
				Value: "/opt/aquasec/ssl/rootCA.crt",
			},
			{
				Name:  "AQUA_TLS_VERIFY",
				Value: "true",
			},
		}
		result = append(result, mtlsKubeEnforcerEnv...)
	}

	return result
}

// Starboard functions

func (ebf *AquaKubeEnforcerHelper) newStarboard(cr *operatorv1alpha1.AquaKubeEnforcer) *aquasecurity1alpha1.AquaStarboard {
	labels := map[string]string{
		"app":                cr.Name + "-kube-enforcer",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Starboard",
	}

	aquasb := &aquasecurity1alpha1.AquaStarboard{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "aquasecurity.github.io/v1alpha1",
			Kind:       "AquaStarboard",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: aquasecurity1alpha1.AquaStarboardSpec{
			Infrastructure:                cr.Spec.DeployStarboard.Infrastructure,
			AllowAnyVersion:               cr.Spec.DeployStarboard.AllowAnyVersion,
			StarboardService:              cr.Spec.DeployStarboard.StarboardService,
			Config:                        cr.Spec.DeployStarboard.Config,
			RegistryData:                  cr.Spec.DeployStarboard.RegistryData,
			ImageData:                     cr.Spec.DeployStarboard.ImageData,
			Envs:                          cr.Spec.DeployStarboard.Envs,
			LogDevMode:                    cr.Spec.DeployStarboard.LogDevMode,
			ConcurrentScanJobsLimit:       cr.Spec.DeployStarboard.ConcurrentScanJobsLimit,
			ScanJobRetryAfter:             cr.Spec.DeployStarboard.ScanJobRetryAfter,
			MetricsBindAddress:            cr.Spec.DeployStarboard.MetricsBindAddress,
			HealthProbeBindAddress:        cr.Spec.DeployStarboard.HealthProbeBindAddress,
			CisKubernetesBenchmarkEnabled: cr.Spec.DeployStarboard.CisKubernetesBenchmarkEnabled,
			VulnerabilityScannerEnabled:   cr.Spec.DeployStarboard.VulnerabilityScannerEnabled,
			BatchDeleteLimit:              cr.Spec.DeployStarboard.BatchDeleteLimit,
			BatchDeleteDelay:              cr.Spec.DeployStarboard.BatchDeleteLimit,
		},
	}
	return aquasb
}
