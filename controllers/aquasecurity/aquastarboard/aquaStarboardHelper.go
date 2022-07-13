package aquastarboard

import (
	"fmt"
	aquasecurityv1alpha1 "github.com/aquasecurity/aqua-operator/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	WebhookTimeout int32 = 5
)

// StarboardParameters :
type StarboardParameters struct {
	Starboard *aquasecurityv1alpha1.AquaStarboard
}

// AquaStarboardHelper :
type AquaStarboardHelper struct {
	Parameters StarboardParameters
}

func newAquaStarboardHelper(cr *aquasecurityv1alpha1.AquaStarboard) *AquaStarboardHelper {
	params := StarboardParameters{
		Starboard: cr,
	}

	return &AquaStarboardHelper{
		Parameters: params,
	}
}

func (enf *AquaStarboardHelper) CreateStarboardClusterRole(name string, namespace string) *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"pods", "pods/log", "replicationcontrollers", "services",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"nodes",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"configmaps", "secrets", "serviceaccounts", "resourcequotas", "limitranges",
			},
			Verbs: []string{
				"get", "list", "watch", "create", "update",
			},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"secrets",
			},
			Verbs: []string{
				"delete",
			},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"events",
			},
			Verbs: []string{
				"create",
			},
		},
		{
			APIGroups: []string{
				"apps",
			},
			Resources: []string{
				"replicasets", "statefulsets", "daemonsets", "deployments",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"batch",
			},
			Resources: []string{
				"jobs", "cronjobs",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"rbac.authorization.k8s.io",
			},
			Resources: []string{
				"roles", "rolebindings", "clusterroles", "clusterrolebindings",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"apiextensions.k8s.io",
			},
			Resources: []string{
				"customresourcedefinitions",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"batch",
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
				"aquasecurity.github.io",
			},
			Resources: []string{
				"vulnerabilityreports", "configauditreports", "clusterconfigauditreports", "ciskubebenchreports",
			},
			Verbs: []string{
				"get", "list", "watch", "create", "update", "delete",
			},
		},
		{
			APIGroups: []string{
				"coordination.k8s.io",
			},
			Resources: []string{
				"leases",
			},
			Verbs: []string{
				"create", "get", "update",
			},
		},
		{
			APIGroups: []string{
				"networking.k8s.io",
			},
			Resources: []string{
				"networkpolicies", "ingresses",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"policy",
			},
			Resources: []string{
				"podsecuritypolicies",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
	}

	crole := rbac.CreateClusterRole(name, namespace, "starboard-operator", fmt.Sprintf("%s-rbac", "aqua-sb"), "Deploy Aqua Starboard Cluster Role", rules)

	return crole
}

// CreateServiceAccount Create new service account
func (enf *AquaStarboardHelper) CreateStarboardServiceAccount(cr, namespace, app, name string) *corev1.ServiceAccount {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Service account for aqua starboard",
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
		ImagePullSecrets: []corev1.LocalObjectReference{
			{
				Name: "aqua-registry",
			},
		},
	}

	return sa
}

func (enf *AquaStarboardHelper) CreateClusterRoleBinding(cr, namespace, name, app, sa, clusterrole string) *rbacv1.ClusterRoleBinding {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua starboard Cluster Role Binding",
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

func (enf *AquaStarboardHelper) CreateStarboardSecret(cr, namespace, name, app string) *corev1.Secret {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Starboard secret",
	}
	starboardSecret := &corev1.Secret{
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
	}

	return starboardSecret
}

func (enf *AquaStarboardHelper) CreateStarboardConftestConfigMap(cr, namespace, name, app, version string) *corev1.ConfigMap {
	labels := map[string]string{
		"app":                        app,
		"deployedby":                 "aqua-operator",
		"aquasecoperator_cr":         cr,
		"app.kubernetes.io/name":     "starboard-operator",
		"app.kubernetes.io/instance": "starboard-operator",
		"app.kubernetes.io/version":  consts.StarboardVersion,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua starboard-policies-config ConfigMap",
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
	}

	return configMap
}

func (enf *AquaStarboardHelper) CreateStarboardConfigMap(cr, namespace, name, app string) *corev1.ConfigMap {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua starboard ConfigMap",
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
		Data: map[string]string{
			"configAuditReports.scanner": "Conftest",
		},
	}

	return configMap
}

func (enf *AquaStarboardHelper) CreateStarboardDeployment(cr *aquasecurityv1alpha1.AquaStarboard, name, app, registry, tag, pullPolicy, repository string) *appsv1.Deployment {

	image := os.Getenv("RELATED_IMAGE_STARBOARD")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description":       "Deploy Starboard Deployment",
		"ConfigMapChecksum": cr.Spec.ConfigMapChecksum,
	}

	privileged := false
	automountServiceAccountToken := true
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := false

	envVars := enf.getStarboardEnvVars(cr)
	selectors := map[string]string{
		"app": "starboard-operator",
	}

	ports := []corev1.ContainerPort{
		{
			Name:          "probes",
			ContainerPort: 9090,
		},
		{
			Name:          "metrics",
			ContainerPort: 8080,
		},
	}
	//runAsUser := int64(11431)
	//runAsGroup := int64(11433)
	//fsGroup := int64(11433)

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
			Replicas: extra.Int32Ptr(int32(cr.Spec.StarboardService.Replicas)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: selectors,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: selectors,
				},
				Spec: corev1.PodSpec{
					//SecurityContext: &corev1.PodSecurityContext{
					//	RunAsUser:  &runAsUser,
					//	RunAsGroup: &runAsGroup,
					//	FSGroup:    &fsGroup,
					//},
					ServiceAccountName:           cr.Spec.Infrastructure.ServiceAccount,
					AutomountServiceAccountToken: &automountServiceAccountToken,
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: cr.Spec.Config.ImagePullSecret,
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "operator",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							SecurityContext: &corev1.SecurityContext{
								Privileged:               &privileged,
								ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
								AllowPrivilegeEscalation: &allowPrivilegeEscalation,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{
										"ALL",
									},
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz/",
										Port: intstr.FromString("probes"),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
								SuccessThreshold:    1,
								FailureThreshold:    10,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz/",
										Port: intstr.FromString("probes"),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
								SuccessThreshold:    1,
								FailureThreshold:    3,
							},
							Ports: ports,
							Env:   envVars,
						},
					},
				},
			},
		},
	}

	StarboardExtraData := enf.Parameters.Starboard.Spec.StarboardService

	if StarboardExtraData.Resources != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *StarboardExtraData.Resources
	}

	if StarboardExtraData.LivenessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].LivenessProbe = StarboardExtraData.LivenessProbe
	}

	if StarboardExtraData.ReadinessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = StarboardExtraData.ReadinessProbe
	}

	if StarboardExtraData.VolumeMounts != nil {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, StarboardExtraData.VolumeMounts...)
	}

	if StarboardExtraData.Volumes != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, StarboardExtraData.Volumes...)
	}

	if enf.Parameters.Starboard.Spec.Envs != nil {
		deployment.Spec.Template.Spec.Containers[0].Env = append(deployment.Spec.Template.Spec.Containers[0].Env, enf.Parameters.Starboard.Spec.Envs...)
	}

	return deployment
}

func (ebf *AquaStarboardHelper) getStarboardEnvVars(cr *aquasecurityv1alpha1.AquaStarboard) []corev1.EnvVar {

	result := []corev1.EnvVar{
		{
			Name:  "OPERATOR_NAMESPACE",
			Value: cr.Namespace,
		},
		{
			Name:  "OPERATOR_TARGET_NAMESPACES",
			Value: "",
		},
		{
			Name:  "OPERATOR_METRICS_BIND_ADDRESS",
			Value: consts.OperatorMetricsBindAddress,
		},
		{
			Name:  "OPERATOR_HEALTH_PROBE_BIND_ADDRESS",
			Value: consts.OperatorHealthProbeBindAddress,
		},
	}
	operatorLogDevMode := corev1.EnvVar{
		Name:  "OPERATOR_LOG_DEV_MODE",
		Value: consts.OperatorLogDevMode,
	}
	if cr.Spec.LogDevMode {
		operatorLogDevMode = corev1.EnvVar{
			Name:  "OPERATOR_LOG_DEV_MODE",
			Value: "true",
		}
	}
	result = append(result, operatorLogDevMode)

	operatorConcurrentScanJobsLimit := corev1.EnvVar{
		Name:  "OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT",
		Value: consts.OperatorConcurrentScanJobsLimit,
	}

	if cr.Spec.ConcurrentScanJobsLimit != "" {
		operatorConcurrentScanJobsLimit = corev1.EnvVar{
			Name:  "OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT",
			Value: cr.Spec.ConcurrentScanJobsLimit,
		}
	}

	result = append(result, operatorConcurrentScanJobsLimit)

	operatorScanJobRetryAfter := corev1.EnvVar{
		Name:  "OPERATOR_SCAN_JOB_RETRY_AFTER",
		Value: consts.OperatorScanJobRetryAfter,
	}

	if cr.Spec.ScanJobRetryAfter != "" {
		operatorScanJobRetryAfter = corev1.EnvVar{
			Name:  "OPERATOR_SCAN_JOB_RETRY_AFTER",
			Value: cr.Spec.ScanJobRetryAfter}
	}

	result = append(result, operatorScanJobRetryAfter)

	operatorCisKubernetesBenchmarkEnabled := corev1.EnvVar{
		Name:  "OPERATOR_CIS_KUBERNETES_BENCHMARK_ENABLED",
		Value: consts.OperatorCisKubernetesBenchmarkEnabled,
	}

	if cr.Spec.CisKubernetesBenchmarkEnabled != "" {
		operatorCisKubernetesBenchmarkEnabled = corev1.EnvVar{
			Name:  "OPERATOR_CIS_KUBERNETES_BENCHMARK_ENABLED",
			Value: cr.Spec.CisKubernetesBenchmarkEnabled}
	}

	result = append(result, operatorCisKubernetesBenchmarkEnabled)

	operatorVulnerabilityScannerEnabled := corev1.EnvVar{
		Name:  "OPERATOR_VULNERABILITY_SCANNER_ENABLED",
		Value: consts.OperatorVulnerabilityScannerEnabled,
	}

	if cr.Spec.VulnerabilityScannerEnabled != "" {
		operatorVulnerabilityScannerEnabled = corev1.EnvVar{
			Name:  "OPERATOR_VULNERABILITY_SCANNER_ENABLED",
			Value: cr.Spec.VulnerabilityScannerEnabled}
	}

	result = append(result, operatorVulnerabilityScannerEnabled)

	operatorBatchDeleteLimit := corev1.EnvVar{
		Name:  "OPERATOR_BATCH_DELETE_LIMIT",
		Value: consts.OperatorBatchDeleteLimit,
	}

	if cr.Spec.BatchDeleteLimit != "" {
		operatorBatchDeleteLimit = corev1.EnvVar{
			Name:  "OPERATOR_BATCH_DELETE_LIMIT",
			Value: cr.Spec.BatchDeleteLimit}
	}

	result = append(result, operatorBatchDeleteLimit)

	operatorBatchDeleteDelay := corev1.EnvVar{
		Name:  "OPERATOR_BATCH_DELETE_DELAY",
		Value: consts.OperatorBatchDeleteDelay,
	}

	if cr.Spec.BatchDeleteDelay != "" {
		operatorBatchDeleteDelay = corev1.EnvVar{
			Name:  "OPERATOR_BATCH_DELETE_DELAY",
			Value: cr.Spec.BatchDeleteDelay}
	}

	result = append(result, operatorBatchDeleteDelay)

	operatorClusterComplianceEnabled := corev1.EnvVar{
		Name:  "OPERATOR_CLUSTER_COMPLIANCE_ENABLED",
		Value: consts.OperatorClusterComplianceEnabled,
	}

	if cr.Spec.OperatorClusterComplianceEnabled != "" {
		operatorClusterComplianceEnabled = corev1.EnvVar{
			Name:  "OPERATOR_BATCH_DELETE_DELAY",
			Value: cr.Spec.BatchDeleteDelay}
	}

	result = append(result, operatorClusterComplianceEnabled)
	return result
}
