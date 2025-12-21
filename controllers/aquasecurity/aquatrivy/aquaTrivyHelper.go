package aquatrivy

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

// TrivyParameters :
type TrivyParameters struct {
	Trivy *aquasecurityv1alpha1.AquaTrivy
}

// AquaTrivyHelper :
type AquaTrivyHelper struct {
	Parameters TrivyParameters
}

func newAquaTrivyHelper(cr *aquasecurityv1alpha1.AquaTrivy) *AquaTrivyHelper {
	params := TrivyParameters{
		Trivy: cr,
	}

	return &AquaTrivyHelper{
		Parameters: params,
	}
}

func (enf *AquaTrivyHelper) CreateTrivyClusterRole(name string, namespace string) *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"configmaps",
				"limitranges",
				"nodes",
				"pods",
				"replicationcontrollers",
				"resourcequotas",
				"services",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"namespaces"},
			Verbs:     []string{"get"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods/log"},
			Verbs:     []string{"get", "list"},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"secrets",
			},
			Verbs: []string{
				"create", "get", "update",
			},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"serviceaccounts",
			},
			Verbs: []string{
				"get",
			},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"nodes/proxy"},
			Verbs:     []string{"get"},
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
				"daemonsets", "deployments", "replicasets", "statefulsets",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"apps.openshift.io",
			},
			Resources: []string{
				"deploymentconfigs",
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
				"cronjobs",
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
				"clusterrolebindings", "clusterroles", "rolebindings", "roles",
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
				"create", "delete", "get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"networking.k8s.io",
			},
			Resources: []string{
				"ingresses", "networkpolicies",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"aquasecurity.github.io",
			},
			Resources: []string{
				"clusterconfigauditreports",
				"clusterrbacassessmentreports",
				"configauditreports",
				"rbacassessmentreports",
			},
			Verbs: []string{
				"create", "delete", "get", "list", "patch", "update", "watch",
			},
		},
		{
			APIGroups: []string{
				"aquasecurity.github.io",
			},
			Resources: []string{
				"clustercompliancereports/status",
			},
			Verbs: []string{
				"get", "patch", "update",
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
	}

	crole := rbac.CreateClusterRole(name, namespace, "trivy-operator", fmt.Sprintf("%s-rbac", "aqua-trivy"), "Deploy Aqua Trivy Cluster Role", rules)

	return crole
}

// CreateServiceAccount Create new service account
func (enf *AquaTrivyHelper) CreateTrivyServiceAccount(cr, namespace, app, name string) *corev1.ServiceAccount {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Service account for aqua trivy",
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

func (enf *AquaTrivyHelper) CreateClusterRoleBinding(cr, namespace, name, app, sa, clusterrole string) *rbacv1.ClusterRoleBinding {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Trivy Cluster Role Binding",
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

func (enf *AquaTrivyHelper) CreateTrivyConfigMap(cr, namespace, name, app string) *corev1.ConfigMap {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua trivy ConfigMap",
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
			"configAuditReports.scanner": "Trivy",
		},
	}

	return configMap
}

func (enf *AquaTrivyHelper) CreateTrivyOperatorConfigMap(namespace string) *corev1.ConfigMap {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator",
			Namespace: namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"nodeCollector.volumes":                        "[{\"hostPath\":{\"path\":\"/var/lib/etcd\"},\"name\":\"var-lib-etcd\"},{\"hostPath\":{\"path\":\"/var/lib/kubelet\"},\"name\":\"var-lib-kubelet\"},{\"hostPath\":{\"path\":\"/var/lib/kube-scheduler\"},\"name\":\"var-lib-kube-scheduler\"},{\"hostPath\":{\"path\":\"/var/lib/kube-controller-manager\"},\"name\":\"var-lib-kube-controller-manager\"},{\"hostPath\":{\"path\":\"/etc/systemd\"},\"name\":\"etc-systemd\"},{\"hostPath\":{\"path\":\"/lib/systemd\"},\"name\":\"lib-systemd\"},{\"hostPath\":{\"path\":\"/etc/kubernetes\"},\"name\":\"etc-kubernetes\"},{\"hostPath\":{\"path\":\"/etc/cni/net.d/\"},\"name\":\"etc-cni-netd\"}]",
			"nodeCollector.volumeMounts":                   "[{\"mountPath\":\"/var/lib/etcd\",\"name\":\"var-lib-etcd\",\"readOnly\":true},{\"mountPath\":\"/var/lib/kubelet\",\"name\":\"var-lib-kubelet\",\"readOnly\":true},{\"mountPath\":\"/var/lib/kube-scheduler\",\"name\":\"var-lib-kube-scheduler\",\"readOnly\":true},{\"mountPath\":\"/var/lib/kube-controller-manager\",\"name\":\"var-lib-kube-controller-manager\",\"readOnly\":true},{\"mountPath\":\"/etc/systemd\",\"name\":\"etc-systemd\",\"readOnly\":true},{\"mountPath\":\"/lib/systemd/\",\"name\":\"lib-systemd\",\"readOnly\":true},{\"mountPath\":\"/etc/kubernetes\",\"name\":\"etc-kubernetes\",\"readOnly\":true},{\"mountPath\":\"/etc/cni/net.d/\",\"name\":\"etc-cni-netd\",\"readOnly\":true}]",
			"scanJob.useGCRServiceAccount":                 "true",
			"scanJob.podTemplateContainerSecurityContext":  "{\"allowPrivilegeEscalation\":false,\"capabilities\":{\"drop\":[\"ALL\"]},\"privileged\":false,\"readOnlyRootFilesystem\":true}",
			"scanJob.compressLogs":                         "true",
			"vulnerabilityReports.scanner":                 "Trivy",
			"configAuditReports.scanner":                   "Trivy",
			"compliance.failEntriesLimit":                  "10",
			"report.recordFailedChecksOnly":                "true",
			"node.collector.imageRef":                      "ghcr.io/aquasecurity/node-collector:0.3.1",
			"policies.bundle.oci.ref":                      "mirror.gcr.io/aquasec/trivy-checks:1",
			"policies.bundle.insecure":                     "false",
			"node.collector.nodeSelector":                  "true",
			"vulnerabilityReports.scanJobsInSameNamespace": "false",
		},
	}
}

func (enf *AquaTrivyHelper) CreateTrivyOperatorSettingsConfigMap(namespace string) *corev1.ConfigMap {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator-config",
			Namespace: namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"OPERATOR_LOG_DEV_MODE":                                      "false",
			"OPERATOR_SCAN_JOB_TTL":                                      "",
			"OPERATOR_SCAN_JOB_TIMEOUT":                                  "5m",
			"OPERATOR_CONCURRENT_SCAN_JOBS_LIMIT":                        "10",
			"OPERATOR_CONCURRENT_NODE_COLLECTOR_LIMIT":                   "1",
			"OPERATOR_SCAN_JOB_RETRY_AFTER":                              "30s",
			"OPERATOR_BATCH_DELETE_LIMIT":                                "10",
			"OPERATOR_BATCH_DELETE_DELAY":                                "10s",
			"OPERATOR_METRICS_BIND_ADDRESS":                              ":8080",
			"OPERATOR_METRICS_FINDINGS_ENABLED":                          "true",
			"OPERATOR_METRICS_VULN_ID_ENABLED":                           "false",
			"OPERATOR_HEALTH_PROBE_BIND_ADDRESS":                         ":9090",
			"OPERATOR_PPROF_BIND_ADDRESS":                                "",
			"OPERATOR_VULNERABILITY_SCANNER_ENABLED":                     "false",
			"OPERATOR_SBOM_GENERATION_ENABLED":                           "false",
			"OPERATOR_CLUSTER_SBOM_CACHE_ENABLED":                        "false",
			"OPERATOR_VULNERABILITY_SCANNER_SCAN_ONLY_CURRENT_REVISIONS": "true",
			"OPERATOR_SCANNER_REPORT_TTL":                                "",
			"OPERATOR_CACHE_REPORT_TTL":                                  "120h",
			"CONTROLLER_CACHE_SYNC_TIMEOUT":                              "5m",
			"OPERATOR_CONFIG_AUDIT_SCANNER_ENABLED":                      "true",
			"OPERATOR_RBAC_ASSESSMENT_SCANNER_ENABLED":                   "true",
			"OPERATOR_INFRA_ASSESSMENT_SCANNER_ENABLED":                  "false",
			"OPERATOR_CONFIG_AUDIT_SCANNER_SCAN_ONLY_CURRENT_REVISIONS":  "true",
			"OPERATOR_EXPOSED_SECRET_SCANNER_ENABLED":                    "false",
			"OPERATOR_METRICS_EXPOSED_SECRET_INFO_ENABLED":               "false",
			"OPERATOR_METRICS_CONFIG_AUDIT_INFO_ENABLED":                 "false",
			"OPERATOR_METRICS_RBAC_ASSESSMENT_INFO_ENABLED":              "false",
			"OPERATOR_METRICS_INFRA_ASSESSMENT_INFO_ENABLED":             "false",
			"OPERATOR_METRICS_IMAGE_INFO_ENABLED":                        "false",
			"OPERATOR_METRICS_CLUSTER_COMPLIANCE_INFO_ENABLED":           "false",
			"OPERATOR_WEBHOOK_BROADCAST_URL":                             "",
			"OPERATOR_WEBHOOK_BROADCAST_TIMEOUT":                         "30s",
			"OPERATOR_WEBHOOK_BROADCAST_CUSTOM_HEADERS":                  "",
			"OPERATOR_SEND_DELETED_REPORTS":                              "false",
			"OPERATOR_PRIVATE_REGISTRY_SCAN_SECRETS_NAMES":               "{}",
			"OPERATOR_ACCESS_GLOBAL_SECRETS_SERVICE_ACCOUNTS":            "true",
			"OPERATOR_BUILT_IN_TRIVY_SERVER":                             "false",
			"TRIVY_SERVER_HEALTH_CHECK_CACHE_EXPIRATION":                 "10h",
			"OPERATOR_MERGE_RBAC_FINDING_WITH_CONFIG_AUDIT":              "false",
			"OPERATOR_CLUSTER_COMPLIANCE_ENABLED":                        "false",
		},
	}
}

func (enf *AquaTrivyHelper) CreateTrivyPoliciesConfigMap(namespace string) *corev1.ConfigMap {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator-policies-config",
			Namespace: namespace,
			Labels:    labels,
		},
		// Data intentionally empty.
	}
}

func (enf *AquaTrivyHelper) CreateTrivyConfigConfigMap(namespace string) *corev1.ConfigMap {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "ConfigMap",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator-trivy-config",
			Namespace: namespace,
			Labels:    labels,
		},
		Data: map[string]string{
			"trivy.repository":                          "mirror.gcr.io/aquasec/trivy",
			"trivy.tag":                                 "0.67.0",
			"trivy.imagePullPolicy":                     "IfNotPresent",
			"trivy.severity":                            "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
			"trivy.slow":                                "true",
			"trivy.skipJavaDBUpdate":                    "false",
			"trivy.includeDevDeps":                      "false",
			"trivy.imageScanCacheDir":                   "/tmp/trivy/.cache",
			"trivy.filesystemScanCacheDir":              "/var/trivyoperator/trivy-db",
			"trivy.dbRepository":                        "mirror.gcr.io/aquasec/trivy-db",
			"trivy.javaDbRepository":                    "mirror.gcr.io/aquasec/trivy-java-db",
			"trivy.command":                             "image",
			"trivy.sbomSources":                         "",
			"trivy.dbRepositoryInsecure":                "false",
			"trivy.useBuiltinRegoPolicies":              "false",
			"trivy.useEmbeddedRegoPolicies":             "true",
			"trivy.supportedConfigAuditKinds":           "Workload,Service,Role,ClusterRole,NetworkPolicy,Ingress,LimitRange,ResourceQuota",
			"trivy.timeout":                             "5m0s",
			"trivy.mode":                                "Standalone",
			"trivy.resources.requests.cpu":              "100m",
			"trivy.resources.requests.memory":           "100M",
			"trivy.resources.limits.cpu":                "500m",
			"trivy.resources.limits.memory":             "500M",
			"trivy.additionalVulnerabilityReportFields": "",
		},
	}
}

func (enf *AquaTrivyHelper) CreateTrivySecret(namespace, name string) *corev1.Secret {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Type: corev1.SecretTypeOpaque,
	}
}

func (enf *AquaTrivyHelper) CreateTrivyService(namespace string) *corev1.Service {
	labels := map[string]string{
		"app.kubernetes.io/name":     "trivy-operator",
		"app.kubernetes.io/instance": "trivy-operator",
	}
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "trivy-operator",
				"app.kubernetes.io/instance":   "trivy-operator",
				"app.kubernetes.io/version":    "0.29.0-ubi9",
				"app.kubernetes.io/managed-by": "trivy-operator",
			},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector:  labels,
			Ports: []corev1.ServicePort{
				{
					Name:        "metrics",
					Port:        80,
					TargetPort:  intstr.FromString("metrics"),
					Protocol:    corev1.ProtocolTCP,
					AppProtocol: func() *string { s := "TCP"; return &s }(),
				},
			},
			Type: corev1.ServiceTypeClusterIP,
		},
	}
}

func (enf *AquaTrivyHelper) CreateTrivyRole(namespace string) *rbacv1.Role {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator",
			Namespace: enf.Parameters.Trivy.Namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"create", "get", "list", "watch"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"create", "get", "delete", "update"},
			},
		},
	}
}

func (enf *AquaTrivyHelper) CreateTrivyRoleBinding(namespace string) *rbacv1.RoleBinding {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator",
			Namespace: namespace,
			Labels:    labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "trivy-operator",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      enf.Parameters.Trivy.Spec.Infrastructure.ServiceAccount,
				Namespace: namespace,
			},
		},
	}
}

func (enf *AquaTrivyHelper) CreateTrivyLeaderElectionRole(namespace string) *rbacv1.Role {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator-leader-election",
			Namespace: namespace,
			Labels:    labels,
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"create", "get", "update"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create"},
			},
		},
	}
}

func (enf *AquaTrivyHelper) CreateTrivyLeaderElectionRoleBinding(namespace string) *rbacv1.RoleBinding {
	labels := map[string]string{
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "trivy-operator",
	}
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "trivy-operator-leader-election",
			Namespace: namespace,
			Labels:    labels,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "trivy-operator-leader-election",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      enf.Parameters.Trivy.Spec.Infrastructure.ServiceAccount,
				Namespace: namespace,
			},
		},
	}
}
func (enf *AquaTrivyHelper) CreateTrivyDeployment(cr *aquasecurityv1alpha1.AquaTrivy, name, app, registry, tag, pullPolicy, repository string) *appsv1.Deployment {
	image := os.Getenv("RELATED_IMAGE_TRIVY")
	if image == "" {
		image = fmt.Sprintf("%s/%s:%s", registry, repository, tag)
	}

	labels := map[string]string{
		"app":                          app,
		"deployedby":                   "aqua-operator",
		"aquasecoperator_cr":           cr.Name,
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "aqua-operator",
	}
	annotations := map[string]string{
		"description":       "Deploy Trivy Deployment",
		"ConfigMapChecksum": cr.Spec.ConfigMapChecksum,
	}

	privileged := false
	automountServiceAccountToken := true
	readOnlyRootFilesystem := true
	allowPrivilegeEscalation := false

	envVars := enf.getTrivyEnvVars(cr)
	selectors := map[string]string{
		"app":                          "trivy-operator",
		"app.kubernetes.io/name":       "trivy-operator",
		"app.kubernetes.io/instance":   "trivy-operator",
		"app.kubernetes.io/version":    "0.29.0-ubi9",
		"app.kubernetes.io/managed-by": "aqua-operator",
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
			Replicas: extra.Int32Ptr(int32(cr.Spec.TrivyService.Replicas)),
			Strategy: appsv1.DeploymentStrategy{
				Type: appsv1.RecreateDeploymentStrategyType,
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: selectors,
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: selectors,
					Annotations: map[string]string{
						"ConfigMapChecksum": cr.Spec.ConfigMapChecksum,
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName:           cr.Spec.Infrastructure.ServiceAccount,
					AutomountServiceAccountToken: &automountServiceAccountToken,
					ImagePullSecrets: []corev1.LocalObjectReference{
						{
							Name: cr.Spec.Config.ImagePullSecret,
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "trivy-operator",
							Image:           image,
							ImagePullPolicy: corev1.PullPolicy(pullPolicy),
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "tmp",
									MountPath: "/tmp",
								},
								{
									Name:      "trivy-operator-cache",
									MountPath: "/var/trivyoperator",
								},
							},
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
							EnvFrom: []corev1.EnvFromSource{
								{
									ConfigMapRef: &corev1.ConfigMapEnvSource{
										LocalObjectReference: corev1.LocalObjectReference{
											Name: "trivy-operator-config",
										},
									},
								},
							},
							Env: envVars,
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "tmp",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "trivy-operator-cache",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		},
	}

	trivyExtraData := enf.Parameters.Trivy.Spec.TrivyService

	if trivyExtraData.Resources != nil {
		deployment.Spec.Template.Spec.Containers[0].Resources = *trivyExtraData.Resources
	}

	if trivyExtraData.LivenessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].LivenessProbe = trivyExtraData.LivenessProbe
	}

	if trivyExtraData.ReadinessProbe != nil {
		deployment.Spec.Template.Spec.Containers[0].ReadinessProbe = trivyExtraData.ReadinessProbe
	}

	if trivyExtraData.VolumeMounts != nil {
		deployment.Spec.Template.Spec.Containers[0].VolumeMounts = append(deployment.Spec.Template.Spec.Containers[0].VolumeMounts, trivyExtraData.VolumeMounts...)
	}

	if trivyExtraData.Volumes != nil {
		deployment.Spec.Template.Spec.Volumes = append(deployment.Spec.Template.Spec.Volumes, trivyExtraData.Volumes...)
	}

	if enf.Parameters.Trivy.Spec.Envs != nil {
		deployment.Spec.Template.Spec.Containers[0].Env = append(deployment.Spec.Template.Spec.Containers[0].Env, enf.Parameters.Trivy.Spec.Envs...)
	}

	return deployment
}

func (ebf *AquaTrivyHelper) getTrivyEnvVars(cr *aquasecurityv1alpha1.AquaTrivy) []corev1.EnvVar {
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
			Name:  "OPERATOR_EXCLUDE_NAMESPACES",
			Value: consts.OperatorExcludeNamespaces,
		},
		{
			Name:  "OPERATOR_METRICS_BIND_ADDRESS",
			Value: consts.OperatorMetricsBindAddress,
		},
		{
			Name:  "OPERATOR_HEALTH_PROBE_BIND_ADDRESS",
			Value: consts.OperatorHealthProbeBindAddress,
		},
		{
			Name:  "OPERATOR_TARGET_WORKLOADS",
			Value: "pod,replicaset,replicationcontroller,statefulset,daemonset,cronjob,job",
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
