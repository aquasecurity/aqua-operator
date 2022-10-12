package consts

const (
	// ServiceAccount Service Account
	ServiceAccount = "%s-sa"

	// StarboardServiceAccount Service Account
	StarboardServiceAccount = "starboard-operator"
	// Registry URL
	Registry = "registry.aquasec.com"

	// StarboardRegistry URL
	StarboardRegistry = "docker.io/aquasec"

	// PullPolicy Image Pull Policy
	PullPolicy = "IfNotPresent"

	// PullImageSecretName pull image secret name
	PullImageSecretName = "%s-registry-secret"

	// AdminPasswordSecretName Admin Password Secre Name
	AdminPasswordSecretName = "%s-aqua-admin"

	// AdminPasswordSecretKey Admin Password Secret Key
	AdminPasswordSecretKey = "password"

	// LicenseTokenSecretName License Token Secret Name
	LicenseTokenSecretName = "%s-aqua-license"

	// LicenseTokenSecretKey License Token Secret Key
	LicenseTokenSecretKey = "license"

	// EnforcerTokenSecretName Enforcer Token Secret Name
	EnforcerTokenSecretName = "%s-enforcer-token"

	// EnforcerTokenSecretKey Enforcer Token Secret Key
	EnforcerTokenSecretKey = "token"

	// ScalockDbPasswordSecretName Scalock DB Password Secret Name
	ScalockDbPasswordSecretName = "%s-aqua-db"

	// AuditDbPasswordSecretName Scalock audit DB Password Secret Name
	AuditDbPasswordSecretName = "%s-aqua-audit-db"

	// ClusterReaderRole is Openshift cluster role to bind Aqua service accounts
	ClusterReaderRole = "cluster-reader"

	// AquaSAClusterReaderRoleBind is Openshift cluster role binding between aqua-sa and ClusterReaderRole
	AquaSAClusterReaderRoleBind = "aqua-sa-cluster-reader-crb"

	// AquaKubeEnforcerSAClusterReaderRoleBind is Openshift cluster role binding between aqua-kube-enforcer-sa and ClusterReaderRole
	AquaKubeEnforcerSAClusterReaderRoleBind = "aqua-kube-enforcer-sa-cluster-reader-crb"

	AquaKubeEnforcerFinalizer                          = "aquakubeenforcers.operator.aquasec.com/finalizer"
	AquaKubeEnforcerMutantingWebhookConfigurationName  = "kube-enforcer-me-injection-hook-config"
	AquaKubeEnforcerValidatingWebhookConfigurationName = "kube-enforcer-admission-hook-config"
	AquaKubeEnforcerClusterRoleName                    = "aqua-kube-enforcer"
	AquaKubeEnforcerClusterRoleBidingName              = "aqua-kube-enforcer"

	// AquaStarboardSAClusterReaderRoleBind is Openshift cluster role binding between aqua-starboard-sa and ClusterReaderRole
	AquaStarboardSAClusterReaderRoleBind = "aqua-starboard-sa-cluster-reader-crb"

	// ScalockDbPasswordSecretKey Scalock DB Password Secret Key
	ScalockDbPasswordSecretKey = "password"

	// GatewayURL Aqua Gateway
	GatewayURL = "%s-gateway:8443"

	// DiscoveryClusterRole Discovery Cluster Role
	DiscoveryClusterRole = "%s-discovery-cr"

	// DiscoveryClusterRoleBinding Discovery Cluster Role Binding
	DiscoveryClusterRoleBinding = "%s-discovery-crb"

	// DbPvcName DB PVC Name
	DbPvcName = "%s-db-pvc"

	// AuditDbPvcName DB PVC Name
	AuditDbPvcName = "%s-audit-db-pvc"

	// DbPvcSize Database PVC Size
	DbPvcSize = 10

	// LatestVersion Latest supported aqua version in operator
	LatestVersion = "6.5"

	// StarboardVersion Latest starboard version

	StarboardVersion = "0.15.10"

	// CyberCenterAddress Aqua Cybercenter Address
	CyberCenterAddress = "https://cybercenter5.aquasec.com"

	// Deployments

	DbDeployName  = "%s-db"
	DbServiceName = "%s-db"

	AuditDbDeployName  = "%s-audit-db"
	AuditDbServiceName = "%s-audit-db"

	GatewayDeployName  = "%s-gateway"
	GatewayServiceName = "%s-gateway"

	ServerDeployName  = "%s-server"
	ServerServiceName = "%s-server"

	EnforcerDeamonsetName = "%s-agent"

	ScannerDeployName = "%s-scanner"

	ScannerSecretName = "aqua-scanner"

	ScannerConfigMapName = "aqua-scanner-config"

	EmptyString = ""

	AquaRunAsUser  = int64(11431)
	AquaRunAsGroup = int64(11433)
	AquaFsGroup    = int64(11433)

	DefaultKubeEnforcerToken = "ke-token"

	DBInitContainerCommand = "[ -f $PGDATA/server.key ] && chmod 600 $PGDATA/server.key || echo 'OK'"

	OpenShiftPlatform = "openshift"

	// mtls

	MtlsAquaWebSecretName = "aqua-grpc-web"

	MtlsAquaGatewaySecretName = "aqua-grpc-gateway"

	MtlsAquaEnforcerSecretName = "aqua-grpc-enforcer"

	MtlsAquaKubeEnforcerSecretName = "aqua-grpc-kube-enforcer"

	OperatorLogDevMode = "false"

	OperatorConcurrentScanJobsLimit = "10"

	OperatorScanJobRetryAfter = "30s"

	OperatorMetricsBindAddress = ":8080"

	OperatorHealthProbeBindAddress = ":9090"

	OperatorCisKubernetesBenchmarkEnabled = "false"

	OperatorVulnerabilityScannerEnabled = "false"

	OperatorBatchDeleteLimit = "10"

	OperatorBatchDeleteDelay = "10s"

	OperatorClusterComplianceEnabled = "false"

	ServerConfigMapName = "aqua-csp-server-config"

	EnforcerConfigMapName = "aqua-csp-enforcer"
)
