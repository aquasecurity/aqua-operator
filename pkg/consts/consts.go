package consts

const (
	// ServiceAccount Service Account
	ServiceAccount = "%s-sa"

	// Registry URL
	Registry = "registry.aquasec.com"

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
	LatestVersion = "5.3"

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

	EmptyString = ""

	AquaRunAsUser  = int64(11431)
	AquaRunAsGroup = int64(11433)
	AquaFsGroup    = int64(11433)

	DefaultKubeEnforcerToken = "ke-token"
)
