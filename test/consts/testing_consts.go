package testing_consts

import "github.com/aquasecurity/aqua-operator/pkg/consts"

const (
	Namespace                  = "aqua"
	Version                    = consts.LatestVersion
	StarboardVersion           = consts.StarboardVersion
	UbiImageTag                = "2022.4.81-ubi8" //todo: update it to latest after we create ubi8 latest tag in the release process
	NameSpace                  = "aqua"
	CspServiceAccount          = "aqua-sa"
	StarboardServiceAccount    = "starboard-operator"
	KubeEnforcerServiceAccount = "aqua-kube-enforcer-sa"
	ImagePullSecret            = "aqua-registry"
	StarboardImagePullSecret   = "starboard-registry"
	DbDiskSize                 = 10
	DataBaseSecretKey          = "db-password"
	DatabaseSecretName         = "aqua-database-password"
	Registry                   = "registry.aquasec.com"
	StarboardRegistry          = "docker.io/aquasec"
	DatabaseRepo               = "database"
	GatewayRepo                = "gateway"
	ServerRepo                 = "console"
	EnforcerRepo               = "enforcer"
	KeEnforcerRepo             = "kube-enforcer"
	ScannerRepo                = "scanner"
	StarboardRepo              = "starboard-operator"
	GatewayPort                = 8443
	DbPvcStorageClassName      = "aqua-storage"
	DbPvcStorageSize           = "50Gi"
	DbPvcHostPath              = "/tmp/aquadb/"
	EnforcerToken              = "enforcer_token"
	GatewayServiceName         = "%s-gateway"
	EnforcerGroupName          = "operator-default-enforcer-group"
	KubeEnforcerToken          = "ke_enforcer_token"
	KUbeEnforcerGroupName      = "operator-default-ke-group"
	ServerAdminUser            = "administrator"
	ServerAdminPassword        = "@Password1"
	ServerHost                 = "http://aqua-server:8080"
	ScannerToken               = ""
	GatewayAddress             = "aqua-gateway:8443"
	ClusterName                = "Default-cluster-name"
)
