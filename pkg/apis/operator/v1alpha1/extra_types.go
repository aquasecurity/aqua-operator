package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
)

type AquaInfrastructure struct {
	ServiceAccount string `json:"serviceAccount,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	Version        string `json:"version,omitempty"`
	Platform       string `json:"platform,omitempty"`
	Requirements   bool   `json:"requirements"`
}

type AquaCommon struct {
	ActiveActive       bool        `json:"activeActive"`
	StorageClass       string      `json:"storageclass,omitempty"`
	CyberCenterAddress string      `json:"cybercenterAddress,omitempty"`
	ImagePullSecret    string      `json:"imagePullSecret,omitempty"`
	AdminPassword      *AquaSecret `json:"adminPassword,omitempty"`
	AquaLicense        *AquaSecret `json:"license,omitempty"`
	DatabaseSecret     *AquaSecret `json:"databaseSecret,omitempty"`
	DbDiskSize         int         `json:"dbDiskSize,omitempty"`
}

type AquaDockerRegistry struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type AquaDatabaseInformation struct {
	Host     string `json:"host"`
	Port     int64  `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type AquaSecret struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type AquaImage struct {
	Repository string `json:"repository"`
	Registry   string `json:"registry"`
	Tag        string `json:"tag"`
	PullPolicy string `json:"pullPolicy"`
}

// AquaService Struct for deployment spec
type AquaService struct {
	// Number of instances to deploy for a specific aqua deployment.
	Replicas       int64                        `json:"replicas"`
	ServiceType    string                       `json:"service,omitempty"`
	ImageData      *AquaImage                   `json:"image,omitempty"`
	Resources      *corev1.ResourceRequirements `json:"resources,omitempty"`
	LivenessProbe  *corev1.Probe                `json:"livenessProbe,omitempty"`
	ReadinessProbe *corev1.Probe                `json:"readinessProbe,omitempty"`
	NodeSelector   map[string]string            `json:"nodeSelector,omitempty"`
	Affinity       *corev1.Affinity             `json:"affinity,omitempty"`
	Tolerations    []corev1.Toleration          `json:"tolerations,omitempty"`
}

type AquaGatewayInformation struct {
	Host string `json:"host"`
	Port int64  `json:"port"`
}

type AquaLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Host     string `json:"host"`
}

type AquaScannerCliScale struct {
	Max              int64 `json:"max"`
	Min              int64 `json:"min"`
	ImagesPerScanner int64 `json:"imagesPerScanner"`
}

type AquaEnforcerDetailes struct {
	Gateway     string `json:"gateway"`
	Name        string `json:"name"`
	EnforceMode bool   `json:"enforceMode"`
}

type AquaDeploymentState string

const (
	// AquaDeploymentStatePending Pending status when start to deploy aqua
	AquaDeploymentStatePending AquaDeploymentState = "Pending"

	// AquaDeploymentStateWaitingDB After creating aqua database waiting to done
	AquaDeploymentStateWaitingDB AquaDeploymentState = "Waiting For Aqua Database"

	// AquaDeploymentStateWaitingAqua After creating aqua server and gateway waiting to done
	AquaDeploymentStateWaitingAqua AquaDeploymentState = "Waiting For Aqua Server and Gateway"

	// AquaDeploymentStateRunning done
	AquaDeploymentStateRunning AquaDeploymentState = "Running"
)
