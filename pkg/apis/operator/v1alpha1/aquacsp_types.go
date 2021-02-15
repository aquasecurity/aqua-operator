package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AquaCspSpec defines the desired state of AquaCsp
type AquaCspSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Infrastructure *AquaInfrastructure `json:"infra,omitempty"`
	Common         *AquaCommon         `json:"common,omitempty"`

	RegistryData *AquaDockerRegistry      `json:"registry,omitempty"`
	ExternalDb   *AquaDatabaseInformation `json:"externalDb,omitempty"`
	AuditDB      *AuditDBInformation      `json:"auditDB,omitempty"`

	DbService      *AquaService `json:"database,omitempty"`
	GatewayService *AquaService `json:"gateway,required"`
	ServerService  *AquaService `json:"server,required"`

	LicenseToken           string                   `json:"licenseToken,omitempty"`
	AdminPassword          string                   `json:"adminPassword,omitempty"`
	Enforcer               *AquaEnforcerDetailes    `json:"enforcer,omitempty"`
	Route                  bool                     `json:"route,omitempty"`
	RunAsNonRoot           bool                     `json:"runAsNonRoot,omitempty"`
	ServerEnvs             []corev1.EnvVar          `json:"serverEnvs,required"`
	GatewayEnvs            []corev1.EnvVar          `json:"gatewayEnvs,required"`
	DeployKubeEnforcer     *AquaKubeEnforcerDetails `json:"kubeEnforcer",omitempty`
	EnforcerUpdateApproved *bool                    `json:"updateEnforcer, omitempty"`
}

// AquaCspStatus defines the observed state of AquaCsp
type AquaCspStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Phase string              `json:"phase"`
	State AquaDeploymentState `json:"state"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaCsp is the Schema for the aquacsps API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=aquacsps,scope=Namespaced
type AquaCsp struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaCspSpec   `json:"spec,omitempty"`
	Status AquaCspStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaCspList contains a list of AquaCsp
type AquaCspList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaCsp `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaCsp{}, &AquaCspList{})
}
