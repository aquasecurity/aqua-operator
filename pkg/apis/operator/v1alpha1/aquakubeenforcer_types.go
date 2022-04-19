package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AquaKubeEnforcerSpec defines the desired state of AquaKubeEnforcer
type AquaKubeEnforcerSpec struct {
	Infrastructure         *AquaInfrastructure    `json:"infra,omitempty"`
	Config                 AquaKubeEnforcerConfig `json:"config"`
	Token                  string                 `json:"token,omitempty"`
	RegistryData           *AquaDockerRegistry    `json:"registry,omitempty"`
	ImageData              *AquaImage             `json:"image,omitempty"`
	EnforcerUpdateApproved *bool                  `json:"updateEnforcer,omitempty"`
	AllowAnyVersion        bool                   `json:"allowAnyVersion,omitempty"`
	KubeEnforcerService    *AquaService           `json:"deploy,omitempty"`
	Envs                   []corev1.EnvVar        `json:"env,omitempty"`
	Mtls                   bool                   `json:"mtls,omitempty"`
	DeployStarboard        *AquaStarboardDetails  `json:"starboard,omitempty"`
	ConfigMapChecksum      string                 `json:"config_map_checksum,omitempty"`
}

// AquaKubeEnforcerStatus defines the observed state of AquaKubeEnforcer
type AquaKubeEnforcerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	State AquaDeploymentState `json:"state"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaKubeEnforcer is the Schema for the aquakubeenforcers API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=aquakubeenforcers,scope=Namespaced
type AquaKubeEnforcer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaKubeEnforcerSpec   `json:"spec,omitempty"`
	Status AquaKubeEnforcerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaKubeEnforcerList contains a list of AquaKubeEnforcer
type AquaKubeEnforcerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaKubeEnforcer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaKubeEnforcer{}, &AquaKubeEnforcerList{})
}
