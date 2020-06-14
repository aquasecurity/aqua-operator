package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AquaEnforcerSpec defines the desired state of AquaEnforcer
type AquaEnforcerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Infrastructure *AquaInfrastructure `json:"infra"`
	Common         *AquaCommon         `json:"common"`

	EnforcerService *AquaService            `json:"deploy,required"`
	Gateway         *AquaGatewayInformation `json:"gateway,required"`
	Token           string                  `json:"token,required"`
	Secret          *AquaSecret             `json:"secret,required"`
	Envs            []corev1.EnvVar         `json:"env,required"`
	RunAsNonRoot    bool                    `json:"runAsNonRoot,omitempty"`
}

// AquaEnforcerStatus defines the observed state of AquaEnforcer
type AquaEnforcerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	State AquaDeploymentState `json:"state"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaEnforcer is the Schema for the aquaenforcers API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=aquaenforcers,scope=Namespaced
type AquaEnforcer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaEnforcerSpec   `json:"spec,omitempty"`
	Status AquaEnforcerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaEnforcerList contains a list of AquaEnforcer
type AquaEnforcerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaEnforcer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaEnforcer{}, &AquaEnforcerList{})
}
