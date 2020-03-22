package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AquaScannerSpec defines the desired state of AquaScanner
type AquaScannerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Infrastructure *AquaInfrastructure `json:"infra"`
	Common         *AquaCommon         `json:"common"`

	ScannerService *AquaService `json:"deploy,required"`
	Login          *AquaLogin   `json:"login,required"`
}

// AquaScannerStatus defines the observed state of AquaScanner
type AquaScannerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Nodes []string            `json:"nodes"`
	State AquaDeploymentState `json:"state"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaScanner is the Schema for the aquascanners API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=aquascanners,scope=Namespaced
type AquaScanner struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaScannerSpec   `json:"spec,omitempty"`
	Status AquaScannerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaScannerList contains a list of AquaScanner
type AquaScannerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaScanner `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaScanner{}, &AquaScannerList{})
}
