package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AquaDatabaseSpec defines the desired state of AquaDatabase
type AquaDatabaseSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Infrastructure *AquaInfrastructure `json:"infra"`
	Common         *AquaCommon         `json:"common"`
	DbService      *AquaService        `json:"deploy,required"`
	DiskSize       int                 `json:"diskSize,required"`
	RunAsNonRoot   bool                `json:"runAsNonRoot,omitempty"`
}

// AquaDatabaseStatus defines the observed state of AquaDatabase
type AquaDatabaseStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Nodes []string            `json:"nodes"`
	State AquaDeploymentState `json:"state"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaDatabase is the Schema for the aquadatabases API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=aquadatabases,scope=Namespaced
type AquaDatabase struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaDatabaseSpec   `json:"spec,omitempty"`
	Status AquaDatabaseStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaDatabaseList contains a list of AquaDatabase
type AquaDatabaseList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaDatabase `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaDatabase{}, &AquaDatabaseList{})
}
