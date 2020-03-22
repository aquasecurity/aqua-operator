package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AquaServerSpec defines the desired state of AquaServer
type AquaServerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Infrastructure *AquaInfrastructure `json:"infra"`
	Common         *AquaCommon         `json:"common"`

	ServerService *AquaService             `json:"deploy,required"`
	ExternalDb    *AquaDatabaseInformation `json:"externalDb,omitempty"`
	LicenseToken  string                   `json:"licenseToken,omitempty"`
	AdminPassword string                   `json:"adminPassword,omitempty"`
}

// AquaServerStatus defines the observed state of AquaServer
type AquaServerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "operator-sdk generate k8s" to regenerate code after modifying this file
	// Add custom validation using kubebuilder tags: https://book-v1.book.kubebuilder.io/beyond_basics/generating_crd.html
	Nodes []string            `json:"nodes"`
	State AquaDeploymentState `json:"state"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaServer is the Schema for the aquaservers API
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=aquaservers,scope=Namespaced
type AquaServer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaServerSpec   `json:"spec,omitempty"`
	Status AquaServerStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AquaServerList contains a list of AquaServer
type AquaServerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaServer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaServer{}, &AquaServerList{})
}
