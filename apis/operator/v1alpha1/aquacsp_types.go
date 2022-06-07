/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
	// Important: Run "make" to regenerate code after modifying this file

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
	ServerConfigMapData    map[string]string        `json:"serverConfigMapData,omitempty"`
	DeployKubeEnforcer     *AquaKubeEnforcerDetails `json:"kubeEnforcer,omitempty"`
	EnforcerUpdateApproved *bool                    `json:"updateEnforcer,omitempty"`
	Mtls                   bool                     `json:"mtls,omitempty"`
}

// AquaCspStatus defines the observed state of AquaCsp
type AquaCspStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Phase string              `json:"phase"`
	State AquaDeploymentState `json:"state"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath="..metadata.creationTimestamp",description="Aqua Csp Age"
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state",description="Aqua Csp status"

// AquaCsp is the Schema for the aquacsps API
type AquaCsp struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaCspSpec   `json:"spec,omitempty"`
	Status AquaCspStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AquaCspList contains a list of AquaCsp
type AquaCspList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaCsp `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaCsp{}, &AquaCspList{})
}
