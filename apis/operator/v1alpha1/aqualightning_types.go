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

// AquaLightningSpec defines the desired state of AquaLightning
type AquaLightningSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Common       *AquaCommon                `json:"common"`
	Global       *AquaLightningGlobal       `json:"global"`
	KubeEnforcer *AquaLightningKubeEnforcer `json:"kubeEnforcer"`
	Enforcer     *AquaLightningEnforcer     `json:"enforcer"`
}

type AquaLightningGlobal struct {
	GatewayAddress string `json:"gateway_address,omitempty"`
	ClusterName    string `json:"cluster_name,omitempty"`
}

type AquaLightningKubeEnforcer struct {
	Infrastructure         *AquaInfrastructure   `json:"infra,omitempty"`
	Token                  string                `json:"token,omitempty"`
	RegistryData           *AquaDockerRegistry   `json:"registry,omitempty"`
	ImageData              *AquaImage            `json:"image,omitempty"`
	EnforcerUpdateApproved *bool                 `json:"updateEnforcer,omitempty"`
	AllowAnyVersion        bool                  `json:"allowAnyVersion,omitempty"`
	KubeEnforcerService    *AquaService          `json:"deploy,omitempty"`
	Envs                   []corev1.EnvVar       `json:"env,omitempty"`
	Mtls                   bool                  `json:"mtls,omitempty"`
	DeployStarboard        *AquaStarboardDetails `json:"starboard,omitempty"`
	ConfigMapChecksum      string                `json:"config_map_checksum,omitempty"`
}

type AquaLightningEnforcer struct {
	Infrastructure         *AquaInfrastructure `json:"infra"`
	EnforcerService        *AquaService        `json:"deploy,required"`
	Token                  string              `json:"token,omitempty"`
	Secret                 *AquaSecret         `json:"secret,omitempty"`
	Envs                   []corev1.EnvVar     `json:"env,omitempty"`
	RunAsNonRoot           bool                `json:"runAsNonRoot,omitempty"`
	EnforcerUpdateApproved *bool               `json:"updateEnforcer,omitempty"`
	Mtls                   bool                `json:"mtls,omitempty"`
	ConfigMapChecksum      string              `json:"config_map_checksum,omitempty"`
	AquaExpressMode        bool                `json:"aqua_express_mode,omitempty"`
	RhcosVersion           string              `json:"rhcosVersion,omitempty"`
}

// AquaLightningStatus defines the observed state of AquaLightning
type AquaLightningStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	State AquaDeploymentState `json:"state"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath="..metadata.creationTimestamp",description="Aqua Lightning Age"
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state",description="Aqua Lightning status"

// AquaLightning is the Schema for the aquaLightnings API
type AquaLightning struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaLightningSpec   `json:"spec,omitempty"`
	Status AquaLightningStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AquaLightningList contains a list of AquaLightning
type AquaLightningList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaLightning `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaLightning{}, &AquaLightningList{})
}
