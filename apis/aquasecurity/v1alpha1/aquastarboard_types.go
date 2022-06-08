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
	"github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AquaStarboardSpec defines the desired state of AquaStarboard
type AquaStarboardSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Infrastructure                *v1alpha1.AquaInfrastructure `json:"infra,omitempty"`
	AllowAnyVersion               bool                         `json:"allowAnyVersion,omitempty"`
	StarboardService              *v1alpha1.AquaService        `json:"deploy,required"`
	Config                        v1alpha1.AquaStarboardConfig `json:"config"`
	RegistryData                  *v1alpha1.AquaDockerRegistry `json:"registry,omitempty"`
	ImageData                     *v1alpha1.AquaImage          `json:"image,omitempty"`
	Envs                          []corev1.EnvVar              `json:"env,omitempty"`
	KubeEnforcerVersion           string                       `json:"kube_enforcer_version,omitempty"`
	LogDevMode                    bool                         `json:"logDevMode,omitempty"`
	ConcurrentScanJobsLimit       string                       `json:"concurrentScanJobsLimit,omitempty"`
	ScanJobRetryAfter             string                       `json:"scanJobRetryAfter,omitempty"`
	MetricsBindAddress            string                       `json:"metricsBindAddress,omitempty"`
	HealthProbeBindAddress        string                       `json:"healthProbeBindAddress,omitempty"`
	CisKubernetesBenchmarkEnabled string                       `json:"cisKubernetesBenchmarkEnabled,omitempty"`
	VulnerabilityScannerEnabled   string                       `json:"vulnerabilityScannerEnabled,omitempty"`
	BatchDeleteLimit              string                       `json:"batchDeleteLimit,omitempty"`
	BatchDeleteDelay              string                       `json:"batchDeleteDelay,omitempty"`
	ConfigMapChecksum             string                       `json:"config_map_checksum,omitempty"`
}

// AquaStarboardStatus defines the observed state of AquaStarboard
type AquaStarboardStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Nodes []string                     `json:"nodes"`
	State v1alpha1.AquaDeploymentState `json:"state"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Replicas",type="integer",JSONPath=".spec.deploy.replicas",description="Replicas Number"
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath="..metadata.creationTimestamp",description="Aqua Starboard Age"
//+kubebuilder:printcolumn:name="Status",type="string",JSONPath=".status.state",description="Aqua Starboard status"
//+kubebuilder:printcolumn:name="Nodes",type="string",JSONPath=".status.nodes",description="List Of Nodes (Pods)"

// AquaStarboard is the Schema for the aquastarboards API
type AquaStarboard struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AquaStarboardSpec   `json:"spec,omitempty"`
	Status AquaStarboardStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AquaStarboardList contains a list of AquaStarboard
type AquaStarboardList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AquaStarboard `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AquaStarboard{}, &AquaStarboardList{})
}
