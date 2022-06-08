package secrets

import (
	"context"
	"encoding/json"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckIfSecretExists Check if secret exists in namespace
func CheckIfSecretExists(k8sclient client.Client, name, namespace string) bool {
	exist := true

	found := &corev1.Secret{}
	err := k8sclient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		exist = false
	}

	return exist
}

// CreateSecret Create new secret
func CreateSecret(cr, namespace, app, description, name, key, value string) *corev1.Secret {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": description,
	}
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			key: []byte(value),
		},
	}

	return secret
}

// createPullImageSecret Create pull image secret
func CreatePullImageSecret(cr, namespace, app, name string, registry operatorv1alpha1.AquaDockerRegistry) *corev1.Secret {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Secret for pulling aqua images",
	}
	auth := map[string]interface{}{
		"auths": map[string]interface{}{
			registry.URL: map[string]interface{}{
				"username": registry.Username,
				"password": registry.Password,
				"email":    registry.Email,
			},
		},
	}

	authBytes, _ := json.Marshal(auth)

	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "Secret",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: authBytes,
		},
	}

	return secret
}
