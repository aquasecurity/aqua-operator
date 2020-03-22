package serviceaccounts

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckIfServiceAccountExists Check if secret exists in namespace
func CheckIfServiceAccountExists(k8sclient client.Client, name, namespace string) bool {
	exist := true

	found := &corev1.ServiceAccount{}
	err := k8sclient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		exist = false
	}

	return exist
}

// CreateServiceAccount Create new service account
func CreateServiceAccount(cr, namespace, app, name, pullImageSecret string) *corev1.ServiceAccount {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Service account for aqua",
	}
	sa := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
	}

	if len(pullImageSecret) > 0 {
		sa.ImagePullSecrets = []corev1.LocalObjectReference{
			corev1.LocalObjectReference{
				Name: pullImageSecret,
			},
		}
	}

	return sa
}
