package services

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckIfServiceExists Check if service exists in namespace
func CheckIfServiceExists(k8sclient client.Client, name, namespace string) bool {
	exist := true

	found := &corev1.Service{}
	err := k8sclient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		exist = false
	}

	return exist
}

// CreateService Create service
func CreateService(cr, namespace, name, app, description, servicetype string,
	selectors map[string]string,
	ports []corev1.ServicePort) *corev1.Service {
	serviceType := "ClusterIP"
	if len(servicetype) != 0 {
		serviceType = servicetype
	}

	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": description,
	}

	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "Service",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceType(serviceType),
			Selector: selectors,
			Ports:    ports,
		},
	}

	return service
}
