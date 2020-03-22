package rbac

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckIfClusterRoleExists Check if cluster role exists in namespace
func CheckIfClusterRoleExists(k8sclient client.Client, name, namespace string) bool {
	exist := true

	found := &rbacv1.ClusterRole{}
	err := k8sclient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		exist = false
	}

	return exist
}

// CreateClusterRole Create cluster rule
func CreateClusterRole(cr, namespace, name, app, description string, rules []rbacv1.PolicyRule) *rbacv1.ClusterRole {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description":              description,
		"openshift.io/description": "A user who can search and scan images from an OpenShift integrated registry.",
	}
	crole := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Rules: rules,
	}

	return crole
}
