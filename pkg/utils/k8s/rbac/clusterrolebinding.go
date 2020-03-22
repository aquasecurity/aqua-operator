package rbac

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckIfClusterRoleBindingExists Check if cluster role binding exists in namespace
func CheckIfClusterRoleBindingExists(k8sclient client.Client, name, namespace string) bool {
	exist := true

	found := &rbacv1.ClusterRoleBinding{}
	err := k8sclient.Get(context.TODO(), types.NamespacedName{Name: name, Namespace: namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		exist = false
	}

	return exist
}

// CreateClusterRoleBinding Creaye cluster role binding
func CreateClusterRoleBinding(cr, namespace, name, app, description, sa, clusterrole string) *rbacv1.ClusterRoleBinding {
	labels := map[string]string{
		"app":                app,
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Cluster Role Binding",
	}
	crb := &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      sa,
				Namespace: namespace,
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterrole,
		},
	}

	return crb
}
