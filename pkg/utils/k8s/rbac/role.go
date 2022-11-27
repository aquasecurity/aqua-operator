package rbac

import (
	"context"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CheckIfRoleExists Check if role exists in namespace
func CheckIfRoleExists(k8sclient client.Client, name string) bool {
	exist := true

	found := &rbacv1.Role{}
	err := k8sclient.Get(context.TODO(), types.NamespacedName{Name: name}, found)
	if err != nil && errors.IsNotFound(err) {
		exist = false
	}

	return exist
}

// CreateRole Create role
func CreateRole(r, namespace, name, app, description string, rules []rbacv1.PolicyRule) *rbacv1.Role {
	labels := map[string]string{
		"app":               app,
		"deployedby":        "aqua-operator",
		"aquasecoperator_r": r,
	}
	annotations := map[string]string{
		"description":              description,
		"openshift.io/description": "A user who can search and scan images from an OpenShift integrated registry.",
	}
	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Rules: rules,
	}

	return role
}
