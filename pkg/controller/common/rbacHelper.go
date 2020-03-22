package common

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	rbacv1 "k8s.io/api/rbac/v1"
)

type RbacParameters struct {
	Name  string
	Infra *operatorv1alpha1.AquaInfrastructure
}

type AquaRbacHelper struct {
	Parameters RbacParameters
}

func NewAquaRbacHelper(infra *operatorv1alpha1.AquaInfrastructure, name string) *AquaRbacHelper {
	params := RbacParameters{
		Name:  name,
		Infra: infra,
	}

	return &AquaRbacHelper{
		Parameters: params,
	}
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua RBAC
	----------------------------------------------------------------------------------------------------------------
*/

func (rb *AquaRbacHelper) NewDiscoveryClusterRole(cr, namespace string) *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"nodes", "services", "endpoints", "pods", "deployments", "namespaces", "componentstatuses",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"rbac.authorization.k8s.io",
			},
			Resources: []string{
				"*",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
	}

	if strings.ToLower(rb.Parameters.Infra.Platform) == "openshift" {
		rule := rbacv1.PolicyRule{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"imagestreams",
				"imagestreams/layers",
			},
			Verbs: []string{
				"get",
				"list",
				"watch",
			},
		}
		rules = append(rules, rule)
	}

	crole := rbac.CreateClusterRole(cr, namespace, fmt.Sprintf(consts.DiscoveryClusterRole, cr), fmt.Sprintf("%s-rbac", cr), "Deploy Aqua Discovery Cluster Role", rules)

	return crole
}

func (rb *AquaRbacHelper) NewDiscoveryClusterRoleBinding(cr, namespace, sa string) *rbacv1.ClusterRoleBinding {
	crb := rbac.CreateClusterRoleBinding(cr,
		namespace,
		fmt.Sprintf(consts.DiscoveryClusterRoleBinding, cr),
		fmt.Sprintf("%s-rbac", cr),
		"Deploy Aqua Discovery Cluster Role Binding",
		sa,
		fmt.Sprintf(consts.DiscoveryClusterRole, cr))

	return crb
}
