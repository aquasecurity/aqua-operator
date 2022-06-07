package common

import (
	"context"
	"fmt"
	"strings"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/serviceaccounts"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	rbacv1 "k8s.io/api/rbac/v1"
)

var log = logf.Log.WithName("RBAC logger")

type RbacParameters struct {
	Name      string
	Infra     *operatorv1alpha1.AquaInfrastructure
	Common    *operatorv1alpha1.AquaCommon
	Namespace string
	Client    client.Client
	Scheme    *runtime.Scheme
	Cr        metav1.Object
}

type AquaRbacHelper struct {
	Parameters RbacParameters
}

func NewAquaRbacHelper(infra *operatorv1alpha1.AquaInfrastructure,
	name, namespace string,
	common *operatorv1alpha1.AquaCommon,
	k8sclient client.Client,
	scheme *runtime.Scheme,
	cr metav1.Object) *AquaRbacHelper {
	params := RbacParameters{
		Name:      name,
		Infra:     infra,
		Common:    common,
		Namespace: namespace,
		Client:    k8sclient,
		Scheme:    scheme,
		Cr:        cr,
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

func (rb *AquaRbacHelper) CreateRBAC() (err error) {

	// Check if ServiceAccount exist -> if not, create
	if !serviceaccounts.CheckIfServiceAccountExists(rb.Parameters.Client, rb.Parameters.Infra.ServiceAccount, rb.Parameters.Namespace) {
		_, err = rb.CreateAquaServiceAccount()
		if err != nil {
			return err
		}
	}

	if strings.ToLower(rb.Parameters.Infra.Platform) == consts.OpenShiftPlatform &&
		rbac.CheckIfClusterRoleExists(rb.Parameters.Client, consts.ClusterReaderRole) &&
		!rbac.CheckIfClusterRoleBindingExists(rb.Parameters.Client, consts.AquaSAClusterReaderRoleBind) {

		// Create ClusterRoleBinding between aqua service account and ClusterReaderRole
		_, err = rb.CreateClusterReaderRoleBinding()
		if err != nil {
			return err
		}
	}

	// Check if Cluster role exist -> if not, create
	if !rbac.CheckIfClusterRoleExists(rb.Parameters.Client, fmt.Sprintf(consts.DiscoveryClusterRole, rb.Parameters.Name)) {
		_, err = rb.CreateClusterRole()
		if err != nil {
			return err
		}
	}

	// Check if Cluster role binding exist -> if not, create
	if !rbac.CheckIfClusterRoleBindingExists(rb.Parameters.Client, fmt.Sprintf(consts.DiscoveryClusterRoleBinding, rb.Parameters.Name)) {
		_, err = rb.CreateClusterRoleBinding()
		if err != nil {
			return err
		}
	}

	return nil
}

func (rb *AquaRbacHelper) CreateAquaServiceAccount() (reconcile.Result, error) {
	reqLogger := log.WithValues("RBAC", "Create Aqua Service Account")
	reqLogger.Info("Start creating aqua service account")

	if len(rb.Parameters.Common.ImagePullSecret) > 0 {
		foundSecret := &corev1.Secret{}
		err := rb.Parameters.Client.Get(context.TODO(), types.NamespacedName{Name: rb.Parameters.Common.ImagePullSecret, Namespace: rb.Parameters.Namespace}, foundSecret)
		if err != nil && errors.IsNotFound(err) {
			rb.Parameters.Common.ImagePullSecret = ""
		}
	}

	// Define a new service account object
	sa := serviceaccounts.CreateServiceAccount(rb.Parameters.Name,
		rb.Parameters.Namespace,
		fmt.Sprintf("%s-requirments", rb.Parameters.Name),
		rb.Parameters.Infra.ServiceAccount,
		rb.Parameters.Common.ImagePullSecret)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(rb.Parameters.Cr, sa, rb.Parameters.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this service account already exists
	found := &corev1.ServiceAccount{}
	err := rb.Parameters.Client.Get(context.TODO(), types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Service Account", "ServiceAccount.Namespace", sa.Namespace, "ServiceAccount.Name", sa.Name)
		err = rb.Parameters.Client.Create(context.TODO(), sa)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Service account already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Service Account Already Exists", "ServiceAccount.Namespace", found.Namespace, "ServiceAccount.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (rb *AquaRbacHelper) CreateClusterRole() (reconcile.Result, error) {
	reqLogger := log.WithValues("RBAC Phase", "Create ClusterRole")
	reqLogger.Info("Start creating ClusterRole")

	// Define a new ClusterRole object
	crole := rb.NewDiscoveryClusterRole(rb.Parameters.Name, rb.Parameters.Namespace)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(rb.Parameters.Cr, crole, rb.Parameters.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRole already exists
	found := &rbacv1.ClusterRole{}
	err := rb.Parameters.Client.Get(context.TODO(), types.NamespacedName{Name: crole.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ClusterRole", "ClusterRole.Namespace", crole.Namespace, "ClusterRole.Name", crole.Name)
		err = rb.Parameters.Client.Create(context.TODO(), crole)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// ClusterRole already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua ClusterRole Exists", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (rb *AquaRbacHelper) CreateClusterRoleBinding() (reconcile.Result, error) {
	reqLogger := log.WithValues("RBAC Phase", "Create ClusterRoleBinding")
	reqLogger.Info("Start creating ClusterRole")

	// Define a new ClusterRoleBinding object
	crb := rb.NewDiscoveryClusterRoleBinding(
		rb.Parameters.Name,
		rb.Parameters.Namespace,
		rb.Parameters.Infra.ServiceAccount)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(rb.Parameters.Cr, crb, rb.Parameters.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := rb.Parameters.Client.Get(context.TODO(), types.NamespacedName{Name: crb.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", crb.Namespace, "ClusterRoleBinding.Name", crb.Name)
		err = rb.Parameters.Client.Create(context.TODO(), crb)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// ClusterRoleBinding already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua ClusterRoleBinding Exists", "ClusterRoleBinding.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (rb *AquaRbacHelper) CreateClusterReaderRoleBinding() (reconcile.Result, error) {
	reqLogger := log.WithValues("RBAC Phase", "Create ClusterReaderRoleBinding")
	reqLogger.Info("Start creating ClusterReaderRoleBinding")

	crb := rbac.CreateClusterRoleBinding(
		rb.Parameters.Name,
		rb.Parameters.Namespace,
		consts.AquaSAClusterReaderRoleBind,
		fmt.Sprintf("%s-cluster-reader", rb.Parameters.Name),
		"Deploy Aqua Cluster Reader Role Binding",
		rb.Parameters.Infra.ServiceAccount,
		consts.ClusterReaderRole)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(rb.Parameters.Cr, crb, rb.Parameters.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := rb.Parameters.Client.Get(context.TODO(), types.NamespacedName{Name: crb.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ClusterReaderRoleBinding", "ClusterReaderRoleBinding.Namespace", crb.Namespace, "ClusterReaderRoleBinding.Name", crb.Name)
		err = rb.Parameters.Client.Create(context.TODO(), crb)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// ClusterRoleBinding already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua ClusterReaderRoleBinding Exists", "ClusterRoleBinding.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}
