package aquacsp

import (
	"context"
	"fmt"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/serviceaccounts"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

/*	----------------------------------------------------------------------------------------------------------------
							Requirments
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaCsp) CreateImagePullSecret(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("Csp Requirments Phase", "Create Image Pull Secret")
	reqLogger.Info("Start creating aqua images pull secret")

	// Define a new secret object
	secret := secrets.CreatePullImageSecret(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		fmt.Sprintf(consts.PullImageSecretName, cr.Name),
		*cr.Spec.RegistryData)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, secret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this secret already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Image Pull Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.client.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Secret already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Image Pull Secret Already Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaCsp) CreateDbPasswordSecret(cr *operatorv1alpha1.AquaCsp, password string) (reconcile.Result, error) {
	reqLogger := log.WithValues("Csp Requirments Phase", "Create Db Password Secret")
	reqLogger.Info("Start creating aqua db password secret")

	// Define a new secret object
	secret := secrets.CreateSecret(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		"Secret for aqua database password",
		fmt.Sprintf(consts.ScalockDbPasswordSecretName, cr.Name),
		consts.ScalockDbPasswordSecretKey,
		password)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, secret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this secret already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Db Password Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.client.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Secret already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Db Password Secret Already Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaCsp) CreateAquaServiceAccount(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("Csp Requirments Phase", "Create Aqua Service Account")
	reqLogger.Info("Start creating aqua service account")

	if len(cr.Spec.Common.ImagePullSecret) > 0 {
		foundSecret := &corev1.Secret{}
		err := r.client.Get(context.TODO(), types.NamespacedName{Name: cr.Spec.Common.ImagePullSecret, Namespace: cr.Namespace}, foundSecret)
		if err != nil && errors.IsNotFound(err) {
			cr.Spec.Common.ImagePullSecret = ""
		}
	}

	// Define a new service account object
	sa := serviceaccounts.CreateServiceAccount(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		cr.Spec.Infrastructure.ServiceAccount,
		cr.Spec.Common.ImagePullSecret)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, sa, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this service account already exists
	found := &corev1.ServiceAccount{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Service Account", "ServiceAccount.Namespace", sa.Namespace, "ServiceAccount.Name", sa.Name)
		err = r.client.Create(context.TODO(), sa)
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
