package aquaenforcer

import (
	"context"
	"fmt"
	"reflect"

	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/controller/common"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	syserrors "errors"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

var log = logf.Log.WithName("controller_aquaenforcer")

// Add creates a new AquaEnforcer Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaEnforcer{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("aquaenforcer-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaEnforcer
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaEnforcer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaEnforcer{},
	})
	if err != nil {
		return err
	}

	// AquaEnforcer Components

	err = c.Watch(&source.Kind{Type: &appsv1.DaemonSet{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaEnforcer{},
	})
	if err != nil {
		return err
	}

	// RBAC

	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRole{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRoleBinding{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaEnforcer{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileAquaEnforcer implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaEnforcer{}

// ReconcileAquaEnforcer reconciles a AquaEnforcer object
type ReconcileAquaEnforcer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaEnforcer) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaEnforcer")

	// Fetch the AquaEnforcer instance
	instance := &operatorv1alpha1.AquaEnforcer{}
	err := r.client.Get(context.TODO(), request.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, err
	}

	instance = r.updateEnforcerObject(instance)

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	if instance.Spec.EnforcerService != nil {
		if len(instance.Spec.Token) != 0 {
			instance.Spec.Secret = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.EnforcerTokenSecretName, instance.Name),
				Key:  consts.EnforcerTokenSecretKey,
			}

			_, err = r.InstallEnforcerToken(instance)
			if err != nil {
				return reconcile.Result{}, err
			}
		} else if instance.Spec.Secret == nil {
			reqLogger.Error(syserrors.New("You must specifie the enforcer token or the token secret name and key"), "Missing enforcer token")
		} else {
			exists := secrets.CheckIfSecretExists(r.client, instance.Spec.Secret.Name, instance.Namespace)
			if !exists {
				reqLogger.Error(syserrors.New("You must specifie the enforcer token or the token secret name and key"), "Missing enforcer token")

			}
		}

		_, err = r.InstallEnforcerDaemonSet(instance)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStateRunning
		_ = r.client.Status().Update(context.Background(), instance)
	}

	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaEnforcer) updateEnforcerObject(cr *operatorv1alpha1.AquaEnforcer) *operatorv1alpha1.AquaEnforcer {
	version := cr.Spec.Infrastructure.Version
	if len(version) == 0 {
		version = consts.LatestVersion
	}

	if cr.Spec.EnforcerService == nil {
		cr.Spec.EnforcerService = &operatorv1alpha1.AquaService{
			ImageData: &operatorv1alpha1.AquaImage{
				Repository: "enforcer",
				Registry:   consts.Registry,
				Tag:        version,
				PullPolicy: consts.PullPolicy,
			},
		}
	}

	cr.Spec.Infrastructure = common.UpdateAquaInfrastructure(cr.Spec.Infrastructure, cr.Name, cr.Namespace)
	cr.Spec.Common = common.UpdateAquaCommon(cr.Spec.Common, cr.Name, false, false)

	if cr.Spec.Common != nil {
		if len(cr.Spec.Common.ImagePullSecret) != 0 {
			exist := secrets.CheckIfSecretExists(r.client, cr.Name, cr.Namespace)
			if !exist {
				cr.Spec.Common.ImagePullSecret = consts.EmptyString
			}
		}
	}

	return cr
}

func (r *ReconcileAquaEnforcer) InstallEnforcerDaemonSet(cr *operatorv1alpha1.AquaEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Aqua Enforcer DaemonSet Phase", "Install Aqua Enforcer DaemonSet")
	reqLogger.Info("Start installing enforcer")

	// Define a new DaemonSet object
	enforcerHelper := newAquaEnforcerHelper(cr)
	ds := enforcerHelper.CreateDaemonSet(cr)

	// Set AquaEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, ds, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this DaemonSet already exists
	found := &appsv1.DaemonSet{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: ds.Name, Namespace: ds.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Database", "DaemonSet.Namespace", ds.Namespace, "DaemonSet.Name", ds.Name)
		err = r.client.Create(context.TODO(), ds)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// DaemonSet already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Enforcer DaemonSet Already Exists", "DaemonSet.Namespace", found.Namespace, "DaemonSet.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaEnforcer) InstallEnforcerToken(cr *operatorv1alpha1.AquaEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Aqua Enforcer Phase", "Create Aqua Enforcer Token Secret")
	reqLogger.Info("Start creating enforcer token secret")

	// Define a new DaemonSet object
	enforcerHelper := newAquaEnforcerHelper(cr)
	token := enforcerHelper.CreateTokenSecret(cr)

	// Set AquaEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, token, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this DaemonSet already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: token.Name, Namespace: token.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Database", "Secret.Namespace", token.Namespace, "Secret.Name", token.Name)
		err = r.client.Create(context.TODO(), token)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Secret already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Enforcer Token Secret Already Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}
