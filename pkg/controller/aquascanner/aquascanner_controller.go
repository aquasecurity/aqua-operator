package aquascanner

import (
	"context"
	"reflect"

	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/controller/common"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	appsv1 "k8s.io/api/apps/v1"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
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

var log = logf.Log.WithName("controller_aquascanner")

// Add creates a new AquaScanner Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaScanner{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("aquascanner-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaScanner
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaScanner{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaScanner{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaScanner{},
	})
	if err != nil {
		return err
	}

	// AquaScanner

	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaScanner{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileAquaScanner implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaScanner{}

// ReconcileAquaScanner reconciles a AquaScanner object
type ReconcileAquaScanner struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaScanner) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaScanner")

	// Fetch the AquaScanner instance
	instance := &operatorv1alpha1.AquaScanner{}
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

	instance = r.updateScannerObject(instance)

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	if instance.Spec.ScannerService != nil {
		_, err = r.InstallScannerDeployment(instance)
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
func (r *ReconcileAquaScanner) updateScannerObject(cr *operatorv1alpha1.AquaScanner) *operatorv1alpha1.AquaScanner {
	version := cr.Spec.Infrastructure.Version
	if len(version) == 0 {
		version = consts.LatestVersion
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

func (r *ReconcileAquaScanner) InstallScannerDeployment(cr *operatorv1alpha1.AquaScanner) (reconcile.Result, error) {
	reqLogger := log.WithValues("Scanner Aqua Phase", "Install Scanner Deployment")
	reqLogger.Info("Start installing aqua scanner cli deployment")

	// Define a new deployment object
	scannerHelper := newAquaScannerHelper(cr)
	deployment := scannerHelper.newDeployment(cr)

	// Set AquaScanner instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this deployment already exists
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Scanner Deployment", "Dervice.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		err = r.client.Create(context.TODO(), deployment)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	if found != nil {
		size := deployment.Spec.Replicas
		if *found.Spec.Replicas != *size {
			found.Spec.Replicas = size
			err = r.client.Status().Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua Scanner: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		}

		podList := &corev1.PodList{}
		labelSelector := labels.SelectorFromSet(found.Labels)
		listOps := &client.ListOptions{
			Namespace:     deployment.Namespace,
			LabelSelector: labelSelector,
		}
		err = r.client.List(context.TODO(), podList, listOps)
		if err != nil {
			reqLogger.Error(err, "Aqua Scanner: Failed to list pods.", "AquaScanner.Namespace", cr.Namespace, "AquaScanner.Name", cr.Name)
			return reconcile.Result{}, err
		}
		podNames := k8s.PodNames(podList.Items)

		// Update status.Nodes if needed
		if !reflect.DeepEqual(podNames, cr.Status.Nodes) {
			cr.Status.Nodes = podNames
			err := r.client.Status().Update(context.Background(), cr)
			if err != nil {
				return reconcile.Result{}, err
			}
		}
	}

	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Scanner Deployment Already Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}
