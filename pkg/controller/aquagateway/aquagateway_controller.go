package aquagateway

import (
	"context"
	"reflect"
	"time"

	"github.com/aquasecurity/aqua-operator/pkg/controller/common"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"
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

var log = logf.Log.WithName("controller_aquagateway")

// Add creates a new AquaGateway Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaGateway{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("aquagateway-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaGateway
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaGateway{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaGateway{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaGateway{},
	})
	if err != nil {
		return err
	}

	// AquaGateway Components

	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaGateway{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaGateway{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileAquaGateway implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaGateway{}

// ReconcileAquaGateway reconciles a AquaGateway object
type ReconcileAquaGateway struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaGateway) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaGateway")

	// Fetch the AquaGateway instance
	instance := &operatorv1alpha1.AquaGateway{}
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

	instance = r.updateGatewayObject(instance)

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	if instance.Spec.GatewayService != nil {
		reqLogger.Info("Start Setup Aqua Gateway")
		_, err = r.InstallGatewayService(instance)
		if err != nil {
			return reconcile.Result{}, err
		}

		_, err = r.InstallGatewayDeployment(instance)
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

func (r *ReconcileAquaGateway) updateGatewayObject(cr *operatorv1alpha1.AquaGateway) *operatorv1alpha1.AquaGateway {
	cr.Spec.Infrastructure = common.UpdateAquaInfrastructure(cr.Spec.Infrastructure, cr.Name, cr.Namespace)
	cr.Spec.Common = common.UpdateAquaCommon(cr.Spec.Common, cr.Name, false, false)

	return cr
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Gateway
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaGateway) InstallGatewayService(cr *operatorv1alpha1.AquaGateway) (reconcile.Result, error) {
	reqLogger := log.WithValues("Gateway Aqua Phase", "Install Gateway Service")
	reqLogger.Info("Start installing aqua gateway service")

	// Define a new Service object
	gatewayHelper := newAquaGatewayHelper(cr)
	service := gatewayHelper.newService(cr)

	// Set AquaGateway instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, service, r.scheme); err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	// Check if this service already exists
	found := &corev1.Service{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: service.Name, Namespace: service.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Gateway Service", "Service.Namespace", service.Namespace, "Service.Name", service.Name)
		err = r.client.Create(context.TODO(), service)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	// Service already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Gateway Service Already Exists", "Service.Namespace", found.Namespace, "Service.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *ReconcileAquaGateway) InstallGatewayDeployment(cr *operatorv1alpha1.AquaGateway) (reconcile.Result, error) {
	reqLogger := log.WithValues("Gateway Aqua Phase", "Install Database Deployment")
	reqLogger.Info("Start installing aqua gateway deployment")

	// Define a new deployment object
	gatewayHelper := newAquaGatewayHelper(cr)
	deployment := gatewayHelper.newDeployment(cr)

	// Set AquaGateway instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.scheme); err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	// Check if this deployment already exists
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Gateway Deployment", "Dervice.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		err = r.client.Create(context.TODO(), deployment)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	if found != nil {
		size := deployment.Spec.Replicas
		if *found.Spec.Replicas != *size {
			found.Spec.Replicas = size
			err = r.client.Status().Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua Gateway: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}

		podList := &corev1.PodList{}
		labelSelector := labels.SelectorFromSet(found.Labels)
		listOps := &client.ListOptions{
			Namespace:     deployment.Namespace,
			LabelSelector: labelSelector,
		}

		err = r.client.List(context.TODO(), podList, listOps)
		if err != nil {
			reqLogger.Error(err, "Aqua Gateway: Failed to list pods.", "AquaGateway.Namespace", cr.Namespace, "AquaDatabase.Name", cr.Name)
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}
		podNames := k8s.PodNames(podList.Items)

		// Update status.Nodes if needed
		if !reflect.DeepEqual(podNames, cr.Status.Nodes) {
			cr.Status.Nodes = podNames
			err := r.client.Status().Update(context.Background(), cr)
			if err != nil {
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		}
	}

	// Deployment already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Gateway Deployment Already Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}
