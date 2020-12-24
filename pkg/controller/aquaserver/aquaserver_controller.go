package aquaserver

import (
	"context"
	syserrors "errors"
	"fmt"
	"reflect"

	"github.com/aquasecurity/aqua-operator/pkg/controller/common"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
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

var log = logf.Log.WithName("controller_aquaserver")

// Add creates a new AquaServer Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaServer{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("aquaserver-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaServer
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaServer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaServer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaServer{},
	})
	if err != nil {
		return err
	}

	// AquaServer Components

	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaServer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaServer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.PersistentVolumeClaim{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaDatabase{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileAquaServer implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaServer{}

// ReconcileAquaServer reconciles a AquaServer object
type ReconcileAquaServer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaServer) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaServer")

	// Fetch the AquaServer instance
	instance := &operatorv1alpha1.AquaServer{}
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

	instance = r.updateServerObject(instance)

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	if instance.Spec.ServerService != nil {
		reqLogger.Info("Start Setup Aqua Server")
		_, err = r.InstallServerService(instance)
		if err != nil {
			return reconcile.Result{}, err
		}

		if len(instance.Spec.AdminPassword) > 0 {
			reqLogger.Info("Start Creating Admin Password Secret")
			_, err = r.CreateAdminPasswordSecret(instance)
			if err != nil {
				return reconcile.Result{}, err
			}
		} else {
			if instance.Spec.Common.AdminPassword != nil {
				exists := secrets.CheckIfSecretExists(r.client, instance.Spec.Common.AdminPassword.Name, instance.Namespace)
				if !exists {
					reqLogger.Error(syserrors.New("Admin password secret that mentioned in common section don't exists"), "Please create first or pass the password")
				}
			}
		}

		if len(instance.Spec.LicenseToken) > 0 {
			reqLogger.Info("Start Creating License Token Secret")
			_, err = r.CreateLicenseSecret(instance)
			if err != nil {
				return reconcile.Result{}, err
			}
		} else {
			if instance.Spec.Common.AquaLicense != nil {
				exists := secrets.CheckIfSecretExists(r.client, instance.Spec.Common.AquaLicense.Name, instance.Namespace)
				if !exists {
					reqLogger.Error(syserrors.New("Aqua license secret that mentioned in common section don't exists"), "Please create first or pass the license")
				}
			}
		}

		if instance.Spec.Enforcer != nil {
			reqLogger.Info("Start Setup Aqua Enforcer Token Secret")
			_, err = r.CreateEnforcerToken(instance)
			if err != nil {
				return reconcile.Result{}, err
			}
		}

		reqLogger.Info("Start Creating Aqua Server Deployment...")
		_, err = r.InstallServerDeployment(instance)
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

func (r *ReconcileAquaServer) updateServerObject(cr *operatorv1alpha1.AquaServer) *operatorv1alpha1.AquaServer {
	admin := false
	license := false

	if len(cr.Spec.AdminPassword) != 0 {
		admin = true
	}

	if len(cr.Spec.LicenseToken) != 0 {
		license = true
	}

	cr.Spec.Infrastructure = common.UpdateAquaInfrastructure(cr.Spec.Infrastructure, cr.Name, cr.Namespace)
	cr.Spec.Common = common.UpdateAquaCommon(cr.Spec.Common, cr.Name, admin, license)

	if cr.Spec.Enforcer != nil {
		if len(cr.Spec.Enforcer.Name) == 0 {
			cr.Spec.Enforcer.Name = "operator-default"
		}

		if len(cr.Spec.Enforcer.Gateway) == 0 {
			cr.Spec.Enforcer.Gateway = fmt.Sprintf("%s-gateway", cr.Name)
		}
	}

	return cr
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Server
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaServer) InstallServerService(cr *operatorv1alpha1.AquaServer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Server Aqua Phase", "Install Server Service")
	reqLogger.Info("Start installing aqua server service")

	// Define a new Service object
	serverHelper := newAquaServerHelper(cr)
	service := serverHelper.newService(cr)

	// Set AquaServer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, service, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this service already exists
	found := &corev1.Service{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: service.Name, Namespace: service.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Server Service", "Service.Namespace", service.Namespace, "Service.Name", service.Name)
		err = r.client.Create(context.TODO(), service)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Service already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Server Service Already Exists", "Service.Namespace", found.Namespace, "Service.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaServer) CreateAdminPasswordSecret(cr *operatorv1alpha1.AquaServer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Server Aqua Phase", "Create Server Secrets")
	reqLogger.Info("Start creating aqua server admin password secret")

	// Define a new Secrets object
	secret := secrets.CreateSecret(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-server", cr.Name),
		"Secret for aqua admin password",
		cr.Spec.Common.AdminPassword.Name,
		cr.Spec.Common.AdminPassword.Key,
		cr.Spec.AdminPassword)

	// Set AquaServer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, secret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this service already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Server Admin Password Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.client.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Secrets already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Server Admin Password Secret Already Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaServer) CreateLicenseSecret(cr *operatorv1alpha1.AquaServer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Server Aqua Phase", "Create Server Secrets")
	reqLogger.Info("Start creating aqua server license secret")

	// Define a new Secrets object
	secret := secrets.CreateSecret(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-server", cr.Name),
		"Secret for aqua license token",
		cr.Spec.Common.AquaLicense.Name,
		cr.Spec.Common.AquaLicense.Key,
		cr.Spec.LicenseToken)

	// Set AquaServer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, secret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this service already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Server License Token Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.client.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Secrets already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Server License Token Secret Already Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaServer) InstallServerDeployment(cr *operatorv1alpha1.AquaServer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Server Aqua Phase", "Install Aqua Server Deployment")
	reqLogger.Info("Start installing aqua server deployment")

	// Define a new deployment object
	serverHelper := newAquaServerHelper(cr)
	deployment := serverHelper.newDeployment(cr)

	// Set AquaServer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this deployment already exists
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Server Deployment", "Dervice.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		err = r.client.Create(context.TODO(), deployment)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	if found != nil {
		upgrade := deployment.Spec.Template.Spec.Containers[0].Image != found.Spec.Template.Spec.Containers[0].Image
		reqLogger.Info("Checking for Aqua Server Upgrade", "deployment obj", deployment.Spec.Template.Spec.Containers[0].Image, "found obj", found.Spec.Template.Spec.Containers[0].Image, "upgrade bool", upgrade)
		size := deployment.Spec.Replicas
		if *found.Spec.Replicas != *size || upgrade {
			found.Spec.Replicas = size
			found.Spec.Template.Spec.Containers[0].Image = deployment.Spec.Template.Spec.Containers[0].Image
			err = r.client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua Server: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
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
			reqLogger.Error(err, "Aqua Server: Failed to list pods.", "AquaServer.Namespace", cr.Namespace, "AquaServer.Name", cr.Name)
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
	reqLogger.Info("Skip reconcile: Aqua Server Deployment Already Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

/*	----------------------------------------------------------------------------------------------------------------
							Enforcer
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaServer) CreateEnforcerToken(cr *operatorv1alpha1.AquaServer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Csp Requirments Phase", "Create Enforcer Token")
	reqLogger.Info("Start creating aqua default enforcer token secret")

	// Generate token
	token := extra.CreateRundomPassword()

	// Define a new secret object
	secret := secrets.CreateSecret(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-enforcer", cr.Name),
		"Enforcer token for default enforcer group",
		fmt.Sprintf("%s-enforcer-token", cr.Name),
		"token",
		token)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, secret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this secret already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Default Enforcer Token Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.client.Create(context.TODO(), secret)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Secret already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Default Enforcer Token Secret Already Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}
