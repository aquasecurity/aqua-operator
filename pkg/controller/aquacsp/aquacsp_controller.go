package aquacsp

import (
	"context"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/controller/common"
	"github.com/aquasecurity/aqua-operator/pkg/controller/ocp"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	rbacv1 "k8s.io/api/rbac/v1"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	"reflect"
	"fmt"
	"time"

	syserrors "errors"
	routev1 "github.com/openshift/api/route/v1"

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

var log = logf.Log.WithName("controller_aquacsp")

// Add creates a new AquaCsp Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaCsp{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("aquacsp-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaCsp
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaCsp{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	// AquaCsp Components

	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaDatabase{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaGateway{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaServer{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaEnforcer{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaScanner{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	// RBAC

	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRole{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRoleBinding{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaCsp{},
	})
	if err != nil {
		return err
	}

	// Openshift Route
	isOpenshift, _ := ocp.VerifyRouteAPI()
	if isOpenshift {
		err = c.Watch(&source.Kind{Type: &routev1.Route{}}, &handler.EnqueueRequestForOwner{
			IsController: true,
			OwnerType:    &operatorv1alpha1.AquaCsp{},
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// blank assignment to verify that ReconcileAquaCsp implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaCsp{}

// ReconcileAquaCsp reconciles a AquaCsp object
type ReconcileAquaCsp struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a AquaCsp object and makes changes based on the state read
// and what is in the AquaCsp.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaCsp) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaCsp")

	// Fetch the AquaCsp instance
	instance := &operatorv1alpha1.AquaCsp{}
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

	instance = r.updateCspObject(instance)

	if instance.Spec.Infrastructure.Requirements {
		reqLogger.Info("Start Setup Requirment For Aqua CSP...")

		if instance.Spec.RegistryData != nil {
			reqLogger.Info("Start Setup Aqua Image Secret Secret")
			_, err = r.CreateImagePullSecret(instance)
			if err != nil {
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		}

		reqLogger.Info("Start Setup Aqua Service Account")
		_, err = r.CreateAquaServiceAccount(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}
	}

	reqLogger.Info("Creating discovery cluster roles...")
	_, err = r.CreateClusterRole(instance)
	if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	reqLogger.Info("Creating discovery cluster roles binding...")
	_, err = r.CreateClusterRoleBinding(instance)
	if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	dbstatus := true
	if instance.Spec.DbService != nil {
		reqLogger.Info("Start Setup Secret For Database Password")
		password := extra.CreateRundomPassword()
		_, err = r.CreateDbPasswordSecret(instance, password)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		reqLogger.Info("CSP Deployment: Start Setup Internal Aqua Database (Not Recommended For Production Usage)")
		_, err = r.InstallAquaDatabase(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		dbstatus, _ = r.WaitForDatabase(instance)
	} else if instance.Spec.ExternalDb != nil {
		if len(instance.Spec.ExternalDb.Password) != 0 {
			_, err = r.CreateDbPasswordSecret(instance, instance.Spec.ExternalDb.Password)
			if err != nil {
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		} else {
			if instance.Spec.Common.DatabaseSecret != nil {
				exists := secrets.CheckIfSecretExists(r.client, instance.Spec.Common.DatabaseSecret.Name, instance.Namespace)
				if !exists {
					reqLogger.Error(syserrors.New("For using external db you must define password, or define the secret name and key in common section!"), "Missing external database password definition")
				}
			} else {
				reqLogger.Error(syserrors.New("For using external db you must define password, or define the secret name and key in common section!"), "Missing external database password definition")
			}
		}
	}

	if dbstatus {
		if instance.Spec.GatewayService == nil {
			reqLogger.Error(syserrors.New("Missing Aqua Gateway Deployment Data!, Please fix and redeploy template!"), "Aqua CSP Deployment Missing Gateway Deployment Data!")
		}

		if instance.Spec.ServerService == nil {
			reqLogger.Error(syserrors.New("Missing Aqua Server Deployment Data!, Please fix and redeploy template!"), "Aqua CSP Deployment Missing Server Deployment Data!")
		}

		_, err = r.InstallAquaGateway(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		_, err = r.InstallAquaServer(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		gwstatus, _ := r.WaitForGateway(instance)
		srstatus, _ := r.WaitForServer(instance)

		if !gwstatus || !srstatus {
			reqLogger.Info("CSP Deployment: Waiting internal for aqua to start")
			if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateWaitingAqua, instance.Status.State) {
				instance.Status.State = operatorv1alpha1.AquaDeploymentStateWaitingAqua
				_ = r.client.Update(context.TODO(), instance)
			}
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}
	} else {
		reqLogger.Info("CSP Deployment: Waiting internal for database to start")
		if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateWaitingDB, instance.Status.State) {
			instance.Status.State = operatorv1alpha1.AquaDeploymentStateWaitingDB
			_ = r.client.Update(context.TODO(), instance)
		}
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	}

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStateRunning
		_ = r.client.Update(context.TODO(), instance)
	}

	if instance.Spec.ScannerService != nil {
		_, err = r.InstallAquaScanner(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		if instance.Spec.Scale != nil {
			_, err = r.ScaleScannerCLI(instance)
			if err != nil {
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		}
	}

	if instance.Spec.Enforcer != nil {
		_, err = r.InstallAquaEnforcer(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}
	}

	if strings.ToLower(instance.Spec.Infrastructure.Platform) == "openshift" {
		if instance.Spec.Route {
			_, err = r.CreateRoute(instance)
			if err != nil {
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		}
	}

	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *ReconcileAquaCsp) updateCspObject(cr *operatorv1alpha1.AquaCsp) *operatorv1alpha1.AquaCsp {
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

	if cr.Spec.ServerService == nil {
		cr.Spec.ServerService = &operatorv1alpha1.AquaService{
			Replicas:    1,
			ServiceType: "ClusterIP",
		}
	}

	if cr.Spec.GatewayService == nil {
		cr.Spec.GatewayService = &operatorv1alpha1.AquaService{
			Replicas:    1,
			ServiceType: "ClusterIP",
		}
	}

	if cr.Spec.DbService == nil && cr.Spec.ExternalDb == nil {
		cr.Spec.DbService = &operatorv1alpha1.AquaService{
			Replicas:    1,
			ServiceType: "ClusterIP",
		}
	}

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
							Aqua CSP
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaCsp) InstallAquaDatabase(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaDatabase Phase", "Install Aqua Database")
	reqLogger.Info("Start installing AquaDatabase")

	// Define a new AquaDatabase object
	cspHelper := newAquaCspHelper(cr)
	aquadb := cspHelper.newAquaDatabase(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquadb, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaDatabase already exists
	found := &operatorv1alpha1.AquaDatabase{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: aquadb.Name, Namespace: aquadb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Database", "AquaDatabase.Namespace", aquadb.Namespace, "AquaDatabase.Name", aquadb.Name)
		err = r.client.Create(context.TODO(), aquadb)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	if found != nil {
		size := aquadb.Spec.DbService.Replicas
		if found.Spec.DbService.Replicas != size {
			found.Spec.DbService.Replicas = size
			err = r.client.Update(context.TODO(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update aqua database replicas.", "AquaDatabase.Namespace", found.Namespace, "AquaDatabase.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}
	}

	// AquaDatabase already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Database Exists", "AquaDatabase.Namespace", found.Namespace, "AquaDatabase.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *ReconcileAquaCsp) InstallAquaGateway(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaGateway Phase", "Install Aqua Database")
	reqLogger.Info("Start installing AquaGateway")

	// Define a new AquaGateway object
	cspHelper := newAquaCspHelper(cr)
	aquagw := cspHelper.newAquaGateway(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquagw, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaGateway already exists
	found := &operatorv1alpha1.AquaGateway{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: aquagw.Name, Namespace: aquagw.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Gateway", "AquaGateway.Namespace", aquagw.Namespace, "AquaGateway.Name", aquagw.Name)
		err = r.client.Create(context.TODO(), aquagw)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	if found != nil {
		size := aquagw.Spec.GatewayService.Replicas
		if found.Spec.GatewayService.Replicas != size {
			found.Spec.GatewayService.Replicas = size
			err = r.client.Update(context.TODO(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update aqua gateway replicas.", "AquaServer.Namespace", found.Namespace, "AquaServer.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}
	}

	// AquaGateway already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Gateway Exists", "AquaGateway.Namespace", found.Namespace, "AquaGateway.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *ReconcileAquaCsp) InstallAquaServer(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaServer Phase", "Install Aqua Database")
	reqLogger.Info("Start installing AquaServer")

	// Define a new AquaServer object
	cspHelper := newAquaCspHelper(cr)
	aquasr := cspHelper.newAquaServer(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquasr, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaServer already exists
	found := &operatorv1alpha1.AquaServer{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: aquasr.Name, Namespace: aquasr.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua AquaServer", "AquaServer.Namespace", aquasr.Namespace, "AquaServer.Name", aquasr.Name)
		err = r.client.Create(context.TODO(), aquasr)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	if found != nil {
		size := aquasr.Spec.ServerService.Replicas
		if found.Spec.ServerService.Replicas != size {
			found.Spec.ServerService.Replicas = size
			err = r.client.Update(context.TODO(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update aqua server replicas.", "AquaServer.Namespace", found.Namespace, "AquaServer.Name", found.Name)
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}
	}

	// AquaServer already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Server Exists", "AquaServer.Namespace", found.Namespace, "AquaServer.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *ReconcileAquaCsp) InstallAquaScanner(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaScanner Phase", "Install Aqua Scanner")
	reqLogger.Info("Start installing AquaScanner")

	// Define a new AquaScanner object
	cspHelper := newAquaCspHelper(cr)
	scanner := cspHelper.newAquaScanner(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, scanner, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaScanner already exists
	found := &operatorv1alpha1.AquaScanner{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: scanner.Name, Namespace: scanner.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Scanner", "AquaScanner.Namespace", scanner.Namespace, "AquaScanner.Name", scanner.Name)
		err = r.client.Create(context.TODO(), scanner)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	if found != nil {
		size := scanner.Spec.ScannerService.Replicas
		if found.Spec.ScannerService.Replicas != size {
			found.Spec.ScannerService.Replicas = size
			err = r.client.Update(context.TODO(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update aqua scanner replicas.", "AquaScanner.Namespace", found.Namespace, "AquaScanner.Name", found.Name)
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}
	}

	// AquaScanner already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Scanner Exists", "AquaScanner.Namespace", found.Namespace, "AquaScanner.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *ReconcileAquaCsp) InstallAquaEnforcer(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaEnforcer Phase", "Install Aqua Enforcer")
	reqLogger.Info("Start installing AquaEnforcer")

	// Define a new AquaEnforcer object
	cspHelper := newAquaCspHelper(cr)
	enforcer := cspHelper.newAquaEnforcer(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, enforcer, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaEnforcer already exists
	found := &operatorv1alpha1.AquaEnforcer{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: enforcer.Name, Namespace: enforcer.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Enforcer", "AquaEnforcer.Namespace", enforcer.Namespace, "AquaEnforcer.Name", enforcer.Name)
		err = r.client.Create(context.TODO(), enforcer)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}
	// AquaEnforcer already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Enforcer Exists", "AquaEnforcer.Namespace", found.Namespace, "AquaEnforcer.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

/*	----------------------------------------------------------------------------------------------------------------
							Check Functions - Internal Only
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaCsp) WaitForDatabase(cr *operatorv1alpha1.AquaCsp) (bool, error) {
	reqLogger := log.WithValues("Csp Wait For Database Phase", "Wait For Database")
	reqLogger.Info("Start waiting to aqua database")

	ready, err := r.GetPostgresReady(cr)
	if err != nil {
		return false, err
	}

	return ready, nil
}

func (r *ReconcileAquaCsp) GetPostgresReady(cr *operatorv1alpha1.AquaCsp) (bool, error) {
	resource := appsv1.Deployment{}

	selector := types.NamespacedName{
		Namespace: cr.Namespace,
		Name:      fmt.Sprintf(consts.DbDeployName, cr.Name),
	}

	err := r.client.Get(context.TODO(), selector, &resource)
	if err != nil {
		return false, err
	}

	return int(resource.Status.ReadyReplicas) == int(cr.Spec.DbService.Replicas), nil
}

func (r *ReconcileAquaCsp) WaitForGateway(cr *operatorv1alpha1.AquaCsp) (bool, error) {
	reqLogger := log.WithValues("Csp Wait For Aqua Gateway Phase", "Wait For Aqua Gateway")
	reqLogger.Info("Start waiting to aqua gateway")

	ready, err := r.GetGatewayReady(cr)
	if err != nil {
		return false, err
	}

	return ready, nil
}

func (r *ReconcileAquaCsp) GetGatewayReady(cr *operatorv1alpha1.AquaCsp) (bool, error) {
	resource := appsv1.Deployment{}

	selector := types.NamespacedName{
		Namespace: cr.Namespace,
		Name:      fmt.Sprintf(consts.GatewayDeployName, cr.Name),
	}

	err := r.client.Get(context.TODO(), selector, &resource)
	if err != nil {
		return false, err
	}

	return int(resource.Status.ReadyReplicas) == int(cr.Spec.GatewayService.Replicas), nil
}

func (r *ReconcileAquaCsp) WaitForServer(cr *operatorv1alpha1.AquaCsp) (bool, error) {
	reqLogger := log.WithValues("Csp Wait For Aqua Server Phase", "Wait For Aqua Server")
	reqLogger.Info("Start waiting to aqua server")

	ready, err := r.GetServerReady(cr)
	if err != nil {
		return false, err
	}

	return ready, nil
}

func (r *ReconcileAquaCsp) GetServerReady(cr *operatorv1alpha1.AquaCsp) (bool, error) {
	resource := appsv1.Deployment{}

	selector := types.NamespacedName{
		Namespace: cr.Namespace,
		Name:      fmt.Sprintf(consts.ServerDeployName, cr.Name),
	}

	err := r.client.Get(context.TODO(), selector, &resource)
	if err != nil {
		return false, err
	}

	return int(resource.Status.ReadyReplicas) == int(cr.Spec.ServerService.Replicas), nil
}

func (r *ReconcileAquaCsp) ScaleScannerCLI(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - Scale", "Scale Aqua Scanner CLI")
	reqLogger.Info("Start get scanner cli data")

	// TODO:
	result, err := common.GetPendingScanQueue("administrator", cr.Spec.AdminPassword, fmt.Sprintf(consts.ServerServiceName, cr.Name))
	if err != nil {
		reqLogger.Info("Waiting for aqua server to be up...")
		return reconcile.Result{}, err
	}

	reqLogger.Info("Count of pending scan queue", "Pending Scan Queue", result.Count)

	if result.Count == 0 {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	}

	nodes := &corev1.NodeList{}
	count := int64(0)
	err = r.client.List(context.TODO(), nodes, &client.ListOptions{})
	if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	for index := 0; index < len(nodes.Items); index++ {
		if val, ok := nodes.Items[index].Labels["kubernetes.io/role"]; ok {
			if val == "node" {
				count++
			}
		} else if val, ok := nodes.Items[index].Labels["node-role.kubernetes.io/compute"]; ok {
			if val == "true" {
				count++
			}
		}
	}

	reqLogger.Info("Aqua CSP Scanner Scale:", "Kubernetes Nodes Count:", count)

	if count == 0 {
		count = 1
	}

	scanners := result.Count / cr.Spec.Scale.ImagesPerScanner
	extraScanners := result.Count % cr.Spec.Scale.ImagesPerScanner

	if scanners < cr.Spec.Scale.Min {
		scanners = cr.Spec.Scale.Min
	} else {
		if extraScanners > 0 {
			scanners = scanners + 1
		}

		if (cr.Spec.Scale.Max * count) < scanners {
			scanners = (cr.Spec.Scale.Max * count)
		}
	}

	reqLogger.Info("Aqua CSP Scanner Scale:", "Final Scanners Count:", scanners)

	found := &operatorv1alpha1.AquaScanner{}
	err = r.client.Get(context.TODO(), types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace}, found)
	if found != nil {
		reqLogger.Info(string(found.Spec.ScannerService.Replicas))
		reqLogger.Info(string(scanners))

		if found.Spec.ScannerService.Replicas == scanners {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}

		if result.Count > 0 {
			found.Spec.ScannerService.Replicas = scanners
			err = r.client.Update(context.TODO(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP Scanner Scale: Failed to update Aqua Scanner.", "AquaScanner.Namespace", found.Namespace, "AquaScanner.Name", found.Name)
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		}
	}

	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}
