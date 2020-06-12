package aquadatabase

import (
	"context"
	syserrors "errors"
	"fmt"
	"reflect"

	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/pvcs"
	appsv1 "k8s.io/api/apps/v1"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
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

var log = logf.Log.WithName("controller_aquadatabase")

// Add creates a new AquaDatabase Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaDatabase{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("aquadatabase-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaDatabase
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaDatabase{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaDatabase{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaDatabase{},
	})
	if err != nil {
		return err
	}

	// AquaDatabase Components

	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaDatabase{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaDatabase{},
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

// blank assignment to verify that ReconcileAquaDatabase implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaDatabase{}

// ReconcileAquaDatabase reconciles a AquaDatabase object
type ReconcileAquaDatabase struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaDatabase) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaDatabase")

	// Fetch the AquaDatabase instance
	instance := &operatorv1alpha1.AquaDatabase{}
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

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	if instance.Spec.DbService != nil {
		reqLogger.Info("Start Setup Internal Aqua Database (Not For Production Usage)")
		if instance.Spec.Common.DatabaseSecret == nil {
			reqLogger.Info("Start Setup Secret For Database Password")
			password := extra.CreateRundomPassword()
			_, err = r.CreateDbPasswordSecret(instance, password)
			if err != nil {
				return reconcile.Result{}, err
			}

			instance.Spec.Common.DatabaseSecret = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.ScalockDbPasswordSecretName, instance.Name),
				Key:  consts.ScalockDbPasswordSecretKey,
			}
		}

		reqLogger.Info("Start Creating aqua db pvc")
		_, err = r.InstallDatabasePvc(instance)
		if err != nil {
			return reconcile.Result{}, err
		}

		reqLogger.Info("Start Creating aqua db deployment")
		_, err = r.InstallDatabaseDeployment(instance)
		if err != nil {
			return reconcile.Result{}, err
		}

		reqLogger.Info("Start Creating aqua db service")
		_, err = r.InstallDatabaseService(instance)
		if err != nil {
			return reconcile.Result{}, err
		}

	} else {
		reqLogger.Error(syserrors.New("deploy section for aquadatabase can't be empty"), "must define the deployment details")
	}

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStateRunning
		_ = r.client.Status().Update(context.Background(), instance)
	}

	return reconcile.Result{Requeue: true}, nil
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Database
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaDatabase) InstallDatabaseService(cr *operatorv1alpha1.AquaDatabase) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Install Database Service")
	reqLogger.Info("Start installing aqua database service")

	// Define a new Service object
	databaseHelper := newAquaDatabaseHelper(cr)
	service := databaseHelper.newService(cr)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, service, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this service already exists
	found := &corev1.Service{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: service.Name, Namespace: service.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Database Service", "Service.Namespace", service.Namespace, "Service.Name", service.Name)
		err = r.client.Create(context.TODO(), service)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Service already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Database Service Already Exists", "Service.Namespace", found.Namespace, "Service.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaDatabase) InstallDatabasePvc(cr *operatorv1alpha1.AquaDatabase) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Install Database PersistentVolumeClaim")
	reqLogger.Info("Start installing aqua database pvc")

	// Define a new pvc object
	pvc := pvcs.CreatePersistentVolumeClaim(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-database", cr.Name),
		"Persistent Volume Claim for aqua database server",
		fmt.Sprintf(consts.DbPvcName, cr.Name),
		cr.Spec.Common.StorageClass,
		cr.Spec.DiskSize)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, pvc, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this pvc already exists
	found := &corev1.PersistentVolumeClaim{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: pvc.Name, Namespace: pvc.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Database PersistentVolumeClaim", "PersistentVolumeClaim.Namespace", pvc.Namespace, "PersistentVolumeClaim.Name", pvc.Name)
		err = r.client.Create(context.TODO(), pvc)
		if err != nil {
			return reconcile.Result{}, err
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// PersistentVolumeClaim already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Database PersistentVolumeClaim Already Exists", "PersistentVolumeClaim.Namespace", found.Namespace, "PersistentVolumeClaim.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaDatabase) InstallDatabaseDeployment(cr *operatorv1alpha1.AquaDatabase) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Install Database Deployment")
	reqLogger.Info("Start installing aqua database deployment")

	// Define a new deployment object
	databaseHelper := newAquaDatabaseHelper(cr)
	deployment := databaseHelper.newDeployment(cr)

	// Set AquaCspKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this deployment already exists
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Database Deployment", "Dervice.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
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
				reqLogger.Error(err, "Database Aqua: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
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
			reqLogger.Error(err, "Aqua DataBase: Failed to list pods.", "AquaDatabase.Namespace", cr.Namespace, "AquaDatabase.Name", cr.Name)
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
	reqLogger.Info("Skip reconcile: Aqua Database Deployment Already Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaDatabase) CreateDbPasswordSecret(cr *operatorv1alpha1.AquaDatabase, password string) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Create Db Password Secret")
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
