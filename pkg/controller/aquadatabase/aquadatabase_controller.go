package aquadatabase

import (
	"context"
	syserrors "errors"
	"fmt"
	"reflect"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/serviceaccounts"

	"github.com/aquasecurity/aqua-operator/pkg/controller/common"

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
	createDatabaseSecret := instance.Spec.Common == nil || instance.Spec.Common.DatabaseSecret == nil

	instance = r.updateDatabaseObject(instance)

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	if len(instance.Spec.Infrastructure.ServiceAccount) > 0 &&
		!serviceaccounts.CheckIfServiceAccountExists(
			r.client,
			instance.Spec.Infrastructure.ServiceAccount,
			instance.Namespace) {
		_, err = r.CreateAquaServiceAccount(instance)
		if err != nil {
			return reconcile.Result{}, err
		}
	}


	if instance.Spec.DbService != nil {
		reqLogger.Info("Start Setup Internal Aqua Database (Not For Production Usage)")
		if createDatabaseSecret {
			reqLogger.Info("Start Setup Secret For Database Password")
			password := extra.CreateRundomPassword()
			_, err = r.CreateDbPasswordSecret(instance,
				fmt.Sprintf(consts.ScalockDbPasswordSecretName, instance.Name),
				consts.ScalockDbPasswordSecretKey,
				password)
			if err != nil {
				return reconcile.Result{}, err
			}

			instance.Spec.Common.DatabaseSecret = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.ScalockDbPasswordSecretName, instance.Name),
				Key:  consts.ScalockDbPasswordSecretKey,
			}
		}

		pvcName := fmt.Sprintf(consts.DbPvcName, instance.Name)
		dbAppName := fmt.Sprintf("%s-db", instance.Name)
		reqLogger.Info("Start Creating aqua db pvc")
		_, err = r.InstallDatabasePvc(
			instance,
			pvcName)
		if err != nil {
			return reconcile.Result{}, err
		}

		reqLogger.Info("Start Creating aqua db deployment")
		_, err = r.InstallDatabaseDeployment(
			instance,
			instance.Spec.Common.DatabaseSecret,
			fmt.Sprintf(consts.DbDeployName, instance.Name),
			pvcName,
			dbAppName)
		if err != nil {
			return reconcile.Result{}, err
		}

		reqLogger.Info("Start Creating aqua db service")
		_, err = r.InstallDatabaseService(
			instance,
			fmt.Sprintf(consts.DbServiceName, instance.Name),
			dbAppName,
			5432)
		if err != nil {
			return reconcile.Result{}, err
		}

		// if splitDB -> init AuditDB struct
		// Check if AuditDBSecret exist
		// if not -> create AuditDB secret
		// create pvc, deployment, service for audit db
		if instance.Spec.Common.SplitDB {
			instance.Spec.AuditDB = common.UpdateAquaAuditDB(instance.Spec.AuditDB, instance.Name)
			exist := secrets.CheckIfSecretExists(r.client, instance.Spec.AuditDB.AuditDBSecret.Name, instance.Namespace)
			if !exist {
				_, err = r.CreateDbPasswordSecret(instance,
					instance.Spec.AuditDB.AuditDBSecret.Name,
					instance.Spec.AuditDB.AuditDBSecret.Key,
					instance.Spec.AuditDB.Data.Password)
				if err != nil {
					return reconcile.Result{}, err
				}
			}

			auditPvcName := fmt.Sprintf(consts.AuditDbPvcName, instance.Name)
			auditDBAppName := fmt.Sprintf("%s-audit-db", instance.Name)
			reqLogger.Info("Start Creating aqua audit-db pvc")
			_, err = r.InstallDatabasePvc(
				instance,
				auditPvcName)
			if err != nil {
				return reconcile.Result{}, err
			}

			reqLogger.Info("Start Creating aqua audit-db service")
			_, err = r.InstallDatabaseService(
				instance,
				instance.Spec.AuditDB.Data.Host,
				auditDBAppName,
				int32(instance.Spec.AuditDB.Data.Port))
			if err != nil {
				return reconcile.Result{}, err
			}

			reqLogger.Info("Start Creating aqua audit-db deployment")
			_, err = r.InstallDatabaseDeployment(
				instance,
				instance.Spec.AuditDB.AuditDBSecret,
				fmt.Sprintf(consts.AuditDbDeployName, instance.Name),
				auditPvcName,
				auditDBAppName)
			if err != nil {
				return reconcile.Result{}, err
			}
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

func (r *ReconcileAquaDatabase) InstallDatabaseService(cr *operatorv1alpha1.AquaDatabase, serviceName, app string, servicePort int32) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Install Database Service")
	reqLogger.Info("Start installing aqua database service")

	// Define a new Service object
	databaseHelper := newAquaDatabaseHelper(cr)
	service := databaseHelper.newService(cr, serviceName, app, servicePort)

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

func (r *ReconcileAquaDatabase) InstallDatabasePvc(cr *operatorv1alpha1.AquaDatabase, name string) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Install Database PersistentVolumeClaim")
	reqLogger.Info("Start installing aqua database pvc")

	// Define a new pvc object
	pvc := pvcs.CreatePersistentVolumeClaim(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-database", cr.Name),
		"Persistent Volume Claim for aqua database server",
		name,
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

func (r *ReconcileAquaDatabase) InstallDatabaseDeployment(cr *operatorv1alpha1.AquaDatabase, dbSecret *operatorv1alpha1.AquaSecret, deployName, pvcName, app string) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Install Database Deployment")
	reqLogger.Info("Start installing aqua database deployment")

	// Define a new deployment object
	databaseHelper := newAquaDatabaseHelper(cr)
	deployment := databaseHelper.newDeployment(
		cr,
		dbSecret,
		deployName,
		pvcName,
		app)

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
		if len(cr.Status.Nodes) == 0 {
			cr.Status.Nodes = podNames
		}
		nodes := cr.Status.Nodes
		var podsToAppend []string
		for _, pod := range podNames {
			addPodName := true
			for _, node := range nodes {
				if pod == node {
					addPodName = false
				}
			}
			if addPodName {
				podsToAppend = append(podsToAppend, pod)
			}
		}
		if len(podsToAppend) > 0 {
			for _, pod := range podsToAppend {
				cr.Status.Nodes = append(cr.Status.Nodes, pod)
			}
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

func (r *ReconcileAquaDatabase) CreateDbPasswordSecret(cr *operatorv1alpha1.AquaDatabase, name, key, password string) (reconcile.Result, error) {
	reqLogger := log.WithValues("Database Aqua Phase", "Create Db Password Secret")
	reqLogger.Info("Start creating aqua db password secret")

	// Define a new secret object
	secret := secrets.CreateSecret(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		"Secret for aqua database password",
		name,
		key,
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

func (r *ReconcileAquaDatabase) updateDatabaseObject(cr *operatorv1alpha1.AquaDatabase) *operatorv1alpha1.AquaDatabase {

	cr.Spec.Infrastructure = common.UpdateAquaInfrastructure(cr.Spec.Infrastructure, cr.Name, cr.Namespace)
	cr.Spec.Common = common.UpdateAquaCommon(cr.Spec.Common, cr.Name, false, false)

	return cr
}

func (r *ReconcileAquaDatabase) CreateAquaServiceAccount(cr *operatorv1alpha1.AquaDatabase) (reconcile.Result, error) {
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
