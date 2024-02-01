/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aquacsp

import (
	"context"
	syserrors "errors"
	"fmt"
	"reflect"
	"time"

	"github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/controllers/common"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var log = logf.Log.WithName("controller_aquacsp")

// AquaCspReconciler reconciles a AquaCsp object
type AquaCspReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquacsps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquacsps/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquacsps/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquagateways,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquaservers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquaenforcers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquakubeenforcers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquadatabases,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquaservers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquaservers,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the AquaCsp object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *AquaCspReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)
	reqLogger.Info("Reconciling AquaCsp")

	// Fetch the AquaCsp instance
	instance := &v1alpha1.AquaCsp{}
	err := r.Client.Get(context.TODO(), req.NamespacedName, instance)
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
		reqLogger.Info("Start Setup Requirement For Aqua CSP...")

		if instance.Spec.RegistryData != nil {
			marketplace := extra.IsMarketPlace()
			if !marketplace {
				reqLogger.Info("Start Setup Aqua Image Secret Secret")
				_, err = r.CreateImagePullSecret(instance)
				if err != nil {
					return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
				}
			} else {
				reqLogger.Info("[Marketplace Mode] skipping creating of image pull secret, using images from RedHat repository with digest")
			}
		}
	}

	rbacHelper := common.NewAquaRbacHelper(
		instance.Spec.Infrastructure,
		instance.Name,
		instance.Namespace,
		instance.Spec.Common,
		r.Client,
		r.Scheme,
		instance)

	err = rbacHelper.CreateRBAC()
	if err != nil {
		return reconcile.Result{}, err
	}

	dbstatus := true
	if instance.Spec.DbService != nil {
		reqLogger.Info("Start Setup Secret For Database Password")
		password := extra.CreateRundomPassword()
		_, err = r.CreateDbPasswordSecret(
			instance,
			fmt.Sprintf(consts.ScalockDbPasswordSecretName, instance.Name),
			consts.ScalockDbPasswordSecretKey,
			password)
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
			_, err = r.CreateDbPasswordSecret(
				instance,
				fmt.Sprintf(consts.ScalockDbPasswordSecretName, instance.Name),
				consts.ScalockDbPasswordSecretKey,
				instance.Spec.ExternalDb.Password)
			if err != nil {
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		} else {
			if instance.Spec.Common.DatabaseSecret != nil {
				exists := secrets.CheckIfSecretExists(r.Client, instance.Spec.Common.DatabaseSecret.Name, instance.Namespace)
				if !exists {
					reqLogger.Error(syserrors.New("For using external db you must define password, or define the secret name and key in common section!"), "Missing external database password definition")
				}
			} else {
				reqLogger.Error(syserrors.New("For using external db you must define password, or define the secret name and key in common section!"), "Missing external database password definition")
			}
		}

		// if splitDB ->
		//if no  AuditDB struct -> error
		// init AuditDB struct
		// Check if AuditDBSecret exist
		// if not -> create AuditDB secret using given password
		if instance.Spec.Common.SplitDB {
			if instance.Spec.ExternalDb != nil &&
				(instance.Spec.AuditDB == nil ||
					(instance.Spec.AuditDB != nil && instance.Spec.AuditDB.Data == nil)) {
				reqLogger.Error(syserrors.New(
					"When using split DB with External DB, you must define auditDB information"),
					"Missing audit database information definition")
			}

			instance.Spec.AuditDB = common.UpdateAquaAuditDB(instance.Spec.AuditDB, instance.Name)
			exist := secrets.CheckIfSecretExists(r.Client, instance.Spec.AuditDB.AuditDBSecret.Name, instance.Namespace)
			if !exist {
				_, err = r.CreateDbPasswordSecret(instance,
					instance.Spec.AuditDB.AuditDBSecret.Name,
					instance.Spec.AuditDB.AuditDBSecret.Key,
					instance.Spec.AuditDB.Data.Password)
				if err != nil {
					return reconcile.Result{}, err
				}
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
		if instance.Spec.DeployKubeEnforcer != nil {
			keConfigMapData := map[string]string{
				"BATCH_INSTALL_GATEWAY": fmt.Sprintf(consts.GatewayServiceName, instance.Name),
				"AQUA_KE_GROUP_NAME":    "operator-default-ke-group",
				"AQUA_KE_GROUP_TOKEN":   consts.DefaultKubeEnforcerToken,
			}
			if instance.Spec.ServerConfigMapData != nil {
				for k, v := range keConfigMapData {
					instance.Spec.ServerConfigMapData[k] = v
				}
			} else {
				instance.Spec.ServerConfigMapData = keConfigMapData
			}
		}

		_, err = r.InstallAquaServer(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		_, err = r.InstallAquaGateway(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		serverGatewayStatus := r.GetGatewayServerState(instance)

		currentStatus := instance.Status.State
		serverGatewayReady := reflect.DeepEqual(v1alpha1.AquaDeploymentStateRunning, serverGatewayStatus)

		if serverGatewayReady {
			if !reflect.DeepEqual(v1alpha1.AquaEnforcerUpdatePendingApproval, currentStatus) &&
				!reflect.DeepEqual(v1alpha1.AquaEnforcerUpdateInProgress, currentStatus) &&
				!reflect.DeepEqual(v1alpha1.AquaEnforcerWaiting, currentStatus) &&
				!reflect.DeepEqual(v1alpha1.AquaDeploymentStateRunning, currentStatus) {
				instance.Status.State = v1alpha1.AquaDeploymentStateRunning
				_ = r.Client.Status().Update(context.Background(), instance)
			}
		} else {
			if !reflect.DeepEqual(serverGatewayStatus, currentStatus) {
				instance.Status.State = serverGatewayStatus
				_ = r.Client.Status().Update(context.Background(), instance)
			}
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}
	} else {
		reqLogger.Info("CSP Deployment: Waiting internal for database to start")
		if !reflect.DeepEqual(v1alpha1.AquaDeploymentStateWaitingDB, instance.Status.State) {
			instance.Status.State = v1alpha1.AquaDeploymentStateWaitingDB
			_ = r.Client.Status().Update(context.Background(), instance)
		}
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	}

	waitForEnforcer := false
	if instance.Spec.Enforcer != nil {
		_, err = r.InstallAquaEnforcer(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}
		waitForEnforcer = true
	}

	waitForKubeEnforcer := false
	if instance.Spec.DeployKubeEnforcer != nil {
		_, err = r.InstallAquaKubeEnforcer(instance)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}
		waitForKubeEnforcer = true
	}

	if !reflect.DeepEqual(v1alpha1.AquaDeploymentUpdateInProgress, instance.Status.State) &&
		(waitForKubeEnforcer || waitForEnforcer) {
		crStatus := r.WaitForEnforcersReady(instance, waitForEnforcer, waitForKubeEnforcer)
		if !reflect.DeepEqual(instance.Status.State, crStatus) {
			instance.Status.State = crStatus
			_ = r.Client.Status().Update(context.Background(), instance)
		}
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AquaCspReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&operatorv1alpha1.AquaCsp{}).
		Named("aquacsp-controller").
		//WithOptions(controller.Options{
		//	Reconciler:              r,
		//	MaxConcurrentReconciles: 2,
		//}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&operatorv1alpha1.AquaDatabase{}).
		Owns(&operatorv1alpha1.AquaServer{}).
		Owns(&operatorv1alpha1.AquaGateway{}).
		Owns(&operatorv1alpha1.AquaEnforcer{}).
		Owns(&operatorv1alpha1.AquaKubeEnforcer{})

	return builder.Complete(r)
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua CSP
	----------------------------------------------------------------------------------------------------------------
*/

func (r *AquaCspReconciler) updateCspObject(cr *v1alpha1.AquaCsp) *v1alpha1.AquaCsp {
	admin := false
	license := false

	if len(cr.Spec.AdminPassword) != 0 {
		admin = true
	}

	if len(cr.Spec.LicenseToken) != 0 {
		license = true
	}

	registry := consts.Registry
	if cr.Spec.RegistryData != nil {
		if len(cr.Spec.RegistryData.URL) > 0 {
			registry = cr.Spec.RegistryData.URL
		}
	}

	cr.Spec.Infrastructure = common.UpdateAquaInfrastructure(cr.Spec.Infrastructure, cr.Name, cr.Namespace)
	cr.Spec.Common = common.UpdateAquaCommon(cr.Spec.Common, cr.Name, admin, license)

	if cr.Spec.ServerService == nil {
		cr.Spec.ServerService = &v1alpha1.AquaService{
			Replicas:    1,
			ServiceType: "ClusterIP",
			ImageData: &v1alpha1.AquaImage{
				Registry: registry,
			},
		}
	}

	if cr.Spec.GatewayService == nil {
		cr.Spec.GatewayService = &v1alpha1.AquaService{
			Replicas:    1,
			ServiceType: "ClusterIP",
			ImageData: &v1alpha1.AquaImage{
				Registry: registry,
			},
		}
	}

	if cr.Spec.DbService == nil && cr.Spec.ExternalDb == nil {
		cr.Spec.DbService = &v1alpha1.AquaService{
			Replicas:    1,
			ServiceType: "ClusterIP",
			ImageData: &v1alpha1.AquaImage{
				Registry: registry,
			},
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

func (r *AquaCspReconciler) InstallAquaDatabase(cr *v1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaDatabase Phase", "Install Aqua Database")
	reqLogger.Info("Start installing AquaDatabase")

	// Define a new AquaDatabase object
	cspHelper := newAquaCspHelper(cr)
	aquadb := cspHelper.newAquaDatabase(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquadb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaDatabase already exists
	found := &v1alpha1.AquaDatabase{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: aquadb.Name, Namespace: aquadb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Database", "AquaDatabase.Namespace", aquadb.Namespace, "AquaDatabase.Name", aquadb.Name)
		err = r.Client.Create(context.TODO(), aquadb)
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
			err = r.Client.Update(context.Background(), found)
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

func (r *AquaCspReconciler) InstallAquaGateway(cr *v1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaGateway Phase", "Install Aqua Gateway")
	reqLogger.Info("Start installing AquaGateway")

	// Define a new AquaGateway object
	cspHelper := newAquaCspHelper(cr)
	aquagw := cspHelper.newAquaGateway(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquagw, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaGateway already exists
	found := &v1alpha1.AquaGateway{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: aquagw.Name, Namespace: aquagw.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Gateway", "AquaGateway.Namespace", aquagw.Namespace, "AquaGateway.Name", aquagw.Name)
		err = r.Client.Create(context.TODO(), aquagw)
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
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update aqua gateway replicas.", "AquaServer.Namespace", found.Namespace, "AquaServer.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}

		update := !reflect.DeepEqual(aquagw.Spec, found.Spec)

		reqLogger.Info("Checking for AquaGateway Upgrade", "aquagw", aquagw.Spec, "found", found.Spec, "update bool", update)
		if update {
			found.Spec = *(aquagw.Spec.DeepCopy())
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update AquaGateway.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		}
	}

	// AquaGateway already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Gateway Exists", "AquaGateway.Namespace", found.Namespace, "AquaGateway.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *AquaCspReconciler) InstallAquaServer(cr *v1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaServer Phase", "Install Aqua Server")
	reqLogger.Info("Start installing AquaServer")

	// Define a new AquaServer object
	cspHelper := newAquaCspHelper(cr)
	aquasr := cspHelper.newAquaServer(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquasr, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaServer already exists
	found := &v1alpha1.AquaServer{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: aquasr.Name, Namespace: aquasr.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua AquaServer", "AquaServer.Namespace", aquasr.Namespace, "AquaServer.Name", aquasr.Name)
		err = r.Client.Create(context.TODO(), aquasr)
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
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update aqua server replicas.", "AquaServer.Namespace", found.Namespace, "AquaServer.Name", found.Name)
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}

		update := !reflect.DeepEqual(aquasr.Spec, found.Spec)

		reqLogger.Info("Checking for AquaServer Upgrade", "aquasr", aquasr.Spec, "found", found.Spec, "update bool", update)
		if update {
			found.Spec = *(aquasr.Spec.DeepCopy())
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update AquaServer.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		}
	}

	// AquaServer already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Server Exists", "AquaServer.Namespace", found.Namespace, "AquaServer.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

/*func (r *ReconcileAquaCsp) InstallAquaScanner(cr *operatorv1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaScanner Phase", "Install Aqua Scanner")
	reqLogger.Info("Start installing AquaScanner")

	// Define a new AquaScanner object
	cspHelper := newAquaCspHelper(cr)
	scanner := cspHelper.newAquaScanner(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, scanner, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaScanner already exists
	found := &operatorv1alpha1.AquaScanner{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: scanner.Name, Namespace: scanner.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Scanner", "AquaScanner.Namespace", scanner.Namespace, "AquaScanner.Name", scanner.Name)
		err = r.Client.Create(context.TODO(), scanner)
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
			err = r.Client.Status().Update(context.Background(), found)
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
}*/

func (r *AquaCspReconciler) InstallAquaEnforcer(cr *v1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaEnforcer Phase", "Install Aqua Enforcer")
	reqLogger.Info("Start installing AquaEnforcer")

	// Define a new AquaEnforcer object
	cspHelper := newAquaCspHelper(cr)
	enforcer := cspHelper.newAquaEnforcer(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, enforcer, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaEnforcer already exists
	found := &v1alpha1.AquaEnforcer{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: enforcer.Name, Namespace: enforcer.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Enforcer", "AquaEnforcer.Namespace", enforcer.Namespace, "AquaEnforcer.Name", enforcer.Name)
		err = r.Client.Create(context.TODO(), enforcer)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}
	// AquaEnforcer already exists - don't requeue

	if found != nil {
		update := !reflect.DeepEqual(enforcer.Spec, found.Spec)

		reqLogger.Info("Checking for AquaEnforcer Upgrade", "enforcer", enforcer.Spec, "found", found.Spec, "update bool", update)
		if update {
			found.Spec = *(enforcer.Spec.DeepCopy())
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update AquaEnforcer.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		}
	}

	reqLogger.Info("Skip reconcile: Aqua Enforcer Exists", "AquaEnforcer.Namespace", found.Namespace, "AquaEnforcer.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

func (r *AquaCspReconciler) InstallAquaKubeEnforcer(cr *v1alpha1.AquaCsp) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaKubeEnforcer Phase", "Install Aqua Enforcer")
	reqLogger.Info("Start installing AquaKubeEnforcer")

	// Define a new AquaEnforcer object
	cspHelper := newAquaCspHelper(cr)
	enforcer := cspHelper.newAquaKubeEnforcer(cr)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, enforcer, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaKubeEnforcer already exists
	found := &v1alpha1.AquaKubeEnforcer{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: enforcer.Name, Namespace: enforcer.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua KubeEnforcer", "AquaKubeEnforcer.Namespace", enforcer.Namespace, "AquaKubeEnforcer.Name", enforcer.Name)
		err = r.Client.Create(context.TODO(), enforcer)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}
	// AquaEnforcer already exists - don't requeue

	if found != nil {
		update := !reflect.DeepEqual(enforcer.Spec, found.Spec)

		reqLogger.Info("Checking for AquaKubeEnforcer Upgrade", "kube-enforcer", enforcer.Spec, "found", found.Spec, "update bool", update)
		if update {
			found.Spec = *(enforcer.Spec.DeepCopy())
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP: Failed to update AquaKubeEnforcer.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		}

	}

	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer Exists", "AquaKubeEnforcer.Namespace", found.Namespace, "AquaKubeEnforcer.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

/*	----------------------------------------------------------------------------------------------------------------
							Check Functions - Internal Only
	----------------------------------------------------------------------------------------------------------------
*/

func (r *AquaCspReconciler) WaitForDatabase(cr *v1alpha1.AquaCsp) (bool, error) {
	reqLogger := log.WithValues("CSP - AquaDatabase Phase", "Wait For Database")
	reqLogger.Info("Start waiting to aqua database")

	ready, err := r.GetPostgresReady(
		cr,
		fmt.Sprintf(consts.DbDeployName, cr.Name),
		int(cr.Spec.DbService.Replicas))
	if err != nil {
		return false, err
	}

	auditReady := true
	if cr.Spec.Common.SplitDB {
		auditReady, err = r.GetPostgresReady(
			cr,
			fmt.Sprintf(consts.AuditDbDeployName, cr.Name),
			1)
		if err != nil {
			return false, err
		}
	}
	return ready && auditReady, nil
}

func (r *AquaCspReconciler) GetPostgresReady(cr *v1alpha1.AquaCsp, dbDeployName string, replicas int) (bool, error) {
	resource := appsv1.Deployment{}

	selector := types.NamespacedName{
		Namespace: cr.Namespace,
		Name:      dbDeployName,
	}

	err := r.Client.Get(context.TODO(), selector, &resource)
	if err != nil {
		return false, err
	}

	return int(resource.Status.ReadyReplicas) == replicas, nil
}

func (r *AquaCspReconciler) GetGatewayServerState(cr *v1alpha1.AquaCsp) v1alpha1.AquaDeploymentState {
	reqLogger := log.WithValues("CSP - AquaServer and AquaGateway Phase", "Wait For Aqua Gateway and Server")
	reqLogger.Info("Start waiting to aqua gateway and server")

	gatewayState := v1alpha1.AquaDeploymentStateRunning
	gatewayFound := &v1alpha1.AquaGateway{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace}, gatewayFound)
	if err != nil {
		reqLogger.Error(err, "Unable to Get AquaGateway Object", "err", err)
		gatewayState = v1alpha1.AquaDeploymentStatePending
	} else {
		gatewayState = gatewayFound.Status.State
	}

	serverState := v1alpha1.AquaDeploymentStateRunning
	serverFound := &v1alpha1.AquaServer{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace}, serverFound)
	if err != nil {
		reqLogger.Error(err, "Unable to Get AquaServer Object", "err", err)
		serverState = v1alpha1.AquaDeploymentStatePending
	} else {
		serverState = serverFound.Status.State
	}

	cspStatus := v1alpha1.AquaDeploymentStateRunning

	if reflect.DeepEqual(v1alpha1.AquaDeploymentStatePending, gatewayState) ||
		reflect.DeepEqual(v1alpha1.AquaDeploymentStatePending, serverState) {
		cspStatus = v1alpha1.AquaDeploymentStateWaitingAqua
	} else if reflect.DeepEqual(v1alpha1.AquaDeploymentUpdateInProgress, gatewayState) ||
		reflect.DeepEqual(v1alpha1.AquaDeploymentUpdateInProgress, serverState) {
		cspStatus = v1alpha1.AquaDeploymentUpdateInProgress
	}

	return cspStatus
}

func (r *AquaCspReconciler) WaitForEnforcersReady(cr *v1alpha1.AquaCsp, validateEnforcer, validateKubeEnforcer bool) v1alpha1.AquaDeploymentState {
	reqLogger := log.WithValues("CSP - AquaEnforcers Phase", "Wait For Aqua Enforcer and KubeEnforcer")
	reqLogger.Info("Start waiting to aqua enforcer and kube-enforcer")

	enforcerStatus := v1alpha1.AquaDeploymentStateRunning
	if validateEnforcer {
		enforcerFound := &v1alpha1.AquaEnforcer{}
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace}, enforcerFound)
		if err != nil {
			reqLogger.Info("Unable to Get AquaEnforcer Object", "err", err)
			enforcerStatus = v1alpha1.AquaDeploymentStatePending
		} else {
			enforcerStatus = enforcerFound.Status.State
		}

	}

	kubeEnforcerStatus := v1alpha1.AquaDeploymentStateRunning
	if validateKubeEnforcer {
		kubeEnforcerFound := &v1alpha1.AquaKubeEnforcer{}
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace}, kubeEnforcerFound)
		if err != nil {
			reqLogger.Info("Unable to Get AquaKubeEnforcer Object", "err", err)
			kubeEnforcerStatus = v1alpha1.AquaDeploymentStatePending
		} else {
			kubeEnforcerStatus = kubeEnforcerFound.Status.State
		}

	}

	returnStatus := v1alpha1.AquaDeploymentStateRunning

	if reflect.DeepEqual(v1alpha1.AquaDeploymentStatePending, enforcerStatus) ||
		reflect.DeepEqual(v1alpha1.AquaDeploymentStatePending, kubeEnforcerStatus) {
		returnStatus = v1alpha1.AquaEnforcerWaiting
	} else if reflect.DeepEqual(v1alpha1.AquaEnforcerUpdateInProgress, enforcerStatus) ||
		reflect.DeepEqual(v1alpha1.AquaEnforcerUpdateInProgress, kubeEnforcerStatus) {
		returnStatus = v1alpha1.AquaEnforcerUpdateInProgress
	} else if reflect.DeepEqual(v1alpha1.AquaEnforcerUpdatePendingApproval, enforcerStatus) ||
		reflect.DeepEqual(v1alpha1.AquaEnforcerUpdatePendingApproval, kubeEnforcerStatus) {
		returnStatus = v1alpha1.AquaEnforcerUpdatePendingApproval
	}

	return returnStatus

}

/*func (r *ReconcileAquaCsp) WaitForServer(cr *operatorv1alpha1.AquaCsp) (bool, error) {
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

	err := r.Client.Get(context.TODO(), selector, &resource)
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
	err = r.Client.List(context.TODO(), nodes, &client.ListOptions{})
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
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: cr.Name, Namespace: cr.Namespace}, found)
	if found != nil {
		reqLogger.Info(string(found.Spec.ScannerService.Replicas))
		reqLogger.Info(string(scanners))

		if found.Spec.ScannerService.Replicas == scanners {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}

		if result.Count > 0 {
			found.Spec.ScannerService.Replicas = scanners
			err = r.Client.Status().Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua CSP Scanner Scale: Failed to update Aqua Scanner.", "AquaScanner.Namespace", found.Namespace, "AquaScanner.Name", found.Name)
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
		}
	}

	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}*/
