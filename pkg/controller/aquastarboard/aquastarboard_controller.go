package AquaStarboard

import (
	"context"
	"fmt"
	"github.com/aquasecurity/aqua-operator/pkg/apis/aquasecurity/v1alpha1"
	"reflect"
	"strings"

	"github.com/aquasecurity/aqua-operator/pkg/controller/common"

	"github.com/banzaicloud/k8s-objectmatcher/patch"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"

	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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

var log = logf.Log.WithName("controller_AquaStarboard")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new AquaStarboard Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaStarboard{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("AquaStarboard-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaStarboard
	err = c.Watch(&source.Kind{Type: &v1alpha1.AquaStarboard{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner AquaStarboard
	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRole{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &v1alpha1.AquaStarboard{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &v1alpha1.AquaStarboard{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRoleBinding{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &v1alpha1.AquaStarboard{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &v1alpha1.AquaStarboard{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &v1alpha1.AquaStarboard{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &v1alpha1.AquaStarboard{},
	})
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileAquaStarboard implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaStarboard{}

// ReconcileAquaStarboard reconciles a AquaStarboard object
type ReconcileAquaStarboard struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
}

// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaStarboard) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaStarboard")

	// Fetch the AquaStarboard instance
	instance := &v1alpha1.AquaStarboard{}
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
	instance = r.updateStarboardObject(instance)

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) &&
		!reflect.DeepEqual(operatorv1alpha1.AquaDeploymentUpdateInProgress, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	_, err = r.addStarboardClusterRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.createAquaStarboardServiceAccount(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	if strings.ToLower(instance.Spec.Infrastructure.Platform) == consts.OpenShiftPlatform &&
		rbac.CheckIfClusterRoleExists(r.client, consts.ClusterReaderRole) &&
		!rbac.CheckIfClusterRoleBindingExists(r.client, consts.AquaKubeEnforcerSAClusterReaderRoleBind) {
		_, err = r.CreateClusterReaderRoleBinding(instance)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	instance.Spec.StarboardService = r.updateStarboardServerObject(instance.Spec.StarboardService, instance.Spec.ImageData)

	_, err = r.addStarboardClusterRoleBinding(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addStarboardConfigMap(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addStarboardSecret(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addStarboardDeployment(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaStarboard) updateStarboardObject(cr *v1alpha1.AquaStarboard) *v1alpha1.AquaStarboard {

	cr.Spec.Infrastructure = common.UpdateAquaInfrastructure(cr.Spec.Infrastructure, cr.Name, cr.Namespace)
	return cr
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Starboard
	----------------------------------------------------------------------------------------------------------------
*/

func (r *ReconcileAquaStarboard) addStarboardClusterRole(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Aqua Starboard Phase", "Create Aqua Starboard Cluster Role")
	reqLogger.Info("Start creating starboard cluster role")

	starboardHelper := newAquaStarboardHelper(cr)
	crole := starboardHelper.CreateStarboardClusterRole(cr.Name, cr.Namespace)

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crole, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRole already exists
	found := &rbacv1.ClusterRole{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: crole.Name, Namespace: crole.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New ClusterRole", "ClusterRole.Namespace", crole.Namespace, "ClusterRole.Name", crole.Name)
		err = r.client.Create(context.TODO(), crole)
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

func (r *ReconcileAquaStarboard) createAquaStarboardServiceAccount(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirments Phase", "Create Aqua Starboard Service Account")
	reqLogger.Info("Start creating aqua starboard service account")

	// Define a new service account object
	starboardHelper := newAquaStarboardHelper(cr)
	sa := starboardHelper.CreateStarboardServiceAccount(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		cr.Spec.Infrastructure.ServiceAccount)

	// Set AquaStarboardKind instance as the owner and controller
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

func (r *ReconcileAquaStarboard) addStarboardClusterRoleBinding(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard - RBAC Phase", "Create ClusterRoleBinding")
	reqLogger.Info("Start creating ClusterRole")

	// Define a new ClusterRoleBinding object
	starboardHelper := newAquaStarboardHelper(cr)
	crb := starboardHelper.CreateClusterRoleBinding(cr.Name,
		cr.Namespace,
		"aqua-starboard",
		"ke-crb",
		cr.Spec.Infrastructure.ServiceAccount,
		"aqua-starboard")

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crb, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: crb.Name, Namespace: crb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", crb.Namespace, "ClusterRoleBinding.Name", crb.Name)
		err = r.client.Create(context.TODO(), crb)
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

func (r *ReconcileAquaStarboard) addStarboardConfigMap(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard", "Create ConfigMap")
	reqLogger.Info("Start creating ConfigMap")
	//reqLogger.Info(fmt.Sprintf("cr object : %v", cr.ObjectMeta))

	// Define a new ClusterRoleBinding object
	starboardHelper := newAquaStarboardHelper(cr)
	configMaps := []*corev1.ConfigMap{
		starboardHelper.CreateStarboardConftestConfigMap(cr.Name,
			cr.Namespace,
			"starboard-conftest-config",
			"starboard-conftest-configmap",
			cr.Spec.KubeEnforcerVersion,
		),
		starboardHelper.CreateStarboardConfigMap(cr.Name,
			cr.Namespace,
			"starboard",
			"starboard",
		),
	}

	// Set AquaStarboard instance as the owner and controller
	requeue := true
	for _, configMap := range configMaps {
		// Check if this ClusterRoleBinding already exists
		if err := controllerutil.SetControllerReference(cr, configMap, r.scheme); err != nil {
			return reconcile.Result{}, err
		}

		// Check if this ClusterRoleBinding already exists
		found := &corev1.ConfigMap{}
		err := r.client.Get(context.TODO(), types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, found)
		if err != nil && errors.IsNotFound(err) {
			reqLogger.Info("Aqua Starboard: Creating a New ConfigMap", "ConfigMap.Namespace", configMap.Namespace, "ConfigMap.Name", configMap.Name)
			err = r.client.Create(context.TODO(), configMap)
			if err == nil {
				requeue = false
			}
		} else if err != nil {
			return reconcile.Result{}, err
		}
		// MutatingWebhookConfiguration already exists - don't requeue
		reqLogger.Info("Skip reconcile: Aqua Starboard ConfigMap Exists", "ConfigMap.Namespace", found.Namespace, "ConfigMap.Name", found.Name)
	}
	return reconcile.Result{Requeue: requeue}, nil
}

func (r *ReconcileAquaStarboard) addStarboardSecret(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard", "Create Token Secret")
	reqLogger.Info("Start creating token secret")

	starboardHelper := newAquaStarboardHelper(cr)
	starboardSecret := starboardHelper.CreateStarboardSecret(cr.Name,
		cr.Namespace,
		"aqua-starboard-token",
		"ke-token-secret",
	)

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, starboardSecret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: starboardSecret.Name, Namespace: starboardSecret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New token secret", "Secret.Namespace", starboardSecret.Namespace, "Secret.Name", starboardSecret.Name)
		err = r.client.Create(context.TODO(), starboardSecret)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Starboard Token Secret Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaStarboard) addStarboardDeployment(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard", "Create Deployment")
	reqLogger.Info("Start creating deployment")
	reqLogger.Info("cr.Spec.Infrastructure.Version", cr.Spec.Infrastructure.Version)
	pullPolicy, registry, repository, tag := extra.GetImageData("starboard", cr.Spec.Infrastructure.Version, cr.Spec.StarboardService.ImageData, cr.Spec.AllowAnyVersion)

	starboardHelper := newAquaStarboardHelper(cr)
	deployment := starboardHelper.CreateStarboardDeployment(cr,
		"starboard-operator",
		"starboard-operator",
		registry,
		tag,
		pullPolicy,
		repository)

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		err = patch.DefaultAnnotator.SetLastAppliedAnnotation(deployment)
		if err != nil {
			reqLogger.Error(err, "Unable to set default for k8s-objectmatcher", err)
		}

		err = r.client.Create(context.TODO(), deployment)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	if found != nil {

		update, err := k8s.CheckForK8sObjectUpdate("AquaStarboard deployment", found, deployment)
		if err != nil {
			return reconcile.Result{}, err
		}

		if update {
			err = r.client.Update(context.Background(), deployment)
			if err != nil {
				reqLogger.Error(err, "Aqua Starboard: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
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
			reqLogger.Error(err, "Aqua Starboard: Failed to list pods.", "AquaStarboard.Namespace", cr.Namespace, "AquaStarboard.Name", cr.Name)
			return reconcile.Result{}, err
		}
		podNames := k8s.PodNames(podList.Items)

		// Update status.Nodes if needed
		if !reflect.DeepEqual(podNames, cr.Status.Nodes) {
			cr.Status.Nodes = podNames
		}

		currentState := cr.Status.State
		if !k8s.IsDeploymentReady(found, int(cr.Spec.StarboardService.Replicas)) {
			if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentUpdateInProgress, currentState) &&
				!reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStatePending, currentState) {
				cr.Status.State = operatorv1alpha1.AquaDeploymentUpdateInProgress
				_ = r.client.Status().Update(context.Background(), cr)
			}
		} else if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, currentState) {
			cr.Status.State = operatorv1alpha1.AquaDeploymentStateRunning
			_ = r.client.Status().Update(context.Background(), cr)
		}
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Starboard Deployment Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaStarboard) CreateImagePullSecret(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirments Phase", "Create Image Pull Secret")
	reqLogger.Info("Start creating aqua images pull secret")

	// Define a new secret object
	secret := secrets.CreatePullImageSecret(
		cr.Name,
		cr.Namespace,
		"ke-image-pull-secret",
		cr.Spec.Config.ImagePullSecret,
		*cr.Spec.RegistryData)

	// Set AquaStarboardKind instance as the owner and controller
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

func (r *ReconcileAquaStarboard) CreateClusterReaderRoleBinding(cr *v1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Phase", "Create Starboard ClusterReaderRoleBinding")
	reqLogger.Info("Start creating Starboard ClusterReaderRoleBinding")

	crb := rbac.CreateClusterRoleBinding(
		cr.Name,
		cr.Namespace,
		consts.AquaStarboardSAClusterReaderRoleBind,
		fmt.Sprintf("%s-starboard-cluster-reader", cr.Name),
		"Deploy Aqua Starboard Cluster Reader Role Binding",
		"aqua-starboard-sa",
		consts.ClusterReaderRole)

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crb, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: crb.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New Starboard ClusterReaderRoleBinding", "ClusterReaderRoleBinding.Namespace", crb.Namespace, "ClusterReaderRoleBinding.Name", crb.Name)
		err = r.client.Create(context.TODO(), crb)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// ClusterRoleBinding already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Starboard ClusterReaderRoleBinding Exists", "ClusterRoleBinding.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaStarboard) updateStarboardServerObject(serviceObject *operatorv1alpha1.AquaService, StarboardImageData *operatorv1alpha1.AquaImage) *operatorv1alpha1.AquaService {

	if serviceObject == nil {
		serviceObject = &operatorv1alpha1.AquaService{
			ImageData:   StarboardImageData,
			ServiceType: string(corev1.ServiceTypeClusterIP),
		}
	} else {
		if serviceObject.ImageData == nil {
			serviceObject.ImageData = StarboardImageData
		}
		if len(serviceObject.ServiceType) == 0 {
			serviceObject.ServiceType = string(corev1.ServiceTypeClusterIP)
		}

	}

	return serviceObject
}
