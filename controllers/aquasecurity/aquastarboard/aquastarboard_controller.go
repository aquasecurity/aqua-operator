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

package aquastarboard

import (
	"context"
	"fmt"
	"github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	common2 "github.com/aquasecurity/aqua-operator/controllers/common"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	"github.com/banzaicloud/k8s-objectmatcher/patch"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	aquasecurityv1alpha1 "github.com/aquasecurity/aqua-operator/apis/aquasecurity/v1alpha1"
)

var log = logf.Log.WithName("controller_AquaStarboard")

// AquaStarboardReconciler reconciles a AquaStarboard object
type AquaStarboardReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=aquasecurity.aquasec.com,resources=aquastarboards,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aquasecurity.aquasec.com,resources=aquastarboards/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=aquasecurity.aquasec.com,resources=aquastarboards/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the AquaStarboard object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *AquaStarboardReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "req.Name", req.Name)
	reqLogger.Info("Reconciling AquaStarboard")

	// Fetch the AquaStarboard instance
	instance := &aquasecurityv1alpha1.AquaStarboard{}
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
	instance = r.updateStarboardObject(instance)
	r.Client.Update(context.Background(), instance)

	if !reflect.DeepEqual(v1alpha1.AquaDeploymentStateRunning, instance.Status.State) &&
		!reflect.DeepEqual(v1alpha1.AquaDeploymentUpdateInProgress, instance.Status.State) {
		instance.Status.State = v1alpha1.AquaDeploymentStatePending
		_ = r.Client.Status().Update(context.Background(), instance)
	}

	_, err = r.addStarboardClusterRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addStarboardRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.createAquaStarboardServiceAccount(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	if strings.ToLower(instance.Spec.Infrastructure.Platform) == consts.OpenShiftPlatform &&
		rbac.CheckIfClusterRoleExists(r.Client, consts.ClusterReaderRole) &&
		!rbac.CheckIfClusterRoleBindingExists(r.Client, consts.AquaKubeEnforcerSAClusterReaderRoleBind) {
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

	_, err = r.addStarboardRoleBinding(instance)
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

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AquaStarboardReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AquaStarboard-controller").
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&appsv1.Deployment{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&corev1.ConfigMap{}).
		For(&aquasecurityv1alpha1.AquaStarboard{}).
		Complete(r)
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Starboard
	----------------------------------------------------------------------------------------------------------------
*/

func (r *AquaStarboardReconciler) addStarboardDeployment(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard deployment phase", "Create Deployment")
	reqLogger.Info("Start creating deployment")
	reqLogger.Info("Aqua Starboard", "cr.Spec.Infrastructure.Version", cr.Spec.Infrastructure.Version)
	pullPolicy, registry, repository, tag := extra.GetImageData("starboard-operator", cr.Spec.Infrastructure.Version, cr.Spec.StarboardService.ImageData, true)

	starboardHelper := newAquaStarboardHelper(cr)
	deployment := starboardHelper.CreateStarboardDeployment(cr,
		"starboard-operator",
		"starboard-operator",
		registry,
		tag,
		pullPolicy,
		repository)

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &appsv1.Deployment{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		err = patch.DefaultAnnotator.SetLastAppliedAnnotation(deployment)
		if err != nil {
			reqLogger.Error(err, "Unable to set default for k8s-objectmatcher", err)
		}

		err = r.Client.Create(context.TODO(), deployment)
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
			err = r.Client.Update(context.Background(), deployment)
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
		err = r.Client.List(context.TODO(), podList, listOps)
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
			if !reflect.DeepEqual(v1alpha1.AquaDeploymentUpdateInProgress, currentState) &&
				!reflect.DeepEqual(v1alpha1.AquaDeploymentStatePending, currentState) {
				cr.Status.State = v1alpha1.AquaDeploymentUpdateInProgress
				_ = r.Client.Status().Update(context.Background(), cr)
			}
		} else if !reflect.DeepEqual(v1alpha1.AquaDeploymentStateRunning, currentState) {
			cr.Status.State = v1alpha1.AquaDeploymentStateRunning
			_ = r.Client.Status().Update(context.Background(), cr)
		}
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Starboard Deployment Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{}, nil
}

func (r *AquaStarboardReconciler) updateStarboardServerObject(serviceObject *v1alpha1.AquaService, StarboardImageData *v1alpha1.AquaImage) *v1alpha1.AquaService {

	if serviceObject == nil {
		serviceObject = &v1alpha1.AquaService{
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

func (r *AquaStarboardReconciler) updateStarboardObject(cr *aquasecurityv1alpha1.AquaStarboard) *aquasecurityv1alpha1.AquaStarboard {

	cr.Spec.Infrastructure = common2.UpdateAquaInfrastructureFull(cr.Spec.Infrastructure, cr.Name, cr.Namespace, "starboard")
	return cr
}

func (r *AquaStarboardReconciler) addStarboardClusterRole(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create Aqua Starboard Cluster Role")
	reqLogger.Info("Start creating starboard cluster role")

	starboardHelper := newAquaStarboardHelper(cr)
	crole := starboardHelper.CreateStarboardClusterRole(cr.Name, cr.Namespace)

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crole, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRole already exists
	found := &rbacv1.ClusterRole{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crole.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New ClusterRole", "ClusterRole.Namespace", crole.Namespace, "ClusterRole.Name", crole.Name)
		err = r.Client.Create(context.TODO(), crole)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Check if the ClusterRole Rules, matches the found Rules
	equal, err := k8s.CompareByHash(crole.Rules, found.Rules)

	if err != nil {
		return reconcile.Result{}, err
	}

	if !equal {
		found = crole
		log.Info("Aqua Starboard: Updating ClusterRole", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
		err := r.Client.Update(context.TODO(), found)
		if err != nil {
			log.Error(err, "Failed to update ClusterRole", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true}, nil
	}

	// ClusterRole already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua ClusterRole Exists", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaStarboardReconciler) addStarboardRole(ro *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create Aqua Starboard Role")
	reqLogger.Info("Start creating starboard role")

	starboardHelper := newAquaStarboardHelper(ro)
	role := starboardHelper.CreateStarboardRole(ro.Name, ro.Namespace)

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(ro, role, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this Role already exists
	found := &rbacv1.Role{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: role.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New Role", "Role.Namespace", role.Namespace, "Role.Name", role.Name)
		err = r.Client.Create(context.TODO(), role)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Check if the Role Rules, matches the found Rules
	equal, err := k8s.CompareByHash(role.Rules, found.Rules)

	if err != nil {
		return reconcile.Result{}, err
	}

	if !equal {
		found = role
		log.Info("Aqua Starboard: Updating Role", "Role.Namespace", found.Namespace, "Role.Name", found.Name)
		err := r.Client.Update(context.TODO(), found)
		if err != nil {
			log.Error(err, "Failed to update Role", "Role.Namespace", found.Namespace, "Role.Name", found.Name)
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true}, nil
	}

	// Role already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Role Exists", "Role.Namespace", found.Namespace, "Role.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaStarboardReconciler) createAquaStarboardServiceAccount(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create Aqua Starboard Service Account")
	reqLogger.Info("Start creating aqua starboard service account")

	// Define a new service account object
	starboardHelper := newAquaStarboardHelper(cr)
	sa := starboardHelper.CreateStarboardServiceAccount(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		cr.Spec.Infrastructure.ServiceAccount)

	// Set AquaStarboardKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, sa, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this service account already exists
	found := &corev1.ServiceAccount{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: sa.Name, Namespace: sa.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Service Account", "ServiceAccount.Namespace", sa.Namespace, "ServiceAccount.Name", sa.Name)
		err = r.Client.Create(context.TODO(), sa)
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

func (r *AquaStarboardReconciler) addStarboardClusterRoleBinding(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create ClusterRoleBinding")
	reqLogger.Info("Start creating ClusterRole")

	// Define a new ClusterRoleBinding object
	starboardHelper := newAquaStarboardHelper(cr)
	crb := starboardHelper.CreateClusterRoleBinding(cr.Name,
		cr.Namespace,
		"starboard-operator",
		"ke-crb",
		cr.Spec.Infrastructure.ServiceAccount,
		"starboard-operator")

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crb.Name, Namespace: crb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", crb.Namespace, "ClusterRoleBinding.Name", crb.Name)
		err = r.Client.Create(context.TODO(), crb)
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

func (r *AquaStarboardReconciler) addStarboardRoleBinding(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create RoleBinding")
	reqLogger.Info("Start creating Role")

	// Define a new RoleBinding object
	starboardHelper := newAquaStarboardHelper(cr)
	rb := starboardHelper.CreateRoleBinding(cr.Name,
		cr.Namespace,
		"starboard-operator",
		"ke-rb",
		cr.Spec.Infrastructure.ServiceAccount,
		"starboard-operator")

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, rb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this RoleBinding already exists
	found := &rbacv1.RoleBinding{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: rb.Name, Namespace: rb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New RoleBinding", "RoleBinding.Namespace", rb.Namespace, "RoleBinding.Name", rb.Name)
		err = r.Client.Create(context.TODO(), rb)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// RoleBinding already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua RoleBinding Exists", "RoleBinding.Namespace", found.Namespace, "Role.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaStarboardReconciler) addStarboardConfigMap(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create ConfigMap")
	reqLogger.Info("Start creating ConfigMap")
	//reqLogger.Info(fmt.Sprintf("cr object : %v", cr.ObjectMeta))

	// Define a new ClusterRoleBinding object
	starboardHelper := newAquaStarboardHelper(cr)
	configMaps := []*corev1.ConfigMap{
		starboardHelper.CreateStarboardConftestConfigMap(cr.Name,
			cr.Namespace,
			"starboard-policies-config",
			"starboard-policies-configmap",
			cr.Spec.KubeEnforcerVersion,
		),
		starboardHelper.CreateStarboardConfigMap(cr.Name,
			cr.Namespace,
			"starboard",
			"starboard",
		),
	}

	configMapsData := make(map[string]string)

	for _, configMap := range configMaps {
		for k, v := range configMap.Data {
			configMapsData[k] = v
		}
	}

	hash, err := extra.GenerateMD5ForSpec(configMapsData)
	if err != nil {
		return reconcile.Result{}, err
	}
	cr.Spec.ConfigMapChecksum += hash

	// Set AquaStarboard instance as the owner and controller
	requeue := true
	for _, configMap := range configMaps {
		// Set AquaStarboard instance as the owner and controller
		if err := controllerutil.SetControllerReference(cr, configMap, r.Scheme); err != nil {
			return reconcile.Result{}, err
		}
		// Check if ConfigMap already exists
		foundConfigMap := &corev1.ConfigMap{}
		err := r.Client.Get(context.TODO(), types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, foundConfigMap)
		if err != nil && errors.IsNotFound(err) {
			reqLogger.Info("Aqua Starboard: Creating a New ConfigMap", "ConfigMap.Namespace", configMap.Namespace, "ConfigMap.Name", configMap.Name)
			err = r.Client.Create(context.TODO(), configMap)

			if err != nil {
				reqLogger.Error(err, fmt.Sprintf("Failed to create configmap name: %s", configMap.Name))
				return reconcile.Result{Requeue: true}, nil
			}
			return reconcile.Result{}, nil
		} else if err != nil {
			return reconcile.Result{}, err
		}

		// Check if the ConfigMap Data, matches the found Data
		if !equality.Semantic.DeepDerivative(configMap.Data, foundConfigMap.Data) {
			foundConfigMap = configMap
			log.Info("Aqua Starboard: Updating ConfigMap", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
			err := r.Client.Update(context.TODO(), foundConfigMap)
			if err != nil {
				log.Error(err, "Aqua Starboard: Failed to update ConfigMap", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
				return reconcile.Result{}, err
			}
			return reconcile.Result{Requeue: true}, nil
		}

		// MutatingWebhookConfiguration already exists - don't requeue
		reqLogger.Info("Skip reconcile: Aqua Starboard ConfigMap Exists", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
	}
	return reconcile.Result{Requeue: requeue}, nil
}

func (r *AquaStarboardReconciler) addStarboardSecret(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create Token Secret")
	reqLogger.Info("Start creating token secret")

	starboardHelper := newAquaStarboardHelper(cr)
	starboardSecret := starboardHelper.CreateStarboardSecret(cr.Name,
		cr.Namespace,
		"aqua-starboard-token",
		"ke-token-secret",
	)

	hash, err := extra.GenerateMD5ForSpec(starboardSecret)
	if err != nil {
		return reconcile.Result{}, err
	}
	cr.Spec.ConfigMapChecksum += hash

	// Set AquaStarboard instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, starboardSecret, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Secret{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: starboardSecret.Name, Namespace: starboardSecret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New token secret", "Secret.Namespace", starboardSecret.Namespace, "Secret.Name", starboardSecret.Name)
		err = r.Client.Create(context.TODO(), starboardSecret)
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

func (r *AquaStarboardReconciler) CreateImagePullSecret(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create Image Pull Secret")
	reqLogger.Info("Start creating aqua images pull secret")

	// Define a new secret object
	secret := secrets.CreatePullImageSecret(
		cr.Name,
		cr.Namespace,
		"ke-image-pull-secret",
		cr.Spec.Config.ImagePullSecret,
		*cr.Spec.RegistryData)

	// Set AquaStarboardKind instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, secret, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this secret already exists
	found := &corev1.Secret{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: secret.Name, Namespace: secret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua Image Pull Secret", "Secret.Namespace", secret.Namespace, "Secret.Name", secret.Name)
		err = r.Client.Create(context.TODO(), secret)
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

func (r *AquaStarboardReconciler) CreateClusterReaderRoleBinding(cr *aquasecurityv1alpha1.AquaStarboard) (reconcile.Result, error) {
	reqLogger := log.WithValues("Starboard Requirements Phase", "Create Starboard ClusterReaderRoleBinding")
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
	if err := controllerutil.SetControllerReference(cr, crb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crb.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Starboard: Creating a New Starboard ClusterReaderRoleBinding", "ClusterReaderRoleBinding.Namespace", crb.Namespace, "ClusterReaderRoleBinding.Name", crb.Name)
		err = r.Client.Create(context.TODO(), crb)
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
