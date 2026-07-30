/*
Copyright 2025.

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

package aquatrivy

import (
	"context"
	"fmt"
	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	common2 "github.com/aquasecurity/aqua-operator/controllers/common"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"
	"github.com/banzaicloud/k8s-objectmatcher/patch"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	aquasecurityv1alpha1 "github.com/aquasecurity/aqua-operator/apis/aquasecurity/v1alpha1"
)

var log = logf.Log.WithName("controller_AquaTrivy")

// AquaTrivyReconciler reconciles a AquaTrivy object
type AquaTrivyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=aquasecurity.aquasec.com,resources=aquatrivies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=aquasecurity.aquasec.com,resources=aquatrivies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=aquasecurity.aquasec.com,resources=aquatrivies/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete

// Reconcile
func (r *AquaTrivyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "req.Name", req.Name)
	reqLogger.Info("Reconciling AquaTrivy")

	// Fetch the AquaTrivy instance
	instance := &aquasecurityv1alpha1.AquaTrivy{}
	err := r.Client.Get(context.TODO(), req.NamespacedName, instance)
	if err != nil {
		if errors.IsNotFound(err) {
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	instance = r.updateTrivyObject(instance)
	r.Client.Update(context.Background(), instance)

	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) &&
		!reflect.DeepEqual(operatorv1alpha1.AquaDeploymentUpdateInProgress, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.Client.Status().Update(context.Background(), instance)
	}

	_, err = r.addTrivyClusterRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.createAquaTrivyServiceAccount(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	// Ensure namespaced RBAC for operator and leader election
	if _, err = r.addTrivyNamespacedRole(instance); err != nil {
		return reconcile.Result{}, err
	}
	if _, err = r.addTrivyNamespacedRoleBinding(instance); err != nil {
		return reconcile.Result{}, err
	}
	if _, err = r.addTrivyLeaderElectionRole(instance); err != nil {
		return reconcile.Result{}, err
	}
	if _, err = r.addTrivyLeaderElectionRoleBinding(instance); err != nil {
		return reconcile.Result{}, err
	}

	instance.Spec.TrivyService = r.updateTrivyServerObject(instance.Spec.TrivyService, instance.Spec.ImageData)

	_, err = r.addTrivyClusterRoleBinding(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	// ConfigMaps and Secrets as defined by Trivy charts
	if _, err = r.addTrivyOperatorConfigMap(instance); err != nil {
		return reconcile.Result{}, err
	}
	if _, err = r.addTrivyOperatorSettingsConfigMap(instance); err != nil {
		return reconcile.Result{}, err
	}
	if _, err = r.addTrivyPoliciesConfigMap(instance); err != nil {
		return reconcile.Result{}, err
	}
	if _, err = r.addTrivyTrivyConfigMap(instance); err != nil {
		return reconcile.Result{}, err
	}
	if _, err = r.addTrivySecrets(instance); err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addTrivyConfigMap(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	if _, err = r.addTrivyService(instance); err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addTrivyDeployment(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AquaTrivyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("AquaTrivy-controller").
		WithOptions(controller.Options{Reconciler: r}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&appsv1.Deployment{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		For(&aquasecurityv1alpha1.AquaTrivy{}).
		Complete(r)
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Trivy
	----------------------------------------------------------------------------------------------------------------
*/

func (r *AquaTrivyReconciler) addTrivyDeployment(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	reqLogger := log.WithValues("Trivy deployment phase", "Create Deployment")
	reqLogger.Info("Start creating deployment")
	reqLogger.Info("Aqua Trivy", "cr.Spec.Infrastructure.Version", cr.Spec.Infrastructure.Version)
	pullPolicy, registry, repository, tag := extra.GetImageData("trivy-operator", cr.Spec.Infrastructure.Version, cr.Spec.TrivyService.ImageData, true)

	trivyHelper := newAquaTrivyHelper(cr)
	deployment := trivyHelper.CreateTrivyDeployment(cr,
		"trivy-operator",
		"trivy-operator",
		registry,
		tag,
		pullPolicy,
		repository)

	// Set AquaTrivy instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &appsv1.Deployment{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Trivy: Creating a New deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
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
		update, err := k8s.CheckForK8sObjectUpdate("AquaTrivy deployment", found, deployment)
		if err != nil {
			return reconcile.Result{}, err
		}

		if update {
			err = r.Client.Update(context.Background(), deployment)
			if err != nil {
				reqLogger.Error(err, "Aqua Trivy: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
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
			reqLogger.Error(err, "Aqua Trivy: Failed to list pods.", "AquaTrivy.Namespace", cr.Namespace, "AquaTrivy.Name", cr.Name)
			return reconcile.Result{}, err
		}
		podNames := k8s.PodNames(podList.Items)

		if !reflect.DeepEqual(podNames, cr.Status.Nodes) {
			cr.Status.Nodes = podNames
		}

		currentState := cr.Status.State
		if !k8s.IsDeploymentReady(found, int(cr.Spec.TrivyService.Replicas)) {
			if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentUpdateInProgress, currentState) &&
				!reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStatePending, currentState) {
				cr.Status.State = operatorv1alpha1.AquaDeploymentUpdateInProgress
				_ = r.Client.Status().Update(context.Background(), cr)
			}
		} else if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, currentState) {
			cr.Status.State = operatorv1alpha1.AquaDeploymentStateRunning
			_ = r.Client.Status().Update(context.Background(), cr)
		}
	}

	reqLogger.Info("Skip reconcile: Aqua Trivy Deployment Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) updateTrivyServerObject(serviceObject *operatorv1alpha1.AquaService, TrivyImageData *operatorv1alpha1.AquaImage) *operatorv1alpha1.AquaService {
	if serviceObject == nil {
		serviceObject = &operatorv1alpha1.AquaService{
			ImageData:   TrivyImageData,
			ServiceType: string(corev1.ServiceTypeClusterIP),
		}
	} else {
		if serviceObject.ImageData == nil {
			serviceObject.ImageData = TrivyImageData
		}
		if len(serviceObject.ServiceType) == 0 {
			serviceObject.ServiceType = string(corev1.ServiceTypeClusterIP)
		}
	}
	return serviceObject
}

func (r *AquaTrivyReconciler) updateTrivyObject(cr *aquasecurityv1alpha1.AquaTrivy) *aquasecurityv1alpha1.AquaTrivy {
	cr.Spec.Infrastructure = common2.UpdateAquaInfrastructureFull(cr.Spec.Infrastructure, cr.Name, cr.Namespace, "trivy")
	return cr
}

func (r *AquaTrivyReconciler) addTrivyClusterRole(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	reqLogger := log.WithValues("Trivy Requirements Phase", "Create Aqua Trivy Cluster Role")
	reqLogger.Info("Start creating trivy cluster role")

	trivyHelper := newAquaTrivyHelper(cr)
	crole := trivyHelper.CreateTrivyClusterRole(cr.Name, cr.Namespace)

	if err := controllerutil.SetControllerReference(cr, crole, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	found := &rbacv1.ClusterRole{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crole.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Trivy: Creating a New ClusterRole", "ClusterRole.Namespace", crole.Namespace, "ClusterRole.Name", crole.Name)
		err = r.Client.Create(context.TODO(), crole)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	equal, err := k8s.CompareByHash(crole.Rules, found.Rules)
	if err != nil {
		return reconcile.Result{}, err
	}

	if !equal {
		found = crole
		log.Info("Aqua Trivy: Updating ClusterRole", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
		err := r.Client.Update(context.TODO(), found)
		if err != nil {
			log.Error(err, "Failed to update ClusterRole", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	reqLogger.Info("Skip reconcile: Aqua ClusterRole Exists", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaTrivyReconciler) createAquaTrivyServiceAccount(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	reqLogger := log.WithValues("Trivy Requirements Phase", "Create Aqua Trivy Service Account")
	reqLogger.Info("Start creating aqua trivy service account")

	trivyHelper := newAquaTrivyHelper(cr)
	sa := trivyHelper.CreateTrivyServiceAccount(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		cr.Spec.Infrastructure.ServiceAccount)

	if err := controllerutil.SetControllerReference(cr, sa, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

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

	reqLogger.Info("Skip reconcile: Aqua Service Account Already Exists", "ServiceAccount.Namespace", found.Namespace, "ServiceAccount.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaTrivyReconciler) addTrivyClusterRoleBinding(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	reqLogger := log.WithValues("Trivy Requirements Phase", "Create ClusterRoleBinding")
	reqLogger.Info("Start creating ClusterRoleBinding")

	trivyHelper := newAquaTrivyHelper(cr)
	crb := trivyHelper.CreateClusterRoleBinding(cr.Name,
		cr.Namespace,
		"trivy-operator",
		"ke-crb",
		cr.Spec.Infrastructure.ServiceAccount,
		"trivy-operator")

	if err := controllerutil.SetControllerReference(cr, crb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	found := &rbacv1.ClusterRoleBinding{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crb.Name, Namespace: crb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Trivy: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", crb.Namespace, "ClusterRoleBinding.Name", crb.Name)
		err = r.Client.Create(context.TODO(), crb)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	reqLogger.Info("Skip reconcile: Aqua ClusterRoleBinding Exists", "ClusterRoleBinding.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaTrivyReconciler) addTrivyConfigMap(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	reqLogger := log.WithValues("Trivy Requirements Phase", "Create ConfigMap")
	reqLogger.Info("Start creating ConfigMap")

	trivyHelper := newAquaTrivyHelper(cr)
	configMap := trivyHelper.CreateTrivyConfigMap(cr.Name,
		cr.Namespace,
		"trivy",
		"trivy",
	)

	hash, err := extra.GenerateMD5ForSpec(configMap.Data)
	if err != nil {
		return reconcile.Result{}, err
	}
	cr.Spec.ConfigMapChecksum += hash

	if err := controllerutil.SetControllerReference(cr, configMap, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	foundConfigMap := &corev1.ConfigMap{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, foundConfigMap)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua Trivy: Creating a New ConfigMap", "ConfigMap.Namespace", configMap.Namespace, "ConfigMap.Name", configMap.Name)
		err = r.Client.Create(context.TODO(), configMap)
		if err != nil {
			reqLogger.Error(err, fmt.Sprintf("Failed to create configmap name: %s", configMap.Name))
			return reconcile.Result{Requeue: true}, nil
		}
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	if !equality.Semantic.DeepDerivative(configMap.Data, foundConfigMap.Data) {
		foundConfigMap = configMap
		log.Info("Aqua Trivy: Updating ConfigMap", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
		err := r.Client.Update(context.TODO(), foundConfigMap)
		if err != nil {
			log.Error(err, "Aqua Trivy: Failed to update ConfigMap", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}

	reqLogger.Info("Skip reconcile: Aqua Trivy ConfigMap Exists", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaTrivyReconciler) addTrivyNamespacedRole(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	role := trivyHelper.CreateTrivyRole(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, role, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &rbacv1.Role{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), role); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if !equality.Semantic.DeepEqual(found.Rules, role.Rules) {
		found.Rules = role.Rules
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyNamespacedRoleBinding(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	rb := trivyHelper.CreateTrivyRoleBinding(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, rb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &rbacv1.RoleBinding{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: rb.Name, Namespace: rb.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), rb); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if !equality.Semantic.DeepEqual(found.Subjects, rb.Subjects) || !equality.Semantic.DeepEqual(found.RoleRef, rb.RoleRef) {
		found.RoleRef = rb.RoleRef
		found.Subjects = rb.Subjects
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyLeaderElectionRole(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	role := trivyHelper.CreateTrivyLeaderElectionRole(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, role, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &rbacv1.Role{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), role); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if !equality.Semantic.DeepEqual(found.Rules, role.Rules) {
		found.Rules = role.Rules
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyLeaderElectionRoleBinding(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	rb := trivyHelper.CreateTrivyLeaderElectionRoleBinding(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, rb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &rbacv1.RoleBinding{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: rb.Name, Namespace: rb.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), rb); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if !equality.Semantic.DeepEqual(found.Subjects, rb.Subjects) || !equality.Semantic.DeepEqual(found.RoleRef, rb.RoleRef) {
		found.RoleRef = rb.RoleRef
		found.Subjects = rb.Subjects
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyOperatorConfigMap(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	cm := trivyHelper.CreateTrivyOperatorConfigMap(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, cm, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &corev1.ConfigMap{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), cm); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if !equality.Semantic.DeepEqual(found.Data, cm.Data) {
		found.Data = cm.Data
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyOperatorSettingsConfigMap(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	cm := trivyHelper.CreateTrivyOperatorSettingsConfigMap(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, cm, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &corev1.ConfigMap{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), cm); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if !equality.Semantic.DeepEqual(found.Data, cm.Data) {
		found.Data = cm.Data
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyPoliciesConfigMap(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	cm := trivyHelper.CreateTrivyPoliciesConfigMap(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, cm, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &corev1.ConfigMap{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), cm); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	// Keep it empty; only ensure labels stay in sync.
	if !equality.Semantic.DeepEqual(found.Labels, cm.Labels) {
		found.Labels = cm.Labels
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyTrivyConfigMap(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	cm := trivyHelper.CreateTrivyConfigConfigMap(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, cm, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &corev1.ConfigMap{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: cm.Name, Namespace: cm.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), cm); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	if !equality.Semantic.DeepEqual(found.Data, cm.Data) {
		found.Data = cm.Data
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivySecrets(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	secretNames := []string{"trivy-operator", "trivy-operator-trivy-config"}
	for _, name := range secretNames {
		sec := trivyHelper.CreateTrivySecret(cr.Namespace, name)
		if err := controllerutil.SetControllerReference(cr, sec, r.Scheme); err != nil {
			return reconcile.Result{}, err
		}
		found := &corev1.Secret{}
		if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: sec.Name, Namespace: sec.Namespace}, found); err != nil {
			if errors.IsNotFound(err) {
				if err := r.Client.Create(context.TODO(), sec); err != nil {
					return reconcile.Result{}, err
				}
				continue
			}
			return reconcile.Result{}, err
		}
	}
	return reconcile.Result{}, nil
}

func (r *AquaTrivyReconciler) addTrivyService(cr *aquasecurityv1alpha1.AquaTrivy) (reconcile.Result, error) {
	trivyHelper := newAquaTrivyHelper(cr)
	svc := trivyHelper.CreateTrivyService(cr.Namespace)
	if err := controllerutil.SetControllerReference(cr, svc, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}
	found := &corev1.Service{}
	if err := r.Client.Get(context.TODO(), types.NamespacedName{Name: svc.Name, Namespace: svc.Namespace}, found); err != nil {
		if errors.IsNotFound(err) {
			if err := r.Client.Create(context.TODO(), svc); err != nil {
				return reconcile.Result{}, err
			}
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}
	needsUpdate := !equality.Semantic.DeepEqual(found.Labels, svc.Labels) ||
		!equality.Semantic.DeepEqual(found.Spec.Ports, svc.Spec.Ports) ||
		!equality.Semantic.DeepEqual(found.Spec.Selector, svc.Spec.Selector)
	if needsUpdate {
		found.Labels = svc.Labels
		found.Spec.Ports = svc.Spec.Ports
		found.Spec.Selector = svc.Spec.Selector
		if err := r.Client.Update(context.TODO(), found); err != nil {
			return reconcile.Result{}, err
		}
		return reconcile.Result{Requeue: true}, nil
	}
	return reconcile.Result{}, nil
}
