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

package aquakubeenforcer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	syserrors "errors"
	"fmt"
	"github.com/aquasecurity/aqua-operator/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/aqua-operator/controllers/common"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	"github.com/banzaicloud/k8s-objectmatcher/patch"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"math/big"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
)

var log = logf.Log.WithName("controller_aquakubeenforcer")

// AquaKubeEnforcerReconciler reconciles a AquaKubeEnforcer object
type AquaKubeEnforcerReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Certs  *KubeEnforcerCertificates
}

type KubeEnforcerCertificates struct {
	CAKey      []byte
	CACert     []byte
	ServerKey  []byte
	ServerCert []byte
}

//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquakubeenforcers,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquakubeenforcers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=operator.aquasec.com,resources=aquakubeenforcers/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=clusterroles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=roles,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=authorization.k8s.io,resources=rolebindings,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// the AquaKubeEnforcer object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *AquaKubeEnforcerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)
	reqLogger.Info("Reconciling AquaKubeEnforcer")

	if r.Certs == nil {
		reqLogger.Error(syserrors.New("Unable to create KubeEnforcer Certificates"), "Unable to create KubeEnforcer Certificates")
		return reconcile.Result{}, nil
	}
	// Fetch the AquaKubeEnforcer instance
	instance := &operatorv1alpha1.AquaKubeEnforcer{}
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

	// Check if the Memcached instance is marked to be deleted, which is
	// indicated by the deletion timestamp being set.
	isMemcachedMarkedToBeDeleted := instance.GetDeletionTimestamp() != nil
	if isMemcachedMarkedToBeDeleted {
		if controllerutil.ContainsFinalizer(instance, consts.AquaKubeEnforcerFinalizer) {
			// Run finalization logic for memcachedFinalizer. If the
			// finalization logic fails, don't remove the finalizer so
			// that we can retry during the next reconciliation.
			if err := r.KubeEnforcerFinalizer(instance); err != nil {
				return ctrl.Result{}, err
			}

			// Remove KubeEnforcerFinalizer. Once all finalizers have been
			// removed, the object will be deleted.
			controllerutil.RemoveFinalizer(instance, consts.AquaKubeEnforcerFinalizer)
			err := r.Update(ctx, instance)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{Requeue: true}, nil
	}

	// Add finalizer for this CR
	if !controllerutil.ContainsFinalizer(instance, consts.AquaKubeEnforcerFinalizer) {
		controllerutil.AddFinalizer(instance, consts.AquaKubeEnforcerFinalizer)
		err = r.Update(ctx, instance)
		if err != nil {
			return ctrl.Result{}, err
		}
	}

	instance = r.updateKubeEnforcerObject(instance)
	r.Client.Update(context.Background(), instance)

	currentStatus := instance.Status.State
	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, currentStatus) &&
		!reflect.DeepEqual(operatorv1alpha1.AquaEnforcerUpdatePendingApproval, currentStatus) &&
		!reflect.DeepEqual(operatorv1alpha1.AquaEnforcerUpdateInProgress, currentStatus) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.Client.Status().Update(context.Background(), instance)
	}

	if instance.Spec.Config.ImagePullSecret == "" && !extra.IsMarketPlace() {
		instance.Spec.Config.ImagePullSecret = "aqua-registry-secret"
	}

	if instance.Spec.RegistryData != nil {
		_, err = r.CreateImagePullSecret(instance)
		if err != nil {
			return reconcile.Result{}, err
		}
	}

	instance.Spec.Infrastructure = common.UpdateAquaInfrastructure(instance.Spec.Infrastructure, consts.AquaKubeEnforcerClusterRoleBidingName, instance.Namespace)

	_, err = r.addKubeEnforcerClusterRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.createAquaServiceAccount(instance)
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

	instance.Spec.KubeEnforcerService = r.updateKubeEnforcerServerObject(instance.Spec.KubeEnforcerService, instance.Spec.ImageData)

	_, err = r.addKEClusterRoleBinding(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKubeEnforcerRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKERoleBinding(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKEValidatingWebhook(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKEMutatingWebhook(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKEConfigMap(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKESecretToken(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKESecretSSL(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKEService(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.addKEDeployment(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	if instance.Spec.DeployStarboard != nil {
		r.installAquaStarboard(instance)
	}

	return ctrl.Result{Requeue: true}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AquaKubeEnforcerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named("aquakubeenforcer-controller").
		WithOptions(controller.Options{Reconciler: r}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&rbacv1.Role{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&rbacv1.ClusterRole{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&admissionv1.ValidatingWebhookConfiguration{}).
		Owns(&admissionv1.MutatingWebhookConfiguration{}).
		Owns(&corev1.ConfigMap{}).
		For(&operatorv1alpha1.AquaKubeEnforcer{}).
		Complete(r)
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Kube-Enforcer-Internal
	----------------------------------------------------------------------------------------------------------------
*/

func GetKECerts() *KubeEnforcerCertificates {
	certs, err := createKECerts()
	if err != nil {
		return nil
	}

	return certs
}

func createKECerts() (*KubeEnforcerCertificates, error) {
	certs := &KubeEnforcerCertificates{}
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2020),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: false,
		Subject: pkix.Name{
			CommonName: "admission_ca",
		},
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return certs, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return certs, err
	}

	// caPEM is ca.crt
	// caPrivKeyPEM is ca.key

	// pem encode
	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return certs, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})
	if err != nil {
		return certs, err
	}

	namespace := extra.GetCurrentNameSpace()

	// set up our server certificate
	cert := &x509.Certificate{
		BasicConstraintsValid: false,
		SerialNumber:          big.NewInt(2020),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:              []string{fmt.Sprintf("aqua-kube-enforcer.%s.svc", namespace), fmt.Sprintf("aqua-kube-enforcer.%s.svc.cluster.local", namespace)},
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("aqua-kube-enforcer.%s.svc", namespace),
		},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return certs, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return certs, err
	}

	// certPEM is server.crt
	// certPrivKeyPEM is server.key

	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return certs, err
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return certs, err
	}

	certs = &KubeEnforcerCertificates{
		CAKey:      caPrivKeyPEM.Bytes(),
		CACert:     certPEM.Bytes(),
		ServerKey:  certPrivKeyPEM.Bytes(),
		ServerCert: certPEM.Bytes(),
	}
	return certs, nil
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Kube-Enforcer
	----------------------------------------------------------------------------------------------------------------
*/
func (r *AquaKubeEnforcerReconciler) updateKubeEnforcerServerObject(serviceObject *operatorv1alpha1.AquaService, kubeEnforcerImageData *operatorv1alpha1.AquaImage) *operatorv1alpha1.AquaService {

	if serviceObject == nil {
		serviceObject = &operatorv1alpha1.AquaService{
			ImageData:   kubeEnforcerImageData,
			ServiceType: string(corev1.ServiceTypeClusterIP),
		}
	} else {
		if serviceObject.ImageData == nil {
			serviceObject.ImageData = kubeEnforcerImageData
		}
		if len(serviceObject.ServiceType) == 0 {
			serviceObject.ServiceType = string(corev1.ServiceTypeClusterIP)
		}

	}

	return serviceObject
}

func (r *AquaKubeEnforcerReconciler) updateKubeEnforcerObject(cr *operatorv1alpha1.AquaKubeEnforcer) *operatorv1alpha1.AquaKubeEnforcer {
	if secrets.CheckIfSecretExists(r.Client, consts.MtlsAquaKubeEnforcerSecretName, cr.Namespace) {
		log.Info(fmt.Sprintf("%s secret found, enabling mtls", consts.MtlsAquaKubeEnforcerSecretName))
		cr.Spec.Mtls = true
	}
	return cr
}

func (r *AquaKubeEnforcerReconciler) addKEDeployment(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Deployment Phase", "Create Deployment")
	reqLogger.Info("Start creating deployment")

	pullPolicy, registry, repository, tag := extra.GetImageData("kube-enforcer", cr.Spec.Infrastructure.Version, cr.Spec.KubeEnforcerService.ImageData, cr.Spec.AllowAnyVersion)

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	deployment := enforcerHelper.CreateKEDeployment(cr,
		consts.AquaKubeEnforcerClusterRoleBidingName,
		"ke-deployment",
		registry,
		tag,
		pullPolicy,
		repository)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &appsv1.Deployment{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
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

		updateEnforcerApproved := true
		if cr.Spec.EnforcerUpdateApproved != nil {
			updateEnforcerApproved = *cr.Spec.EnforcerUpdateApproved
		}

		update, err := k8s.CheckForK8sObjectUpdate("AquaKubeEnforcer deployment", found, deployment)
		if err != nil {
			return reconcile.Result{}, err
		}

		if update && updateEnforcerApproved {
			err = r.Client.Update(context.Background(), deployment)
			if err != nil {
				reqLogger.Error(err, "Aqua KubeEnforcer: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		} else if update && !updateEnforcerApproved {
			cr.Status.State = operatorv1alpha1.AquaEnforcerUpdatePendingApproval
			_ = r.Client.Status().Update(context.Background(), cr)
		} else {
			currentState := cr.Status.State
			if !k8s.IsDeploymentReady(found, 1) {
				if !reflect.DeepEqual(operatorv1alpha1.AquaEnforcerUpdateInProgress, currentState) &&
					!reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStatePending, currentState) {
					cr.Status.State = operatorv1alpha1.AquaEnforcerUpdateInProgress
					_ = r.Client.Status().Update(context.Background(), cr)
				}
			} else if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, currentState) {
				cr.Status.State = operatorv1alpha1.AquaDeploymentStateRunning
				_ = r.Client.Status().Update(context.Background(), cr)
			}
		}
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer Deployment Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) addKubeEnforcerClusterRole(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create Aqua KubeEnforcer Cluster Role")
	reqLogger.Info("Start creating kube-enforcer cluster role")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	crole := enforcerHelper.CreateKubeEnforcerClusterRole(cr.Name, cr.Namespace)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crole, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRole already exists
	found := &rbacv1.ClusterRole{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crole.Name}, found)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ClusterRole", "ClusterRole.Namespace", crole.Namespace, "ClusterRole.Name", crole.Name)
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
		log.Info("Aqua KubeEnforcer: Updating ClusterRole", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
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

func (r *AquaKubeEnforcerReconciler) addKEClusterRoleBinding(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create ClusterRoleBinding")
	reqLogger.Info("Start creating ClusterRole")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	crb := enforcerHelper.CreateClusterRoleBinding(cr.Name,
		cr.Namespace,
		consts.AquaKubeEnforcerClusterRoleBidingName,
		"ke-crb",
		cr.Spec.Infrastructure.ServiceAccount,
		consts.AquaKubeEnforcerClusterRoleBidingName)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crb.Name, Namespace: crb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", crb.Namespace, "ClusterRoleBinding.Name", crb.Name)
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

func (r *AquaKubeEnforcerReconciler) CreateClusterReaderRoleBinding(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create KubeEnforcer ClusterReaderRoleBinding")
	reqLogger.Info("Start creating KubeEnforcer ClusterReaderRoleBinding")

	crb := rbac.CreateClusterRoleBinding(
		cr.Name,
		cr.Namespace,
		consts.AquaKubeEnforcerSAClusterReaderRoleBind,
		fmt.Sprintf("%s-kube-enforcer-cluster-reader", cr.Name),
		"Deploy Aqua KubeEnforcer Cluster Reader Role Binding",
		"aqua-kube-enforcer-sa",
		consts.ClusterReaderRole)

	// Set AquaKube-enforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: crb.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New KubeEnfocer ClusterReaderRoleBinding", "ClusterReaderRoleBinding.Namespace", crb.Namespace, "ClusterReaderRoleBinding.Name", crb.Name)
		err = r.Client.Create(context.TODO(), crb)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// ClusterRoleBinding already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer ClusterReaderRoleBinding Exists", "ClusterRoleBinding.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) createAquaServiceAccount(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create Aqua KubeEnforcer Service Account")
	reqLogger.Info("Start creating aqua kube-enforcer service account")

	// Define a new service account object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	sa := enforcerHelper.CreateKEServiceAccount(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		cr.Spec.Infrastructure.ServiceAccount)

	// Set AquaKubeEnforcerKind instance as the owner and controller
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

func (r *AquaKubeEnforcerReconciler) addKubeEnforcerRole(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create Aqua KubeEnforcer Role")
	reqLogger.Info("Start creating kube-enforcer role")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	role := enforcerHelper.CreateKubeEnforcerRole(cr.Name, cr.Namespace, consts.AquaKubeEnforcerClusterRoleBidingName, fmt.Sprintf("%s-requirments", cr.Name))

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, role, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this Role already exists
	found := &rbacv1.Role{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ClusterRole", "ClusterRole.Namespace", role.Namespace, "ClusterRole.Name", role.Name)
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
		log.Info("Aqua KubeEnforcer: Updating Role", "Role.Namespace", found.Namespace, "Role.Name", found.Name)
		err := r.Client.Update(context.TODO(), found)
		if err != nil {
			log.Error(err, "Failed to update Role", "Role.Namespace", found.Namespace, "Role.Name", found.Name)
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true}, nil
	}

	// ClusterRole already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua ClusterRole Exists", "ClusterRole.Namespace", found.Namespace, "ClusterRole.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) addKERoleBinding(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create RoleBinding")
	reqLogger.Info("Start creating RoleBinding")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	rb := enforcerHelper.CreateRoleBinding(cr.Name,
		cr.Namespace,
		consts.AquaKubeEnforcerClusterRoleBidingName,
		"ke-rb",
		cr.Spec.Infrastructure.ServiceAccount,
		consts.AquaKubeEnforcerClusterRoleBidingName)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, rb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this RoleBinding already exists
	found := &rbacv1.RoleBinding{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: rb.Name, Namespace: rb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", rb.Namespace, "ClusterRoleBinding.Name", rb.Name)
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

func (r *AquaKubeEnforcerReconciler) addKEValidatingWebhook(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create ValidatingWebhookConfiguration")
	reqLogger.Info("Start creating ValidatingWebhookConfiguration")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	validWebhook := enforcerHelper.CreateValidatingWebhook(cr.Name,
		cr.Namespace,
		consts.AquaKubeEnforcerValidatingWebhookConfigurationName,
		"ke-validatingwebhook",
		consts.AquaKubeEnforcerClusterRoleBidingName,
		r.Certs.CACert)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, validWebhook, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ValidatingWebhookConfiguration already exists
	found := &admissionv1.ValidatingWebhookConfiguration{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: validWebhook.Name, Namespace: validWebhook.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ValidatingWebhookConfiguration", "ValidatingWebhook.Namespace", validWebhook.Namespace, "ClusterRoleBinding.Name", validWebhook.Name)
		err = r.Client.Create(context.TODO(), validWebhook)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// ValidatingWebhookConfiguration already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua ValidatingWebhookConfiguration Exists", "ValidatingWebhookConfiguration.Namespace", found.Namespace, "ValidatingWebhookConfiguration.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) addKEMutatingWebhook(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create MutatingWebhookConfiguration")
	reqLogger.Info("Start creating MutatingWebhookConfiguration")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	mutateWebhook := enforcerHelper.CreateMutatingWebhook(cr.Name,
		cr.Namespace,
		consts.AquaKubeEnforcerMutantingWebhookConfigurationName,
		"ke-mutatingwebhook",
		consts.AquaKubeEnforcerClusterRoleBidingName,
		r.Certs.CACert)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, mutateWebhook, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &admissionv1.MutatingWebhookConfiguration{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: mutateWebhook.Name, Namespace: mutateWebhook.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New MutatingWebhookConfiguration", "MutatingWebhook.Namespace", mutateWebhook.Namespace, "ClusterRoleBinding.Name", mutateWebhook.Name)
		err = r.Client.Create(context.TODO(), mutateWebhook)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// MutatingWebhookConfiguration already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua MutatingWebhookConfiguration Exists", "MutatingWebhookConfiguration.Namespace", found.Namespace, "MutatingWebhookConfiguration.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) addKEConfigMap(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create ConfigMap")
	reqLogger.Info("Start creating ConfigMap")
	//reqLogger.Info(fmt.Sprintf("cr object : %v", cr.ObjectMeta))

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	deployStarboard := false
	if cr.Spec.DeployStarboard != nil {
		deployStarboard = true
	}
	configMap := enforcerHelper.CreateKEConfigMap(cr.Name,
		cr.Namespace,
		"aqua-csp-kube-enforcer",
		"ke-configmap",
		cr.Spec.Config.GatewayAddress,
		cr.Spec.Config.ClusterName,
		deployStarboard)
	hash, err := extra.GenerateMD5ForSpec(configMap.Data)
	if err != nil {
		return reconcile.Result{}, err
	}
	cr.Spec.ConfigMapChecksum = hash

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, configMap, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ConfigMap already exists
	foundConfigMap := &corev1.ConfigMap{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, foundConfigMap)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ConfigMap", "ConfigMap.Namespace", configMap.Namespace, "ConfigMap.Name", configMap.Name)
		err = r.Client.Create(context.TODO(), configMap)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// Check if the ConfigMap Data, matches the found Data
	if !equality.Semantic.DeepDerivative(configMap.Data, foundConfigMap.Data) {
		foundConfigMap = configMap
		log.Info("Aqua KubeEnforcer: Updating ConfigMap", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
		err := r.Client.Update(context.TODO(), foundConfigMap)
		if err != nil {
			log.Error(err, "Failed to update ConfigMap", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
			return reconcile.Result{}, err
		}

		return reconcile.Result{Requeue: true}, nil
	}

	// MutatingWebhookConfiguration already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer ConfigMap Exists", "ConfigMap.Namespace", foundConfigMap.Namespace, "ConfigMap.Name", foundConfigMap.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) addKESecretToken(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create Token Secret")
	reqLogger.Info("Start creating token secret")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	tokenSecret := enforcerHelper.CreateKETokenSecret(cr.Name,
		cr.Namespace,
		"aqua-kube-enforcer-token",
		"ke-token-secret",
		cr.Spec.Token)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, tokenSecret, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Secret{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: tokenSecret.Name, Namespace: tokenSecret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New token secret", "Secret.Namespace", tokenSecret.Namespace, "Secret.Name", tokenSecret.Name)
		err = r.Client.Create(context.TODO(), tokenSecret)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer Token Secret Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) addKESecretSSL(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create SSL Secret")
	reqLogger.Info("Start creating ssl secret")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	sslSecret := enforcerHelper.CreateKESSLSecret(cr.Name,
		cr.Namespace,
		"kube-enforcer-ssl",
		"ke-ssl-secret",
		r.Certs.ServerKey,
		r.Certs.ServerCert)

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, sslSecret, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Secret{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: sslSecret.Name, Namespace: sslSecret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ssl secret", "Secret.Namespace", sslSecret.Namespace, "Secret.Name", sslSecret.Name)
		err = r.Client.Create(context.TODO(), sslSecret)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer SSL Secret Exists", "Secret.Namespace", found.Namespace, "Secret.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) addKEService(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create Service")
	reqLogger.Info("Start creating service")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	service := enforcerHelper.CreateKEService(cr.Name,
		cr.Namespace,
		consts.AquaKubeEnforcerClusterRoleBidingName,
		"ke-service")

	// Set AquaKubeEnforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, service, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Service{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: service.Name, Namespace: service.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New service", "Service.Namespace", service.Namespace, "Service.Name", service.Name)
		err = r.Client.Create(context.TODO(), service)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer Service Exists", "Service.Namespace", found.Namespace, "Service.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *AquaKubeEnforcerReconciler) CreateImagePullSecret(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Requirements Phase", "Create Image Pull Secret")
	reqLogger.Info("Start creating aqua images pull secret")

	// Define a new secret object
	secret := secrets.CreatePullImageSecret(
		cr.Name,
		cr.Namespace,
		"ke-image-pull-secret",
		cr.Spec.Config.ImagePullSecret,
		*cr.Spec.RegistryData)

	// Set AquaKubeEnforcerKind instance as the owner and controller
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

// Starboard functions

func (r *AquaKubeEnforcerReconciler) installAquaStarboard(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer AquaStarboard Phase", "Install Aqua Starboard")
	reqLogger.Info("Start installing AquaStarboard")

	// Define a new AquaServer object
	aquaStarboardHelper := newAquaKubeEnforcerHelper(cr)

	aquasb := aquaStarboardHelper.newStarboard(cr)

	// Set AquaKube-enforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquasb, r.Scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaServer already exists
	found := &v1alpha1.AquaStarboard{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: aquasb.Name, Namespace: aquasb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua AquaStarboard", "AquaStarboard.Namespace", aquasb.Namespace, "AquaStarboard.Name", aquasb.Name)
		err = r.Client.Create(context.TODO(), aquasb)
		if err != nil {
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
		}

		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	} else if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	if found != nil {
		size := aquasb.Spec.StarboardService.Replicas
		if found.Spec.StarboardService.Replicas != size {
			found.Spec.StarboardService.Replicas = size
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua Kube-enforcer: Failed to update aqua starboard replicas.", "AquaStarboard.Namespace", found.Namespace, "AquaStarboard.Name", found.Name)
				return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
		}

		update := !reflect.DeepEqual(aquasb.Spec, found.Spec)

		reqLogger.Info("Checking for AquaStarboard Upgrade", "aquasb", aquasb.Spec, "found", found.Spec, "update bool", update)
		if update {
			found.Spec = *(aquasb.Spec.DeepCopy())
			err = r.Client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua Kube-enforcer: Failed to update AquaStarboard.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		}
	}

	// AquaStarboard already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua Starboard Exists", "AquaStarboard.Namespace", found.Namespace, "AquaStarboard.Name", found.Name)
	return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
}

// finalizers

func (r *AquaKubeEnforcerReconciler) KubeEnforcerFinalizer(cr *operatorv1alpha1.AquaKubeEnforcer) error {
	reqLogger := log.WithValues("KubeEnforcer Finalizer Phase", "Remove KE-Webhooks")
	reqLogger.Info("Start removing ValidatingWebhookConfiguration")

	// Check if this ValidatingWebhookConfiguration exists
	validatingWebhookConfiguration := &admissionv1.ValidatingWebhookConfiguration{}
	err := r.Client.Get(context.TODO(), types.NamespacedName{Name: consts.AquaKubeEnforcerValidatingWebhookConfigurationName, Namespace: cr.Namespace}, validatingWebhookConfiguration)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: ValidatingWebhookConfiguration is not found")
	} else if err != nil {
		return err
	}

	if validatingWebhookConfiguration != nil {
		err = r.Client.Delete(context.TODO(), validatingWebhookConfiguration)
		if err != nil {
			return err
		}
		reqLogger.Info("Successfully removed ValidatingWebhookConfiguration")
	}

	// Check if this ValidatingWebhookConfiguration exists
	reqLogger.Info("Start removing MutatingWebhookConfiguration")
	mutatingWebhookConfiguration := &admissionv1.MutatingWebhookConfiguration{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: consts.AquaKubeEnforcerMutantingWebhookConfigurationName, Namespace: cr.Namespace}, mutatingWebhookConfiguration)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: MutatingWebhookConfiguration is not found")
	} else if err != nil {
		return err
	}

	if mutatingWebhookConfiguration != nil {
		err = r.Client.Delete(context.TODO(), mutatingWebhookConfiguration)
		if err != nil {
			return err
		}
		reqLogger.Info("Successfully removed MutatingWebhookConfiguration")
	}

	// Check if this ClusterRoleBinding exists
	cRoleBinding := &rbacv1.ClusterRoleBinding{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: consts.AquaKubeEnforcerClusterRoleBidingName, Namespace: cr.Namespace}, cRoleBinding)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: ClusterRoleBinding is not found")
	} else if err != nil {
		return err
	}

	if validatingWebhookConfiguration != nil {
		err = r.Client.Delete(context.TODO(), cRoleBinding)
		if err != nil {
			return err
		}
		reqLogger.Info("Successfully removed clusterRoleBinding")
	}

	// Check if this ClusterReaderRoleBinding exists
	cRoleReaderRoleBinding := &rbacv1.ClusterRoleBinding{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: consts.AquaKubeEnforcerSAClusterReaderRoleBind, Namespace: cr.Namespace}, cRoleReaderRoleBinding)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: ClusterReaderRoleBinding is not found")
	} else if err != nil {
		return err
	}

	if validatingWebhookConfiguration != nil {
		err = r.Client.Delete(context.TODO(), cRoleReaderRoleBinding)
		if err != nil {
			return err
		}
		reqLogger.Info("Successfully removed ClusterReaderRoleBinding")
	}

	// Check if this ClusterRole exists
	cRole := &rbacv1.ClusterRole{}
	err = r.Client.Get(context.TODO(), types.NamespacedName{Name: consts.AquaKubeEnforcerClusterRoleName}, cRole)

	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: ClusterRole is not found")
	} else if err != nil {
		return err
	}

	if cRole != nil {
		err = r.Client.Delete(context.TODO(), cRole)
		if err != nil {
			return err
		}
		reqLogger.Info("Successfully removed ClusterRole")
	}

	reqLogger.Info("Successfully Finalized")

	return nil
}
