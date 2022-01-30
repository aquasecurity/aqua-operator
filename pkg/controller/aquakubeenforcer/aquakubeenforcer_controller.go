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
	"math/big"
	"reflect"
	"strings"
	"time"

	"github.com/aquasecurity/aqua-operator/pkg/controller/common"

	"github.com/banzaicloud/k8s-objectmatcher/patch"

	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s"

	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/rbac"

	aquasecurity1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/aquasecurity/v1alpha1"
	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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

var log = logf.Log.WithName("controller_aquakubeenforcer")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new AquaKubeEnforcer Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileAquaKubeEnforcer{
		client: mgr.GetClient(),
		scheme: mgr.GetScheme(),
		certs:  GetKECerts(),
	}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("aquakubeenforcer-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource AquaKubeEnforcer
	err = c.Watch(&source.Kind{Type: &operatorv1alpha1.AquaKubeEnforcer{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// TODO(user): Modify this to be the types you create that are owned by the primary resource
	// Watch for changes to secondary resource Pods and requeue the owner AquaKubeEnforcer
	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRole{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ServiceAccount{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &rbacv1.ClusterRoleBinding{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &rbacv1.Role{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &rbacv1.RoleBinding{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &admissionv1.ValidatingWebhookConfiguration{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &admissionv1.MutatingWebhookConfiguration{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.ConfigMap{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &corev1.Service{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &appsv1.Deployment{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	return nil
}

type KubeEnforcerCertificates struct {
	CAKey      []byte
	CACert     []byte
	ServerKey  []byte
	ServerCert []byte
}

// blank assignment to verify that ReconcileAquaKubeEnforcer implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileAquaKubeEnforcer{}

// ReconcileAquaKubeEnforcer reconciles a AquaKubeEnforcer object
type ReconcileAquaKubeEnforcer struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client client.Client
	scheme *runtime.Scheme
	certs  *KubeEnforcerCertificates
}

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

// Reconcile reads that state of the cluster for a AquaKubeEnforcer object and makes changes based on the state read
// and what is in the AquaKubeEnforcer.Spec
// TODO(user): Modify this Reconcile function to implement your Controller logic.  This example creates
// a Pod as an example
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileAquaKubeEnforcer) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling AquaKubeEnforcer")

	if r.certs == nil {
		reqLogger.Error(syserrors.New("Unable to create KubeEnforcer Certificates"), "Unable to create KubeEnforcer Certificates")
		return reconcile.Result{}, nil
	}
	// Fetch the AquaKubeEnforcer instance
	instance := &operatorv1alpha1.AquaKubeEnforcer{}
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
	instance = r.updateKubeEnforcerObject(instance)

	currentStatus := instance.Status.State
	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, currentStatus) &&
		!reflect.DeepEqual(operatorv1alpha1.AquaEnforcerUpdatePendingApproval, currentStatus) &&
		!reflect.DeepEqual(operatorv1alpha1.AquaEnforcerUpdateInProgress, currentStatus) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
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

	instance.Spec.Infrastructure = common.UpdateAquaInfrastructure(instance.Spec.Infrastructure, "aqua-kube-enforcer", instance.Namespace)

	_, err = r.addKubeEnforcerClusterRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.createAquaServiceAccount(instance)
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

	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaKubeEnforcer) updateKubeEnforcerObject(cr *operatorv1alpha1.AquaKubeEnforcer) *operatorv1alpha1.AquaKubeEnforcer {
	if secrets.CheckIfSecretExists(r.client, consts.MtlsAquaKubeEnforcerSecretName, cr.Namespace) {
		log.Info(fmt.Sprintf("%s secret found, enabling mtls", consts.MtlsAquaKubeEnforcerSecretName))
		cr.Spec.Mtls = true
	}
	return cr
}

func (r *ReconcileAquaKubeEnforcer) addKubeEnforcerClusterRole(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Aqua KubeEnforcer Phase", "Create Aqua KubeEnforcer Cluster Role")
	reqLogger.Info("Start creating kube-enforcer cluster role")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	crole := enforcerHelper.CreateKubeEnforcerClusterRole(cr.Name, cr.Namespace)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crole, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRole already exists
	found := &rbacv1.ClusterRole{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: crole.Name, Namespace: crole.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ClusterRole", "ClusterRole.Namespace", crole.Namespace, "ClusterRole.Name", crole.Name)
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

func (r *ReconcileAquaKubeEnforcer) createAquaServiceAccount(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Csp Requirments Phase", "Create Aqua KubeEnforcer Service Account")
	reqLogger.Info("Start creating aqua kube-enforcer service account")

	// Define a new service account object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	sa := enforcerHelper.CreateKEServiceAccount(cr.Name,
		cr.Namespace,
		fmt.Sprintf("%s-requirments", cr.Name),
		cr.Spec.Infrastructure.ServiceAccount)

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

func (r *ReconcileAquaKubeEnforcer) addKEClusterRoleBinding(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - RBAC Phase", "Create ClusterRoleBinding")
	reqLogger.Info("Start creating ClusterRole")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	crb := enforcerHelper.CreateClusterRoleBinding(cr.Name,
		cr.Namespace,
		"aqua-kube-enforcer",
		"ke-crb",
		cr.Spec.Infrastructure.ServiceAccount,
		"aqua-kube-enforcer")

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crb, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: crb.Name, Namespace: crb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", crb.Namespace, "ClusterRoleBinding.Name", crb.Name)
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

func (r *ReconcileAquaKubeEnforcer) addKubeEnforcerRole(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Aqua KubeEnforcer Phase", "Create Aqua KubeEnforcer Role")
	reqLogger.Info("Start creating kube-enforcer role")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	role := enforcerHelper.CreateKubeEnforcerRole(cr.Name, cr.Namespace, "aqua-kube-enforcer", fmt.Sprintf("%s-requirments", cr.Name))

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, role, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRole already exists
	found := &rbacv1.Role{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: role.Name, Namespace: role.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New ClusterRole", "ClusterRole.Namespace", role.Namespace, "ClusterRole.Name", role.Name)
		err = r.client.Create(context.TODO(), role)
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

func (r *ReconcileAquaKubeEnforcer) addKERoleBinding(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - RBAC Phase", "Create RoleBinding")
	reqLogger.Info("Start creating RoleBinding")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	rb := enforcerHelper.CreateRoleBinding(cr.Name,
		cr.Namespace,
		"aqua-kube-enforcer",
		"ke-rb",
		cr.Spec.Infrastructure.ServiceAccount,
		"aqua-kube-enforcer")

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, rb, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: rb.Name, Namespace: rb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ClusterRoleBinding", "ClusterRoleBinding.Namespace", rb.Namespace, "ClusterRoleBinding.Name", rb.Name)
		err = r.client.Create(context.TODO(), rb)
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

func (r *ReconcileAquaKubeEnforcer) addKEValidatingWebhook(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - RBAC Phase", "Create ValidatingWebhookConfiguration")
	reqLogger.Info("Start creating ValidatingWebhookConfiguration")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	validWebhook := enforcerHelper.CreateValidatingWebhook(cr.Name,
		cr.Namespace,
		"kube-enforcer-admission-hook-config",
		"ke-validatingwebhook",
		"aqua-kube-enforcer",
		r.certs.CACert)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, validWebhook, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &admissionv1.ValidatingWebhookConfiguration{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: validWebhook.Name, Namespace: validWebhook.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ValidatingWebhookConfiguration", "ValidatingWebhook.Namespace", validWebhook.Namespace, "ClusterRoleBinding.Name", validWebhook.Name)
		err = r.client.Create(context.TODO(), validWebhook)
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

func (r *ReconcileAquaKubeEnforcer) addKEMutatingWebhook(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - RBAC Phase", "Create MutatingWebhookConfiguration")
	reqLogger.Info("Start creating MutatingWebhookConfiguration")

	// Define a new ClusterRoleBinding object
	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	mutateWebhook := enforcerHelper.CreateMutatingWebhook(cr.Name,
		cr.Namespace,
		"kube-enforcer-me-injection-hook-config",
		"ke-mutatingwebhook",
		"aqua-kube-enforcer",
		r.certs.CACert)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, mutateWebhook, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &admissionv1.MutatingWebhookConfiguration{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: mutateWebhook.Name, Namespace: mutateWebhook.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New MutatingWebhookConfiguration", "MutatingWebhook.Namespace", mutateWebhook.Namespace, "ClusterRoleBinding.Name", mutateWebhook.Name)
		err = r.client.Create(context.TODO(), mutateWebhook)
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

func (r *ReconcileAquaKubeEnforcer) addKEConfigMap(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer", "Create ConfigMap")
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

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, configMap, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &corev1.ConfigMap{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: configMap.Name, Namespace: configMap.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ConfigMap", "ConfigMap.Namespace", configMap.Namespace, "ConfigMap.Name", configMap.Name)
		err = r.client.Create(context.TODO(), configMap)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	// MutatingWebhookConfiguration already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer ConfigMap Exists", "ConfigMap.Namespace", found.Namespace, "ConfigMap.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaKubeEnforcer) addKESecretToken(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer", "Create Token Secret")
	reqLogger.Info("Start creating token secret")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	tokenSecret := enforcerHelper.CreateKETokenSecret(cr.Name,
		cr.Namespace,
		"aqua-kube-enforcer-token",
		"ke-token-secret",
		cr.Spec.Token)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, tokenSecret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: tokenSecret.Name, Namespace: tokenSecret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New token secret", "Secret.Namespace", tokenSecret.Namespace, "Secret.Name", tokenSecret.Name)
		err = r.client.Create(context.TODO(), tokenSecret)
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

func (r *ReconcileAquaKubeEnforcer) addKESecretSSL(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer", "Create SSL Secret")
	reqLogger.Info("Start creating ssl secret")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	sslSecret := enforcerHelper.CreateKESSLSecret(cr.Name,
		cr.Namespace,
		"kube-enforcer-ssl",
		"ke-ssl-secret",
		r.certs.ServerKey,
		r.certs.ServerCert)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, sslSecret, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Secret{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: sslSecret.Name, Namespace: sslSecret.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New ssl secret", "Secret.Namespace", sslSecret.Namespace, "Secret.Name", sslSecret.Name)
		err = r.client.Create(context.TODO(), sslSecret)
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

func (r *ReconcileAquaKubeEnforcer) addKEService(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer", "Create Service")
	reqLogger.Info("Start creating service")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	service := enforcerHelper.CreateKEService(cr.Name,
		cr.Namespace,
		"aqua-kube-enforcer",
		"ke-service")

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, service, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &corev1.Service{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: service.Name, Namespace: service.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New service", "Service.Namespace", service.Namespace, "Service.Name", service.Name)
		err = r.client.Create(context.TODO(), service)
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

func (r *ReconcileAquaKubeEnforcer) addKEDeployment(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer", "Create Deployment")
	reqLogger.Info("Start creating deployment")

	pullPolicy, registry, repository, tag := extra.GetImageData("kube-enforcer", cr.Spec.Infrastructure.Version, cr.Spec.KubeEnforcerService.ImageData, cr.Spec.AllowAnyVersion)

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	deployment := enforcerHelper.CreateKEDeployment(cr,
		"aqua-kube-enforcer",
		"ke-deployment",
		registry,
		tag,
		pullPolicy,
		repository)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
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

		updateEnforcerApproved := true
		if cr.Spec.EnforcerUpdateApproved != nil {
			updateEnforcerApproved = *cr.Spec.EnforcerUpdateApproved
		}

		update, err := k8s.CheckForK8sObjectUpdate("AquaKubeEnforcer deployment", found, deployment)
		if err != nil {
			return reconcile.Result{}, err
		}

		if update && updateEnforcerApproved {
			err = r.client.Update(context.Background(), deployment)
			if err != nil {
				reqLogger.Error(err, "Aqua KubeEnforcer: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
		} else if update && !updateEnforcerApproved {
			cr.Status.State = operatorv1alpha1.AquaEnforcerUpdatePendingApproval
			_ = r.client.Status().Update(context.Background(), cr)
		} else {
			currentState := cr.Status.State
			if !k8s.IsDeploymentReady(found, 1) {
				if !reflect.DeepEqual(operatorv1alpha1.AquaEnforcerUpdateInProgress, currentState) &&
					!reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStatePending, currentState) {
					cr.Status.State = operatorv1alpha1.AquaEnforcerUpdateInProgress
					_ = r.client.Status().Update(context.Background(), cr)
				}
			} else if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, currentState) {
				cr.Status.State = operatorv1alpha1.AquaDeploymentStateRunning
				_ = r.client.Status().Update(context.Background(), cr)
			}
		}
	}

	// object already exists - don't requeue
	reqLogger.Info("Skip reconcile: Aqua KubeEnforcer Deployment Exists", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaKubeEnforcer) CreateImagePullSecret(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Csp Requirments Phase", "Create Image Pull Secret")
	reqLogger.Info("Start creating aqua images pull secret")

	// Define a new secret object
	secret := secrets.CreatePullImageSecret(
		cr.Name,
		cr.Namespace,
		"ke-image-pull-secret",
		cr.Spec.Config.ImagePullSecret,
		*cr.Spec.RegistryData)

	// Set AquaCspKind instance as the owner and controller
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

func (r *ReconcileAquaKubeEnforcer) CreateClusterReaderRoleBinding(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("KubeEnforcer Phase", "Create KubeEnforcer ClusterReaderRoleBinding")
	reqLogger.Info("Start creating KubeEnforcer ClusterReaderRoleBinding")

	crb := rbac.CreateClusterRoleBinding(
		cr.Name,
		cr.Namespace,
		consts.AquaKubeEnforcerSAClusterReaderRoleBind,
		fmt.Sprintf("%s-kube-enforcer-cluster-reader", cr.Name),
		"Deploy Aqua KubeEnforcer Cluster Reader Role Binding",
		"aqua-kube-enforcer",
		consts.ClusterReaderRole)

	// Set AquaKube-enforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, crb, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this ClusterRoleBinding already exists
	found := &rbacv1.ClusterRoleBinding{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: crb.Name}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua CSP: Creating a New KubeEnfocer ClusterReaderRoleBinding", "ClusterReaderRoleBinding.Namespace", crb.Namespace, "ClusterReaderRoleBinding.Name", crb.Name)
		err = r.client.Create(context.TODO(), crb)
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

func (r *ReconcileAquaKubeEnforcer) updateKubeEnforcerServerObject(serviceObject *operatorv1alpha1.AquaService, kubeEnforcerImageData *operatorv1alpha1.AquaImage) *operatorv1alpha1.AquaService {

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

// Starboard functions

func (r *ReconcileAquaKubeEnforcer) installAquaStarboard(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Kube-enforcer - AquaStarboard Phase", "Install Aqua Starboard")
	reqLogger.Info("Start installing AquaStarboard")

	// Define a new AquaServer object
	aquaStarboardHelper := newAquaKubeEnforcerHelper(cr)

	aquasb := aquaStarboardHelper.newStarboard(cr)

	// Set AquaKube-enforcer instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, aquasb, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this AquaServer already exists
	found := &aquasecurity1alpha1.AquaStarboard{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: aquasb.Name, Namespace: aquasb.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Creating a New Aqua AquaStarboard", "AquaStarboard.Namespace", aquasb.Namespace, "AquaStarboard.Name", aquasb.Name)
		err = r.client.Create(context.TODO(), aquasb)
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
			err = r.client.Status().Update(context.Background(), found)
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
			err = r.client.Update(context.Background(), found)
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
