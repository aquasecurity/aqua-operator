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
	"time"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	"k8s.io/api/admissionregistration/v1beta1"
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

	err = c.Watch(&source.Kind{Type: &v1beta1.ValidatingWebhookConfiguration{}}, &handler.EnqueueRequestForOwner{
		IsController: true,
		OwnerType:    &operatorv1alpha1.AquaKubeEnforcer{},
	})
	if err != nil {
		return err
	}

	err = c.Watch(&source.Kind{Type: &v1beta1.MutatingWebhookConfiguration{}}, &handler.EnqueueRequestForOwner{
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

	// set up our server certificate
	cert := &x509.Certificate{
		BasicConstraintsValid: false,
		SerialNumber:          big.NewInt(2020),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		DNSNames:              []string{"aqua-kube-enforcer.aqua.svc", "aqua-kube-enforcer.aqua.svc.cluster.local"},
		Subject: pkix.Name{
			CommonName: "aqua-kube-enforcer.aqua.svc",
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
	if !reflect.DeepEqual(operatorv1alpha1.AquaDeploymentStateRunning, instance.Status.State) {
		instance.Status.State = operatorv1alpha1.AquaDeploymentStatePending
		_ = r.client.Status().Update(context.Background(), instance)
	}

	if instance.Spec.Config.ImagePullSecret == "" {
		instance.Spec.Config.ImagePullSecret = "aqua-registry-secret"
	}

	if instance.Spec.RegistryData != nil {
		_, err = r.CreateImagePullSecret(instance)
		if err != nil {
			return reconcile.Result{}, err
		}
	}
	_, err = r.addKubeEnforcerClusterRole(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

	_, err = r.createAquaServiceAccount(instance)
	if err != nil {
		return reconcile.Result{}, err
	}

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

	return reconcile.Result{Requeue: true}, nil
}

func (r *ReconcileAquaKubeEnforcer) addKubeEnforcerClusterRole(cr *operatorv1alpha1.AquaKubeEnforcer) (reconcile.Result, error) {
	reqLogger := log.WithValues("Aqua KubeEnforcer Phase", "Create Aqua KubeEnforcer Cluster Role")
	reqLogger.Info("Start creating kube-enforcer cluster role")

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	crole := enforcerHelper.CreateKubeEnforcerClusterRole(cr.Name)

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
		"aqua-kube-enforcer-sa")

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
		"aqua-kube-enforcer-sa",
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
		"aqua-kube-enforcer-sa",
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
	found := &v1beta1.ValidatingWebhookConfiguration{}
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
	found := &v1beta1.MutatingWebhookConfiguration{}
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
	configMap := enforcerHelper.CreateKEConfigMap(cr.Name,
		cr.Namespace,
		"aqua-csp-kube-enforcer",
		"ke-configmap",
		cr.Spec.Config.GatewayAddress,
		cr.Spec.Config.ClusterName)

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

	enforcerHelper := newAquaKubeEnforcerHelper(cr)
	deployment := enforcerHelper.CreateKEDeployment(cr.Name,
		cr.Namespace,
		"aqua-kube-enforcer",
		"ke-deployment",
		"aqua-kube-enforcer-sa",
		cr.Spec.ImageData.Registry,
		cr.Spec.ImageData.Tag,
		cr.Spec.Config.ImagePullSecret)

	// Set AquaCsp instance as the owner and controller
	if err := controllerutil.SetControllerReference(cr, deployment, r.scheme); err != nil {
		return reconcile.Result{}, err
	}

	// Check if this object already exists
	found := &appsv1.Deployment{}
	err := r.client.Get(context.TODO(), types.NamespacedName{Name: deployment.Name, Namespace: deployment.Namespace}, found)
	if err != nil && errors.IsNotFound(err) {
		reqLogger.Info("Aqua KubeEnforcer: Creating a New deployment", "Deployment.Namespace", deployment.Namespace, "Deployment.Name", deployment.Name)
		err = r.client.Create(context.TODO(), deployment)
		if err != nil {
			return reconcile.Result{Requeue: true}, nil
		}

		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, err
	}

	if found != nil {
		upgrade := deployment.Spec.Template.Spec.Containers[0].Image != found.Spec.Template.Spec.Containers[0].Image
		reqLogger.Info("Checking for Aqua KubeEnforcer Upgrade", "deployment obj", deployment.Spec.Template.Spec.Containers[0].Image, "found obj", found.Spec.Template.Spec.Containers[0].Image, "upgrade bool", upgrade)
		if upgrade {
			found.Spec.Template.Spec.Containers[0].Image = deployment.Spec.Template.Spec.Containers[0].Image
			err = r.client.Update(context.Background(), found)
			if err != nil {
				reqLogger.Error(err, "Aqua KubeEnforcer: Failed to update Deployment.", "Deployment.Namespace", found.Namespace, "Deployment.Name", found.Name)
				return reconcile.Result{}, err
			}
			// Spec updated - return and requeue
			return reconcile.Result{Requeue: true}, nil
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
