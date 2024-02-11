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

package aqualightning

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	stderrors "errors"
	"fmt"
	"github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/controllers/common"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	"github.com/aquasecurity/aqua-operator/pkg/utils/k8s/secrets"
	corev1 "k8s.io/api/core/v1"
	"math/big"
	ctrl "sigs.k8s.io/controller-runtime"
	//"github.com/aquasecurity/aqua-operator/controllers/common"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	//ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const maxRetries = 3
const retryDelay = 1 * time.Second

var log = logf.Log.WithName("controller_aqualightning")

// AquaLightningReconciler reconciles a AquaKubeEnforcer object
type AquaLightningReconciler struct {
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

func (r *AquaLightningReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		result, err := r.reconcileOnce(ctx, req)
		if err == nil {
			return result, nil
		}

		if errors.IsConflict(err) {
			// Conflict error encountered, retry after delay
			time.Sleep(retryDelay)
			continue
		}

		return result, err
	}

	return reconcile.Result{}, stderrors.New("exhausted max retries")
}

func (r *AquaLightningReconciler) reconcileOnce(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", req.Namespace, "Request.Name", req.Name)
	reqLogger.Info("Reconciling AquaLightning")

	// Fetch the AquaCsp instance
	instance := &v1alpha1.AquaLightning{}
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

	instance = r.updateLightningObject(instance)

	_, err = r.InstallAquaEnforcer(instance)
	if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	_, err = r.InstallAquaKubeEnforcer(instance)
	if err != nil {
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, err
	}

	waitForEnforcer := true
	waitForKubeEnforcer := true

	if !reflect.DeepEqual(v1alpha1.AquaDeploymentUpdateInProgress, instance.Status.State) &&
		(waitForKubeEnforcer || waitForEnforcer) {
		crStatus := r.WaitForEnforcersReady(instance, waitForEnforcer, waitForKubeEnforcer)
		if !reflect.DeepEqual(instance.Status.State, crStatus) {
			instance.Status.State = crStatus
			_ = r.Client.Status().Update(context.Background(), instance)
		}
		return reconcile.Result{Requeue: true, RequeueAfter: time.Duration(0)}, nil
	}
	reqLogger.Info("Finished Reconciling AquaLightning")
	return ctrl.Result{}, nil
}

/*	----------------------------------------------------------------------------------------------------------------
							Aqua Lightning
	----------------------------------------------------------------------------------------------------------------
*/

func (r *AquaLightningReconciler) updateLightningObject(cr *v1alpha1.AquaLightning) *v1alpha1.AquaLightning {
	version := cr.Spec.Enforcer.Infrastructure.Version
	if len(version) == 0 {
		version = consts.LatestVersion
	}

	if cr.Spec.Enforcer.EnforcerService == nil {
		cr.Spec.Enforcer.EnforcerService = &v1alpha1.AquaService{
			ImageData: &v1alpha1.AquaImage{
				Repository: "enforcer",
				Registry:   consts.Registry,
				Tag:        version,
				PullPolicy: consts.PullPolicy,
			},
		}
	}

	cr.Spec.Enforcer.Infrastructure = common.UpdateAquaInfrastructure(cr.Spec.Enforcer.Infrastructure, cr.Name, cr.Namespace)
	cr.Spec.Common = common.UpdateAquaCommon(cr.Spec.Common, cr.Name, false, false)

	if cr.Spec.Common != nil {
		if len(cr.Spec.Common.ImagePullSecret) != 0 {
			exist := secrets.CheckIfSecretExists(r.Client, cr.Spec.Common.ImagePullSecret, cr.Namespace)
			if !exist {
				cr.Spec.Common.ImagePullSecret = consts.EmptyString
			}
		}
	}

	if secrets.CheckIfSecretExists(r.Client, consts.MtlsAquaEnforcerSecretName, cr.Namespace) {
		log.Info(fmt.Sprintf("%s secret found, enabling mtls", consts.MtlsAquaEnforcerSecretName))
		cr.Spec.Enforcer.Mtls = true
	}
	if secrets.CheckIfSecretExists(r.Client, consts.MtlsAquaKubeEnforcerSecretName, cr.Namespace) {
		log.Info(fmt.Sprintf("%s secret found, enabling mtls", consts.MtlsAquaKubeEnforcerSecretName))
		cr.Spec.KubeEnforcer.Mtls = true
	}
	return cr
}

func (r *AquaLightningReconciler) InstallAquaKubeEnforcer(cr *v1alpha1.AquaLightning) (reconcile.Result, error) {
	reqLogger := log.WithValues("CSP - AquaKubeEnforcer Phase", "Install Aqua Enforcer")
	reqLogger.Info("Start installing AquaKubeEnforcer")

	// Define a new AquaEnforcer object
	lightningHelper := newAquaLightningHelper(cr)
	enforcer := lightningHelper.newAquaKubeEnforcer(cr)

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

func (r *AquaLightningReconciler) InstallAquaEnforcer(cr *v1alpha1.AquaLightning) (reconcile.Result, error) {
	reqLogger := log.WithValues("Lightning - AquaEnforcer Phase", "Install Aqua Enforcer")
	reqLogger.Info("Start installing AquaEnforcer")

	// Define a new AquaEnforcer object
	lightningHelper := newAquaLightningHelper(cr)
	enforcer := lightningHelper.newAquaEnforcer(cr)

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

func (r *AquaLightningReconciler) WaitForEnforcersReady(cr *v1alpha1.AquaLightning, validateEnforcer, validateKubeEnforcer bool) v1alpha1.AquaDeploymentState {
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

// SetupWithManager sets up the controller with the Manager.
func (r *AquaLightningReconciler) SetupWithManager(mgr ctrl.Manager) error {
	builder := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AquaLightning{}).
		Named("aqualightning-controller").
		Owns(&corev1.Secret{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&v1alpha1.AquaDatabase{}).
		Owns(&v1alpha1.AquaEnforcer{}).
		Owns(&v1alpha1.AquaKubeEnforcer{})

	return builder.Complete(r)
}
