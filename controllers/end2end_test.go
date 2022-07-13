package controllers

import (
	"context"
	"fmt"
	aquasecurityv1alpha1 "github.com/aquasecurity/aqua-operator/apis/aquasecurity/v1alpha1"
	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	testingconsts "github.com/aquasecurity/aqua-operator/test/consts"
	testutils "github.com/aquasecurity/aqua-operator/test/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"time"
)

const (
	timeout             = time.Minute * 6
	interval            = time.Second * 30
	enforcerTimeout     = time.Minute * 3
	scannerTimeout      = time.Minute * 1
	KubeEnforcerTimeout = time.Minute * 5
	StarboardTimeout    = time.Minute * 2
)

var _ = Describe("Aqua Controller", Serial, func() {
	localLog := logf.Log.WithName("AquaCspControllerTest")

	Context("Initial deployment", func() {
		namespace := "aqua"
		name := "aqua"

		It("It should create AquaCsp Deployment", func() {
			instance := &operatorv1alpha1.AquaCsp{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: operatorv1alpha1.AquaCspSpec{
					Infrastructure: &operatorv1alpha1.AquaInfrastructure{
						ServiceAccount: testingconsts.CspServiceAccount,
						Namespace:      testingconsts.NameSpace,
						Version:        testingconsts.Version,
						Requirements:   true,
					},
					Common: &operatorv1alpha1.AquaCommon{
						ImagePullSecret: testingconsts.ImagePullSecret,
						DbDiskSize:      testingconsts.DbDiskSize,
						DatabaseSecret: &operatorv1alpha1.AquaSecret{
							Name: testingconsts.DatabaseSecretName,
							Key:  testingconsts.DataBaseSecretKey,
						},
					},
					DbService: &operatorv1alpha1.AquaService{
						Replicas:    1,
						ServiceType: "ClusterIP",
						ImageData: &operatorv1alpha1.AquaImage{
							Registry:   testingconsts.Registry,
							Repository: testingconsts.DatabaseRepo,
							PullPolicy: "Always",
						},
					},
					GatewayService: &operatorv1alpha1.AquaService{
						Replicas:    1,
						ServiceType: "ClusterIP",
						ImageData: &operatorv1alpha1.AquaImage{
							Registry:   testingconsts.Registry,
							Repository: testingconsts.GatewayRepo,
							PullPolicy: "Always",
						},
					},
					ServerService: &operatorv1alpha1.AquaService{
						Replicas:    1,
						ServiceType: "LoadBalancer",
						ImageData: &operatorv1alpha1.AquaImage{
							Registry:   testingconsts.Registry,
							Repository: testingconsts.ServerRepo,
							PullPolicy: "Always",
						},
					},
					ServerEnvs: []corev1.EnvVar{
						{
							Name:  "LICENSE_TOKEN",
							Value: testutils.GetLicenseToken(),
						},
						{
							Name:  "ADMIN_PASSWORD",
							Value: testingconsts.ServerAdminPassword,
						},
						{
							Name:  "BATCH_INSTALL_NAME",
							Value: testingconsts.EnforcerGroupName,
						},
						{
							Name:  "BATCH_INSTALL_TOKEN",
							Value: testingconsts.EnforcerToken,
						},
						{
							Name:  "BATCH_INSTALL_GATEWAY",
							Value: fmt.Sprintf(testingconsts.GatewayServiceName, name),
						},
						{
							Name:  "AQUA_KE_GROUP_NAME",
							Value: testingconsts.KUbeEnforcerGroupName,
						},
						{
							Name:  "AQUA_KE_GROUP_TOKEN",
							Value: testingconsts.KubeEnforcerToken,
						},
					},
					Route:        true,
					RunAsNonRoot: false,
				},
			}
			Expect(k8sClient.Create(context.Background(), instance)).Should(Succeed())

			cspLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			csp := &operatorv1alpha1.AquaCsp{}

			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), cspLookupKey, csp)
				if err != nil {
					fmt.Fprint(GinkgoWriter, err)
					return false
				}
				if csp.Status.State != operatorv1alpha1.AquaDeploymentStateRunning {
					localLog.Info(fmt.Sprintf("csp state: %s", csp.Status.State))
					return false
				}
				return true
			}, timeout, interval).Should(BeTrue())
		})

		It("It Should create AquaEnforcer DaemonSet", func() {
			instance := &operatorv1alpha1.AquaEnforcer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: operatorv1alpha1.AquaEnforcerSpec{
					Infrastructure: &operatorv1alpha1.AquaInfrastructure{
						ServiceAccount: testingconsts.CspServiceAccount,
						Version:        testingconsts.Version,
					},
					Common: &operatorv1alpha1.AquaCommon{
						ImagePullSecret: testingconsts.ImagePullSecret,
					},

					EnforcerService: &operatorv1alpha1.AquaService{
						ImageData: &operatorv1alpha1.AquaImage{
							Repository: testingconsts.EnforcerRepo,
							Registry:   testingconsts.Registry,
							PullPolicy: "IfNotPresent",
						},
					},
					RunAsNonRoot: false,
					Gateway: &operatorv1alpha1.AquaGatewayInformation{
						Host: fmt.Sprintf("%s-gateway", name),
						Port: testingconsts.GatewayPort,
					},
					Token: testingconsts.EnforcerToken,
				},
			}
			Expect(k8sClient.Create(context.Background(), instance)).Should(Succeed())

			enforcerLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			enforcer := &operatorv1alpha1.AquaEnforcer{}
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), enforcerLookupKey, enforcer)
				if err != nil {
					fmt.Fprint(GinkgoWriter, err)
					return false
				}
				if enforcer.Status.State != operatorv1alpha1.AquaDeploymentStateRunning {
					localLog.Info(fmt.Sprintf("enforcer state: %s", enforcer.Status.State))
					return false
				}
				return true
			}, enforcerTimeout, interval).Should(BeTrue())
		})

		It("It Should create AquaScanner Deployment", func() {
			instance := &operatorv1alpha1.AquaScanner{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: operatorv1alpha1.AquaScannerSpec{
					Infrastructure: &operatorv1alpha1.AquaInfrastructure{
						ServiceAccount: testingconsts.CspServiceAccount,
						Version:        testingconsts.Version,
					},
					Common: &operatorv1alpha1.AquaCommon{
						ImagePullSecret: testingconsts.ImagePullSecret,
					},
					ScannerService: &operatorv1alpha1.AquaService{
						Replicas: 1,
						ImageData: &operatorv1alpha1.AquaImage{
							Repository: testingconsts.ScannerRepo,
							Registry:   testingconsts.Registry,
							PullPolicy: "IfNotPresent",
						},
					},
					RunAsNonRoot: false,
					Login: &operatorv1alpha1.AquaLogin{
						Username: testingconsts.ServerAdminUser,
						Password: testingconsts.ServerAdminPassword,
						Host:     testingconsts.ServerHost,
					},
				},
			}
			Expect(k8sClient.Create(context.Background(), instance)).Should(Succeed())

			scannerLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			scanner := &operatorv1alpha1.AquaScanner{}
			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), scannerLookupKey, scanner)
				if err != nil {
					fmt.Fprint(GinkgoWriter, err)
					return false
				}
				if scanner.Status.State != operatorv1alpha1.AquaDeploymentStateRunning {
					localLog.Info(fmt.Sprintf("scanner state: %s", scanner.Status.State))
					return false
				}
				return true
			}, scannerTimeout, interval).Should(BeTrue())
		})

		It("It should create AquaKubeEnforcer Deployment", func() {
			instance := &operatorv1alpha1.AquaKubeEnforcer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: operatorv1alpha1.AquaKubeEnforcerSpec{
					Infrastructure: &operatorv1alpha1.AquaInfrastructure{
						ServiceAccount: testingconsts.KubeEnforcerServiceAccount,
						Namespace:      testingconsts.NameSpace,
						Version:        testingconsts.Version,
					},
					Config: operatorv1alpha1.AquaKubeEnforcerConfig{
						GatewayAddress:  testingconsts.GatewayAddress,
						ClusterName:     testingconsts.ClusterName,
						ImagePullSecret: testingconsts.ImagePullSecret,
					},
					KubeEnforcerService: &operatorv1alpha1.AquaService{
						ServiceType: "ClusterIP",
						ImageData: &operatorv1alpha1.AquaImage{
							Registry:   testingconsts.Registry,
							Repository: testingconsts.KeEnforcerRepo,
							PullPolicy: "Always",
						},
					},
					Token: testingconsts.KubeEnforcerToken,
					DeployStarboard: &operatorv1alpha1.AquaStarboardDetails{
						Infrastructure: &operatorv1alpha1.AquaInfrastructure{
							ServiceAccount: testingconsts.StarboardServiceAccount,
						},
						Config: operatorv1alpha1.AquaStarboardConfig{
							ImagePullSecret: testingconsts.StarboardImagePullSecret,
						},
						StarboardService: &operatorv1alpha1.AquaService{
							Replicas: 1,
						},
					},
				},
			}
			Expect(k8sClient.Create(context.Background(), instance)).Should(Succeed())

			keLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			ke := &operatorv1alpha1.AquaKubeEnforcer{}

			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), keLookupKey, ke)
				if err != nil {
					fmt.Fprint(GinkgoWriter, err)
					return false
				}
				if ke.Status.State != operatorv1alpha1.AquaDeploymentStateRunning {
					localLog.Info(fmt.Sprintf("ke state: %s", ke.Status.State))
					return false
				}
				return true
			}, KubeEnforcerTimeout, interval).Should(BeTrue())

			starboard := &aquasecurityv1alpha1.AquaStarboard{}

			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), keLookupKey, starboard)
				if err != nil {
					fmt.Fprint(GinkgoWriter, err)
					return false
				}
				if ke.Status.State != operatorv1alpha1.AquaDeploymentStateRunning {
					localLog.Info(fmt.Sprintf("starboard state: %s", starboard.Status.State))
					return false
				}
				return true
			}, StarboardTimeout, interval).Should(BeTrue())
		})

		// Delete

		It("It should delete AquaKubeEnforcer Deployment", func() {

			keLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			ke := &operatorv1alpha1.AquaKubeEnforcer{}

			err := k8sClient.Get(context.Background(), keLookupKey, ke)
			if err == nil {
				Expect(k8sClient.Delete(context.Background(), ke)).Should(Succeed())
			}

		})

		It("It should delete AquaScanner Deployment", func() {

			scannerLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			scanner := &operatorv1alpha1.AquaScanner{}

			err := k8sClient.Get(context.Background(), scannerLookupKey, scanner)
			if err == nil {
				Expect(k8sClient.Delete(context.Background(), scanner)).Should(Succeed())
			}
		})

		It("It should delete AquaEnforcer DaemonSet", func() {

			enforcerLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			enforcer := &operatorv1alpha1.AquaEnforcer{}

			err := k8sClient.Get(context.Background(), enforcerLookupKey, enforcer)
			if err == nil {
				Expect(k8sClient.Delete(context.Background(), enforcer)).Should(Succeed())
			}
		})

		It("It should delete AquaCsp Deployment", func() {

			cspLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			csp := &operatorv1alpha1.AquaCsp{}

			err := k8sClient.Get(context.Background(), cspLookupKey, csp)
			if err == nil {
				Expect(k8sClient.Delete(context.Background(), csp)).Should(Succeed())
			}

		})
	})
})
