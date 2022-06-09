package operator

import (
	"context"
	"github.com/aquasecurity/aqua-operator/apis/operator/v1alpha1"
	testing_consts "github.com/aquasecurity/aqua-operator/test/consts"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"time"
)

const (
	timeout  = time.Minute * 5
	interval = time.Second * 30
)

var _ = Describe("Aqua Controller", func() {

	Context("Initial deployment", func() {
		namespace := "default"
		name := "aqua"
		//key := types.NamespacedName{
		//	Namespace: namespace,
		//	Name:      name,
		//}

		It("It should create AquaCsp deployment", func() {
			instance := &v1alpha1.AquaCsp{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
				},
				Spec: v1alpha1.AquaCspSpec{
					Infrastructure: &v1alpha1.AquaInfrastructure{
						ServiceAccount: testing_consts.CspServiceAccount,
						Namespace:      testing_consts.NameSpace,
						Version:        testing_consts.Version,
						Requirements:   true,
					},
					Common: &v1alpha1.AquaCommon{
						ImagePullSecret: testing_consts.ImagePullSecret,
						DbDiskSize:      testing_consts.DbDiskSize,
						DatabaseSecret: &v1alpha1.AquaSecret{
							Name: testing_consts.DatabaseSecretName,
							Key:  testing_consts.DataBaseSecretKey,
						},
					},
					DbService: &v1alpha1.AquaService{
						Replicas:    1,
						ServiceType: "ClusterIp",
						ImageData: &v1alpha1.AquaImage{
							Registry:   testing_consts.Registry,
							Repository: testing_consts.DatabaseRepo,
							PullPolicy: "Always",
						},
					},
					GatewayService: &v1alpha1.AquaService{
						Replicas:    1,
						ServiceType: "ClusterIp",
						ImageData: &v1alpha1.AquaImage{
							Registry:   testing_consts.Registry,
							Repository: testing_consts.GatewayRepo,
							PullPolicy: "Always",
						},
					},
					ServerService: &v1alpha1.AquaService{
						Replicas:    1,
						ServiceType: "LoadBalancer",
						ImageData: &v1alpha1.AquaImage{
							Registry:   testing_consts.Registry,
							Repository: testing_consts.ServerRepo,
							PullPolicy: "Always",
						},
					},
					Route:        true,
					RunAsNonRoot: false,
				},
			}
			Expect(k8sClient.Create(context.Background(), instance)).Should(Succeed())
			cspLookupKey := types.NamespacedName{Name: name, Namespace: namespace}
			csp := &v1alpha1.AquaCsp{}

			Eventually(func() bool {
				err := k8sClient.Get(context.Background(), cspLookupKey, csp)
				if err != nil {
					return false
				}
				return true
			}, timeout, interval).Should(BeTrue())
			// Let's make sure our Schedule string value was properly converted/handled.
			Expect(csp.Status.State).Should(Equal("Running"))

		})
	})
})
