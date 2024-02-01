package test_utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"
	testing_consts "github.com/aquasecurity/aqua-operator/test/consts"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"os"
	"os/exec"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

var k8sClient client.Client

func CreateAquaDatabasePassword(namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aqua-database-password",
			Namespace: namespace,
		},
		StringData: map[string]string{"db-password": "@Password1"},
	}
}
func CreatePullingSecret(namespace string) *corev1.Secret {
	username := os.Getenv("REGISTRY_USERNAME")
	if username == "" {
		panic("missing 'REGISTRY_USERNAME' environment variable, please set it")
	}
	password := os.Getenv("REGISTRY_PASSWORD")
	if password == "" {
		panic("missing 'REGISTRY_PASSWORD' environment variable, please set it")
	}
	base64Password := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
	dockerCfg := map[string]map[string]map[string]string{"auths": {"registry.aquasec.com": {"username": username, "password": password, "auth": base64Password}}}

	json, _ := json.Marshal(dockerCfg)

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aqua-registry",
			Namespace: namespace,
		},
		Type: "kubernetes.io/dockerconfigjson",
		Data: map[string][]byte{".dockerconfigjson": json},
	}

}

func CreateServiceAccount() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "core/v1",
			Kind:       "ServiceAccount",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hostpath-provisioner",
			Namespace: "local-storage",
		},
	}
}

func CreateClusterRole() *rbacv1.ClusterRole {
	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"persistentvolumes",
			},
			Verbs: []string{
				"get", "list", "watch", "create", "delete",
			},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"persistentvolumeclaims",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"storage.k8s.io",
			},
			Resources: []string{
				"storageclasses",
			},
			Verbs: []string{
				"get", "list", "watch",
			},
		},
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"events",
			},
			Verbs: []string{
				"patch", "update", "create",
			},
		},
	}
	crole := &rbacv1.ClusterRole{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRole",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hostpath-provisioner",
			Namespace: "local-storage",
		},
		Rules: rules,
	}

	return crole
}

func CreateClusterRoleBinding() *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "ClusterRoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "hostpath-provisioner",
		},
		Subjects: []rbacv1.Subject{
			rbacv1.Subject{
				Kind:      "ServiceAccount",
				Name:      "hostpath-provisioner",
				Namespace: "local-storage",
			},
		},
		RoleRef: rbacv1.RoleRef{
			Kind:     "ClusterRole",
			Name:     "hostpath-provisioner",
			APIGroup: "rbac.authorization.k8s.io",
		},
	}
}

func CreateRole() *rbacv1.Role {

	rules := []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"",
			},
			Resources: []string{
				"endpoints",
			},
			Verbs: []string{
				"get", "list", "watch", "update", "create", "patch",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"jobs",
			},
			Verbs: []string{
				"create", "delete",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"leases",
			},
			Verbs: []string{
				"get", "list", "create", "update",
			},
		},
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"pods",
			},
			Verbs: []string{
				"create", "delete",
			},
		},
	}

	role := &rbacv1.Role{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "Role",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "leader-locking-hostpath-provisioner",
			Namespace: "local-storage",
		},
		Rules: rules,
	}
	return role
}

func CreateRoleBinding() *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "rbac.authorization.k8s.io/v1",
			Kind:       "RoleBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "leader-locking-hostpath-provisioner",
			Namespace: "local-storage",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      "hostpath-provisioner",
				Namespace: "local-storage",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "leader-locking-hostpath-provisioner",
		},
	}
}

func CreateHostPathProvisionerDeployment() *appsv1.Deployment {
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "apps/v1",
			Kind:       "Deployment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hostpath-provisioner",
			Namespace: "local-storage",
			Labels: map[string]string{
				"app": "hostpath-provisioner",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: extra.Int32Ptr(int32(1)),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "hostpath-provisioner",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "hostpath-provisioner",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "hostpath-provisioner",
					Volumes: []corev1.Volume{
						{
							Name: "pv-volume",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/tmp/hostpath-provisioner",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "hostpath-provisioner",
							Image:           "mauilion/hostpath-provisioner:dev",
							ImagePullPolicy: corev1.PullPolicy(consts.PullPolicy),
							Env: []corev1.EnvVar{{
								Name: "NODE_NAME",
								ValueFrom: &corev1.EnvVarSource{
									FieldRef: &corev1.ObjectFieldSelector{
										FieldPath: "spec.nodeName",
									},
								},
							},
							},

							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "pv-volume",
									MountPath: "/tmp/hostpath-provisioner",
								},
							},
						},
					},
				},
			},
		},
	}
}

func CreateStorageClass() *storagev1.StorageClass {
	deletePolicy := corev1.PersistentVolumeReclaimDelete
	return &storagev1.StorageClass{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "torage.k8s.io/v1",
			Kind:       "StorageClass",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "standard",
			Annotations: map[string]string{
				"storageclass.kubernetes.io/is-default-class": "true",
			},
		},
		Provisioner:   "example.com/hostpath",
		ReclaimPolicy: &deletePolicy,
	}
}

func CreatePvc(namespace string) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "aquadb-pv",
			Namespace: namespace,
			Labels: map[string]string{
				"app": "aqua-database",
			},
		},
		Spec: corev1.PersistentVolumeSpec{
			StorageClassName: testing_consts.DbPvcStorageClassName,
			Capacity: corev1.ResourceList{
				corev1.ResourceName(corev1.ResourceStorage): resource.MustParse(testing_consts.DbPvcStorageSize),
			},
			AccessModes: []corev1.PersistentVolumeAccessMode{
				"ReadWriteMany",
			},
			PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				HostPath: &corev1.HostPathVolumeSource{
					Path: testing_consts.DbPvcHostPath,
				},
			},
		},
	}
}

func CreateNamespace(namespace string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
}

// CreateNode returns a fake, but ready, K8S node
func CreateNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"for": "aqua-testing-node", "app": "hostpath-provisioner"},
		},
		Spec: corev1.NodeSpec{
			Unschedulable: false,
		},
		Status: corev1.NodeStatus{
			Allocatable: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("1"),
				corev1.ResourceMemory:           resource.MustParse("1Gi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("10Gi"),
			},
			Capacity: corev1.ResourceList{
				corev1.ResourceCPU:              resource.MustParse("1"),
				corev1.ResourceMemory:           resource.MustParse("1Gi"),
				corev1.ResourceEphemeralStorage: resource.MustParse("10Gi"),
			},
			Phase: corev1.NodeRunning,
		},
	}
}

func KindClusterOperations(operation string) error {
	var err error
	//var out []byte
	log := logf.Log.WithName("KindClusterOperations")
	log.Info(fmt.Sprintf("Going to %s Kind cluster", operation))
	if operation == "create" {
		_, err = exec.Command("bash", "-c", "PATH=~:/usr/local/bin/:$PATH kind create cluster --config ../test/kind.yaml").Output()
		_, err = exec.Command("bash", "-c", "PATH=~:/usr/local/bin/:$PATH kind get nodes").Output()

		//fmt.Fprint(ginkgo.GinkgoWriter, out)
		//CreateStorageClassIfNotExist()
	} else if operation == "delete" {
		_, err = exec.Command("bash", "-c", "PATH=~:/usr/local/bin/:$PATH && kind delete cluster").Output()
	}
	if err != nil {
		log.Error(err, fmt.Sprintf("Failed to %s Kind cluster", operation))
		return err
	}
	return nil
}

func AddUserToCluster(testEnv envtest.Environment) {
	user, err := testEnv.AddUser(
		envtest.User{
			Name:   "envtest-admin",
			Groups: []string{"system:masters"},
		},
		nil)
	if err != nil {
		logf.Log.Error(err, "Unable to provision admin user, continuing on without it")
	}

	kubeconfigFile, err := os.CreateTemp("", "scratch-env-kubeconfig-")
	if err != nil {
		logf.Log.Error(err, "Unable to create kubeconfig file, continuing on without it")
	}
	defer os.Remove(kubeconfigFile.Name())

	{
		log := logf.Log.WithValues("path", kubeconfigFile.Name())
		log.V(1).Info("Writing kubeconfig")

		kubeConfig, err := user.KubeConfig()
		if err != nil {
			log.Error(err, "Unable to create kubeconfig")
		}

		if _, err := kubeconfigFile.Write(kubeConfig); err != nil {
			log.Error(err, "Unable to save kubeconfig")
		}

		log.Info("Wrote kubeconfig")
	}
}

func GetLicenseToken() string {
	licenseToken := os.Getenv("LICENSE_TOKEN")
	if licenseToken == "" {
		panic("missing 'LICENSE_TOKEN' environment variable, please set it")
	}
	return licenseToken
}

func CreateStorageClassIfNotExist() {
	log := logf.Log.WithName("CreateStorageClassIfNotExist")
	//storageClassLookupKey := types.NamespacedName{Name: "standard", Namespace: "local-storage"}
	//storageClass := &storagev1.StorageClass{}
	storageClassLookupKey := types.NamespacedName{Name: "local-storage"}
	storageClass := &corev1.Namespace{}
	err := k8sClient.Get(context.Background(), storageClassLookupKey, storageClass)

	if err != nil {
		if errors.IsNotFound(err) {
			log.Info("storageClass not exist, going to create it")
			//create storage class
			CreateNamespace("local-storage")
			CreateServiceAccount()
			CreateClusterRole()
			CreateClusterRoleBinding()
			CreateRole()
			CreateRoleBinding()
			CreateHostPathProvisionerDeployment()
			CreateStorageClass()
		} else {
			log.Error(err, "Failed to list storageClass")
		}
	}
	log.Info("storageClass not exist, going to create it")
}

//func GetKubeConfig() (string, error) {
//	log := logf.Log.WithName("GetKubeConfig")
//	kubeconfig, err := exec.Command("bash", "-c", "PATH=~:/usr/local/bin/:$PATH && kind get kubeconfig").Output()
//	if err != nil {
//		log.Error(err, "Failed to get kind kubeconfig file")
//		return nil, err
//	}
//	return string(kubeconfig), nil
//}

//func GetPods(clinet, namespace, chart string) {
//
//	if err != nil {
//		log.Error(err, fmt.Sprintf("Failed to %s Kind cluster", operation))
//		return err
//	}
//
//	_, err = exec.Command("bash", "-c", "PATH=~:/usr/local/bin/:$PATH && kind delete cluster").Output()
//	"kubectl get pods -n ${namespace} -l app.kubernetes.io/instance=aqua-${chart} -o jsonpath='{.items[*].status.containerStatuses[0].ready}'"
//}
