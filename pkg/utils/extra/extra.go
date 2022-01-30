package extra

import (
	"encoding/base64"
	"fmt"
	"github.com/operator-framework/operator-sdk/pkg/k8sutil"
	"os"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"strings"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	corev1 "k8s.io/api/core/v1"

	"github.com/aokoli/goutils"
)

func randAlphaNumeric(count int) string {
	// It is not possible, it appears, to actually generate an error here.
	r, _ := goutils.RandomAlphaNumeric(count)
	return r
}

func CreateRundomPassword() string {
	rand := randAlphaNumeric(20)
	pass := base64.StdEncoding.EncodeToString([]byte(rand))

	return pass
}

func Int32Ptr(i int32) *int32 {
	return &i
}

// checkForUpgrade is making sure that .infra.version contain the latest version.
// if not, there is a need to upgrade the images.
func checkForUpgrade(existingTag string) bool {

	return !strings.Contains(existingTag, consts.LatestVersion)
}

func GetImageData(repo string, version string, imageData *operatorv1alpha1.AquaImage, allowAnyVersion bool) (string, string, string, string) {

	fmt.Printf("repo: %s", repo)
	fmt.Printf("version: %s", version)
	fmt.Printf("imageData: %s", imageData)

	pullPolicy := consts.PullPolicy
	repository := repo
	tag := version
	registry := consts.Registry

	if len(tag) == 0 {
		fmt.Printf("Setting latest tag version %s", consts.LatestVersion)
		tag = consts.LatestVersion
	}

	if imageData != nil {
		if len(imageData.PullPolicy) != 0 {
			pullPolicy = imageData.PullPolicy
		}

		if len(imageData.Repository) != 0 {
			fmt.Printf("Setting repo %s", imageData.Repository)
			repository = imageData.Repository
		}

		if len(imageData.Tag) != 0 {
			tag = imageData.Tag
		}

		if len(imageData.Registry) != 0 {
			fmt.Printf("Setting registry %s", imageData.Registry)
			registry = imageData.Registry
		}
	}

	if checkForUpgrade(tag) && !allowAnyVersion {
		tag = consts.LatestVersion
	}

	return pullPolicy, registry, repository, tag
}

func IsMarketPlace() bool {
	item := os.Getenv("CERTIFIED_MARKETPLACE")

	if item == "true" || item == "yes" || item == "1" {
		return true
	}

	return false
}

func AppendEnvVar(envs []corev1.EnvVar, item corev1.EnvVar) []corev1.EnvVar {
	var found bool

	for index := 0; index < len(envs); index++ {
		if envs[index].Name == item.Name {
			envs[index] = item
			found = true
		}
	}

	if !found {
		envs = append(envs, item)
	}

	return envs
}

func GetCurrentNameSpace() string {
	var log = logf.Log.WithName("GetWatchNamespace")
	namespace, err := k8sutil.GetWatchNamespace()
	if err != nil {
		log.Error(err, "Failed to get watch namespace")
		os.Exit(1)
	}
	return namespace
}
