package extra

import (
	"encoding/base64"
	"os"
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
	pullPolicy := consts.PullPolicy
	repository := repo
	tag := version
	registry := consts.Registry

	if len(tag) == 0 {
		tag = consts.LatestVersion
	}

	if imageData != nil {
		if len(imageData.PullPolicy) != 0 {
			pullPolicy = imageData.PullPolicy
		}

		if len(imageData.Repository) != 0 {
			repository = imageData.Repository
		}

		if len(imageData.Tag) != 0 {
			tag = imageData.Tag
		}

		if len(imageData.Registry) != 0 {
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
