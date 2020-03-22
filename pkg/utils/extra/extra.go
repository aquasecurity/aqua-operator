package extra

import (
	"encoding/base64"
	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"

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

func GetImageData(repo string, version string, imageData *operatorv1alpha1.AquaImage) (string, string, string, string) {
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

	return pullPolicy, registry, repository, tag
}
