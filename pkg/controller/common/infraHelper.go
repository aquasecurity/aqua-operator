package common

import (
	"fmt"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
)

func UpdateAquaInfrastructure(infra *operatorv1alpha1.AquaInfrastructure, name, namespace string) *operatorv1alpha1.AquaInfrastructure {
	if infra != nil {
		if len(infra.Namespace) == 0 {
			infra.Namespace = namespace
		}

		if len(infra.ServiceAccount) == 0 {
			infra.ServiceAccount = fmt.Sprintf(consts.ServiceAccount, name)
		}

		if len(infra.Version) == 0 {
			infra.Version = consts.LatestVersion
		}

		if len(infra.Platform) == 0 {
			infra.Platform = "openshift"
		}
	} else {
		infra = &operatorv1alpha1.AquaInfrastructure{
			ServiceAccount: fmt.Sprintf(consts.ServiceAccount, name),
			Namespace:      namespace,
			Version:        consts.LatestVersion,
			Platform:       "openshift",
			Requirements:   false,
		}
	}

	return infra
}

func UpdateAquaCommon(common *operatorv1alpha1.AquaCommon, name string, admin bool, license bool) *operatorv1alpha1.AquaCommon {
	if common != nil {
		if len(common.CyberCenterAddress) == 0 {
			common.CyberCenterAddress = consts.CyberCenterAddress
		}

		if len(common.ImagePullSecret) == 0 {
			common.ImagePullSecret = fmt.Sprintf(consts.PullImageSecretName, name)
		}

		if common.AdminPassword == nil && admin {
			common.AdminPassword = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.AdminPasswordSecretName, name),
				Key:  consts.AdminPasswordSecretKey,
			}
		}

		if common.AquaLicense == nil && license {
			common.AquaLicense = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.LicenseTokenSecretName, name),
				Key:  consts.LicenseTokenSecretKey,
			}
		}

		if common.DatabaseSecret == nil {
			common.DatabaseSecret = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.ScalockDbPasswordSecretName, name),
				Key:  consts.ScalockDbPasswordSecretKey,
			}
		}

		if common.ServerDiskSize == 0 {
			common.ServerDiskSize = consts.ServerPvcSize
		}
	} else {
		adminPassword := (*operatorv1alpha1.AquaSecret)(nil)
		aquaLicense := (*operatorv1alpha1.AquaSecret)(nil)

		if admin {
			adminPassword = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.AdminPasswordSecretName, name),
				Key:  consts.AdminPasswordSecretKey,
			}
		}

		if license {
			aquaLicense = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.LicenseTokenSecretName, name),
				Key:  consts.LicenseTokenSecretKey,
			}
		}

		common = &operatorv1alpha1.AquaCommon{
			ClusterMode:        false,
			ActiveActive:       false,
			CyberCenterAddress: consts.CyberCenterAddress,
			ImagePullSecret:    fmt.Sprintf(consts.PullImageSecretName, name),
			AdminPassword:      adminPassword,
			AquaLicense:        aquaLicense,
			DatabaseSecret: &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.ScalockDbPasswordSecretName, name),
				Key:  consts.ScalockDbPasswordSecretKey,
			},
			DbDiskSize:     consts.DbPvcSize,
			ServerDiskSize: consts.ServerPvcSize,
		}
	}

	return common
}
