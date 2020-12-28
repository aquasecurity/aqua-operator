package common

import (
	"fmt"

	"github.com/aquasecurity/aqua-operator/pkg/controller/ocp"
	"github.com/aquasecurity/aqua-operator/pkg/utils/extra"

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
			isOpenshift, _ := ocp.VerifyRouteAPI()
			if isOpenshift {
				infra.Platform = "openshift"
			} else {
				infra.Platform = "kubernetes"
			}
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
			marketplace := extra.IsMarketPlace()
			if !marketplace {
				common.ImagePullSecret = fmt.Sprintf(consts.PullImageSecretName, name)
			}
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

		if common.DbDiskSize == 0 {
			common.DbDiskSize = consts.DbPvcSize
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
			ActiveActive:       false,
			CyberCenterAddress: consts.CyberCenterAddress,
			ImagePullSecret:    fmt.Sprintf(consts.PullImageSecretName, name),
			AdminPassword:      adminPassword,
			AquaLicense:        aquaLicense,
			DatabaseSecret: &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.ScalockDbPasswordSecretName, name),
				Key:  consts.ScalockDbPasswordSecretKey,
			},
			DbDiskSize: consts.DbPvcSize,
			SplitDB: false,
		}
	}

	return common
}


func UpdateAquaAuditDB(auditDb *operatorv1alpha1.AuditDBInformation, name string) *operatorv1alpha1.AuditDBInformation {
	password := extra.CreateRundomPassword()

	if auditDb != nil {
		if auditDb.AuditDBSecret == nil {
			auditDb.AuditDBSecret = &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.AuditDbPasswordSecretName, name),
				Key: consts.ScalockDbPasswordSecretKey,
			}
		}

		if auditDb.Data == nil {
			auditDb.Data = &operatorv1alpha1.AquaDatabaseInformation{
				Host: fmt.Sprintf(consts.AuditDbServiceName, name),
				Port: 5432,
				Username: "postgres",
				Password: password,
			}
		}
	} else {
		auditDb = &operatorv1alpha1.AuditDBInformation{
			AuditDBSecret: &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf(consts.AuditDbPasswordSecretName, name),
				Key: consts.ScalockDbPasswordSecretKey,
			},
			Data: &operatorv1alpha1.AquaDatabaseInformation{
				Host: fmt.Sprintf(consts.AuditDbServiceName, name),
				Port: 5432,
				Username: "postgres",
				Password: password,

			},
		}
	}

	return auditDb
}
