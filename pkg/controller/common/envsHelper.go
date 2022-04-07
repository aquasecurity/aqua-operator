package common

import (
	"errors"
	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

type EnvsParameters struct {
	Infrastructure *operatorv1alpha1.AquaInfrastructure
	Common         *operatorv1alpha1.AquaCommon
	ExternalDb     *operatorv1alpha1.AquaDatabaseInformation
	Name           string
	AuditDB        *operatorv1alpha1.AuditDBInformation
}

type AquaEnvsHelper struct {
	Parameters EnvsParameters
}

func NewAquaEnvsHelper(infra *operatorv1alpha1.AquaInfrastructure,
	common *operatorv1alpha1.AquaCommon,
	externalDb *operatorv1alpha1.AquaDatabaseInformation,
	name string,
	auditDB *operatorv1alpha1.AuditDBInformation) *AquaEnvsHelper {
	params := EnvsParameters{
		Infrastructure: infra,
		Common:         common,
		ExternalDb:     externalDb,
		Name:           name,
		AuditDB:        auditDB,
	}

	return &AquaEnvsHelper{
		Parameters: params,
	}
}

func (ctx *AquaEnvsHelper) GetDbEnvVars() ([]corev1.EnvVar, error) {
	result := ([]corev1.EnvVar)(nil)

	dbSecret := ctx.Parameters.Common.DatabaseSecret
	dbAuditSecret := dbSecret

	if ctx.Parameters.Common.SplitDB {
		dbAuditSecret = ctx.Parameters.AuditDB.AuditDBSecret
	}

	result = []corev1.EnvVar{
		{
			Name: "SCALOCK_DBPASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: dbSecret.Name,
					},
					Key: dbSecret.Key,
				},
			},
		},
		{
			Name: "SCALOCK_AUDIT_DBPASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: dbAuditSecret.Name,
					},
					Key: dbAuditSecret.Key,
				},
			},
		},
	}

	if ctx.Parameters.Common.ActiveActive {
		item := corev1.EnvVar{
			Name: "AQUA_PUBSUB_DBPASSWORD",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: dbSecret.Name,
					},
					Key: dbSecret.Key,
				},
			},
		}
		result = append(result, item)
	}

	if result == nil {
		return nil, errors.New("Failed to create Aqua Gateway deployments environments variables")
	}

	return result, nil
}
