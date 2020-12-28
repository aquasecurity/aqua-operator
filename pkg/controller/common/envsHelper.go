package common

import (
	"errors"
	"fmt"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
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

	dbuser := "postgres"
	dbhost := fmt.Sprintf(consts.DbDeployName, ctx.Parameters.Name)
	dbport := 5432

	if ctx.Parameters.ExternalDb != nil {
		dbuser = ctx.Parameters.ExternalDb.Username
		dbhost = ctx.Parameters.ExternalDb.Host
		dbport = int(ctx.Parameters.ExternalDb.Port)
	}

	dbSecret := ctx.Parameters.Common.DatabaseSecret

	dbAuditUser := dbuser
	dbAuditHost := dbhost
	dbAuditPort := dbport
	dbAuditSecret := dbSecret

	if ctx.Parameters.Common.SplitDB {
		dbAuditHost = ctx.Parameters.AuditDB.Data.Host
		dbAuditUser = ctx.Parameters.AuditDB.Data.Username
		dbAuditPort = int(ctx.Parameters.AuditDB.Data.Port)
		dbAuditSecret = ctx.Parameters.AuditDB.AuditDBSecret
	}

	result = []corev1.EnvVar{
		{
			Name:  "SCALOCK_DBUSER",
			Value: dbuser,
		},
		{
			Name:  "SCALOCK_DBNAME",
			Value: "scalock",
		},
		{
			Name:  "SCALOCK_DBHOST",
			Value: dbhost,
		},
		{
			Name:  "SCALOCK_DBPORT",
			Value: fmt.Sprintf("%d", dbport),
		},
		{
			Name:  "SCALOCK_AUDIT_DBUSER",
			Value: dbAuditUser,
		},
		{
			Name:  "SCALOCK_AUDIT_DBNAME",
			Value: "slk_audit",
		},
		{
			Name:  "SCALOCK_AUDIT_DBHOST",
			Value: dbAuditHost,
		},
		{
			Name:  "SCALOCK_AUDIT_DBPORT",
			Value: fmt.Sprintf("%d", dbAuditPort),
		},
		{
			Name:  "SCALOCK_DBSSL",
			Value: "require",
		},
		{
			Name:  "SCALOCK_AUDIT_DBSSL",
			Value: "require",
		},
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
			Name:  "AQUA_PUBSUB_DBNAME",
			Value: "aqua_pubsub",
		}
		result = append(result, item)

		item = corev1.EnvVar{
			Name:  "AQUA_PUBSUB_DBHOST",
			Value: dbhost,
		}
		result = append(result, item)

		item = corev1.EnvVar{
			Name:  "AQUA_PUBSUB_DBPORT",
			Value: fmt.Sprintf("%d", dbport),
		}
		result = append(result, item)

		item = corev1.EnvVar{
			Name:  "AQUA_PUBSUB_DBUSER",
			Value: dbuser,
		}
		result = append(result, item)

		item = corev1.EnvVar{
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
