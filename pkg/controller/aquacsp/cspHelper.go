package aquacsp

import (
	"fmt"

	operatorv1alpha1 "github.com/aquasecurity/aqua-operator/pkg/apis/operator/v1alpha1"
	"github.com/aquasecurity/aqua-operator/pkg/consts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CspParameters struct {
	AquaCsp *operatorv1alpha1.AquaCsp
}

type AquaCspHelper struct {
	Parameters CspParameters
}

func newAquaCspHelper(cr *operatorv1alpha1.AquaCsp) *AquaCspHelper {
	params := CspParameters{
		AquaCsp: cr,
	}

	return &AquaCspHelper{
		Parameters: params,
	}
}

func (csp *AquaCspHelper) newAquaDatabase(cr *operatorv1alpha1.AquaCsp) *operatorv1alpha1.AquaDatabase {
	labels := map[string]string{
		"app":                cr.Name + "-csp",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Database (not for production environments)",
	}
	aquadb := &operatorv1alpha1.AquaDatabase{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaDatabase",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: operatorv1alpha1.AquaDatabaseSpec{
			Infrastructure: csp.Parameters.AquaCsp.Spec.Infrastructure,
			Common:         csp.Parameters.AquaCsp.Spec.Common,
			DbService:      csp.Parameters.AquaCsp.Spec.DbService,
			DiskSize:       csp.Parameters.AquaCsp.Spec.Common.DbDiskSize,
			RunAsNonRoot:   csp.Parameters.AquaCsp.Spec.RunAsNonRoot,
		},
	}

	return aquadb
}

func (csp *AquaCspHelper) newAquaGateway(cr *operatorv1alpha1.AquaCsp) *operatorv1alpha1.AquaGateway {
	labels := map[string]string{
		"app":                cr.Name + "-csp",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Gateway",
	}
	aquadb := &operatorv1alpha1.AquaGateway{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaGateway",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: operatorv1alpha1.AquaGatewaySpec{
			Infrastructure: csp.Parameters.AquaCsp.Spec.Infrastructure,
			Common:         csp.Parameters.AquaCsp.Spec.Common,
			GatewayService: csp.Parameters.AquaCsp.Spec.GatewayService,
			ExternalDb:     csp.Parameters.AquaCsp.Spec.ExternalDb,
			RunAsNonRoot:   csp.Parameters.AquaCsp.Spec.RunAsNonRoot,
		},
	}

	return aquadb
}

func (csp *AquaCspHelper) newAquaServer(cr *operatorv1alpha1.AquaCsp) *operatorv1alpha1.AquaServer {
	labels := map[string]string{
		"app":                cr.Name + "-csp",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Server",
	}
	aquadb := &operatorv1alpha1.AquaServer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaServer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: operatorv1alpha1.AquaServerSpec{
			Infrastructure: csp.Parameters.AquaCsp.Spec.Infrastructure,
			Common:         csp.Parameters.AquaCsp.Spec.Common,
			ServerService:  csp.Parameters.AquaCsp.Spec.ServerService,
			ExternalDb:     csp.Parameters.AquaCsp.Spec.ExternalDb,
			LicenseToken:   csp.Parameters.AquaCsp.Spec.LicenseToken,
			AdminPassword:  csp.Parameters.AquaCsp.Spec.AdminPassword,
			Enforcer:       csp.Parameters.AquaCsp.Spec.Enforcer,
			RunAsNonRoot:   csp.Parameters.AquaCsp.Spec.RunAsNonRoot,
			Envs:           csp.Parameters.AquaCsp.Spec.Envs,
		},
	}

	return aquadb
}

func (csp *AquaCspHelper) newAquaEnforcer(cr *operatorv1alpha1.AquaCsp) *operatorv1alpha1.AquaEnforcer {
	registry := consts.Registry
	if cr.Spec.RegistryData != nil {
		if len(cr.Spec.RegistryData.URL) > 0 {
			registry = cr.Spec.RegistryData.URL
		}
	}

	labels := map[string]string{
		"app":                cr.Name + "-csp",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Enforcer",
	}
	aquaenf := &operatorv1alpha1.AquaEnforcer{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaEnforcer",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: operatorv1alpha1.AquaEnforcerSpec{
			Infrastructure: csp.Parameters.AquaCsp.Spec.Infrastructure,
			Common:         csp.Parameters.AquaCsp.Spec.Common,
			Gateway: &operatorv1alpha1.AquaGatewayInformation{
				Host: fmt.Sprintf("%s-gateway", cr.Name),
				Port: 8443,
			},
			Secret: &operatorv1alpha1.AquaSecret{
				Name: fmt.Sprintf("%s-enforcer-token", cr.Name),
				Key:  "token",
			},
			EnforcerService: &operatorv1alpha1.AquaService{
				ImageData: &operatorv1alpha1.AquaImage{
					Registry: registry,
				},
			},
			RunAsNonRoot: csp.Parameters.AquaCsp.Spec.RunAsNonRoot,
		},
	}

	return aquaenf
}

/*func (csp *AquaCspHelper) newAquaScanner(cr *operatorv1alpha1.AquaCsp) *operatorv1alpha1.AquaScanner {
	labels := map[string]string{
		"app":                cr.Name + "-csp",
		"deployedby":         "aqua-operator",
		"aquasecoperator_cr": cr.Name,
	}
	annotations := map[string]string{
		"description": "Deploy Aqua Scanner",
	}
	scanner := &operatorv1alpha1.AquaScanner{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "operator.aquasec.com/v1alpha1",
			Kind:       "AquaScanner",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        cr.Name,
			Namespace:   cr.Namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: operatorv1alpha1.AquaScannerSpec{
			Infrastructure: cr.Spec.Infrastructure,
			Common:         cr.Spec.Common,
			ScannerService: cr.Spec.ScannerService,
			Login: &operatorv1alpha1.AquaLogin{
				Username: "administrator",
				Password: cr.Spec.AdminPassword,
				Host:     fmt.Sprintf("http://%s:8080", fmt.Sprintf(consts.ServerServiceName, cr.Name)),
			},
		},
	}

	return scanner
}*/
