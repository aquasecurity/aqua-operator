# Installation

## Simple Installation

requirements:
* kubectl configured with your cluster

Create aqua namespace

```shell
kubectl create namespace aqua
```

Install Custom CRDs

```shell
kubectl create -f  config/crd/operator.aquasec.com_aquadatabases_crd.yaml 
kubectl create -f  config/crd/operator.aquasec.com_aquagateways_crd.yaml 
kubectl create -f  config/crd/operator.aquasec.com_aquaservers_crd.yaml 
kubectl create -f  config/crd/operator.aquasec.com_aquaenforcers_crd.yaml
kubectl create -f  config/crd/operator.aquasec.com_aquacsps_crd.yaml
kubectl create -f  config/crd/operator.aquasec.com_aquascanners_crd.yaml
kubectl create -f  config/crd/operator.aquasec.com_aquakubeenforcers_crd.yaml
```

Install operator with version in the [Operator YAML](../config/manifests/operator.yaml)

```shell
kubectl create -f config/rbac/service_account.yaml -n aqua
kubectl create -f config/rbac/role.yaml
kubectl create -f config/rbac/role_binding.yaml
kubectl create -f config/manifests/operator.yaml -n aqua
```
