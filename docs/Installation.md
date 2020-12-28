# Installation

## Simple Installation

requirments:
* kubectl configured with your cluster

Create aqua namespace

```shell
kubectl create namespace aqua
```

Install Custom CRDs

```shell
kubectl create -f  deploy/crds/operator.aquasec.com_aquadatabases_crd.yaml 
kubectl create -f  deploy/crds/operator.aquasec.com_aquagateways_crd.yaml 
kubectl create -f  deploy/crds/operator.aquasec.com_aquaservers_crd.yaml 
kubectl create -f  deploy/crds/operator.aquasec.com_aquaenforcers_crd.yaml
kubectl create -f  deploy/crds/operator.aquasec.com_aquacsps_crd.yaml
kubectl create -f  deploy/crds/operator.aquasec.com_aquascanners_crd.yaml
kubectl create -f  deploy/crds/operator.aquasec.com_aquakubeenforcers_crd.yaml
```

Install operator with version in the [Operator YAML](deploy/operator.yaml)

```shell
kubectl create -f deploy/service_account.yaml -n aqua
kubectl create -f deploy/role.yaml
kubectl create -f deploy/role_binding.yaml
kubectl create -f deploy/operator.yaml -n aqua
```

## Installation via helm

[Helm Aqua Operator](https://github.com/aquasecurity/aqua-operator-helm)