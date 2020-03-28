# Installation

## Simple Installation

requirments:
* kubectl configured with your cluster

Create aqua namespace

```shell
kubectl create namespace <namespace>
```

Install Custom CRDs

```shell
kubectl create -f  deploy/crds/operator_v1alpha1_aquadatabase_crd.yaml
kubectl create -f  deploy/crds/operator_v1alpha1_aquagateway_crd.yaml
kubectl create -f  deploy/crds/operator_v1alpha1_aquaserver_crd.yaml
kubectl create -f  deploy/crds/operator_v1alpha1_aquaenforcer_crd.yaml
kubectl create -f  deploy/crds/operator_v1alpha1_aquacsp_crd.yaml
kubectl create -f  deploy/crds/operator_v1alpha1_aquascanner_crd.yaml
```

Install operator with version in the [Operator YAML](deploy/operator.yaml)

```shell
kubectl create -f deploy/service_account.yaml -n <namespace>
kubectl create -f deploy/role.yaml
kubectl create -f deploy/role_binding.yaml
kubectl create -f deploy/operator.yaml -n <namespace>
```

## Installation via helm

[Helm Aqua Operator](https://github.com/aquasecurity/aqua-operator-helm)