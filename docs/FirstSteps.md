## Kubernetes

Support only Kubernetes 1.11+

### Requirements (Optional)
You can create before using the operator but in Kubernetes the operator able to create all the requirements:
* Namespace
* Service Account
* Docker Pull Image Secret
* Aqua Database Password Secret

> Note: We are recommended to use the automatic requirements generate by the operator in Kubernetes

```shell
kubectl create namespace aqua

kubectl create secret docker-registry aqua-registry-secret --docker-server=registry.aquasec.com --docker-username=<user name> --docker-password=<password> --docker-email=<user email> -n aqua

kubectl create secret generic aqua-database-password --from-literal=db-password=123456 -n aqua

kubectl create -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aqua-sa
  namespace: aqua
imagePullSecrets:
- name: aqua-registry-secret
EOF
```

## Openshift

Support only Openshift 3.11+

### Requirements

First of all you need to create:
* Namespace
* Service Account


```shell
oc new-project aqua

oc create serviceaccount aqua-sa -n aqua

oc adm policy add-cluster-role-to-user cluster-reader system:serviceaccount:aqua:aqua-sa -n aqua
oc adm policy add-scc-to-user privileged system:serviceaccount:aqua:aqua-sa -n aqua
oc adm policy add-scc-to-user hostaccess system:serviceaccount:aqua:aqua-sa -n aqua

```