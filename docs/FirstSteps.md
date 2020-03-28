## Kubernetes

Support only Kubernetes 1.11+

### Requirments (Optional)
You can create before using the operator but in Kubernetes the operator able to create all the requirments:
* Namespace
* Service Account
* Docker Pull Image Secret
* Aqua Database Password Secret

> Note: We recommended to use the automatic requirments generate by the operator in Kuberntes

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

### Requirments

First of all you need to create:
* Namespace
* Service Account
* Docker Pull Image Secret
* Aqua Database Password Secret

```shell
oc new-project aqua

oc create serviceaccount aqua-sa -n aqua

oc adm policy add-cluster-role-to-user cluster-reader system:serviceaccount:aqua:aqua-sa -n aqua
oc adm policy add-scc-to-user privileged system:serviceaccount:aqua:aqua-sa -n aqua
oc adm policy add-scc-to-user hostaccess system:serviceaccount:aqua:aqua-sa -n aqua

oc create secret docker-registry aqua-registry-secret --docker-server=registry.aquasec.com --docker-username=<user name> --docker-password=<password> --docker-email=<user email> -n aqua

oc create secret generic aqua-database-password --from-literal=db-password=123456 -n aqua
oc secrets add aqua-sa aqua-registry-secret --for=pull -n aqua
```