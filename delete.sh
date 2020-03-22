kubectl delete -f  deploy/crds/operator_v1alpha1_aquadatabase_crd.yaml 
kubectl delete -f  deploy/crds/operator_v1alpha1_aquagateway_crd.yaml 
kubectl delete -f  deploy/crds/operator_v1alpha1_aquaserver_crd.yaml 
kubectl delete -f  deploy/crds/operator_v1alpha1_aquaenforcer_crd.yaml
kubectl delete -f  deploy/crds/operator_v1alpha1_aquacsp_crd.yaml 
kubectl delete -f  deploy/crds/operator_v1alpha1_aquascanner_crd.yaml

kubectl delete -f deploy/service_account.yaml -n aqua
kubectl delete -f deploy/role.yaml
kubectl delete -f deploy/role_binding.yaml
kubectl delete -f deploy/operator.yaml -n aqua
kubectl delete ns aqua
