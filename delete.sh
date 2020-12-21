kubectl delete -f  deploy/crds/operator.aquasec.com_aquadatabases_crd.yaml 
kubectl delete -f  deploy/crds/operator.aquasec.com_aquagateways_crd.yaml 
kubectl delete -f  deploy/crds/operator.aquasec.com_aquaservers_crd.yaml 
kubectl delete -f  deploy/crds/operator.aquasec.com_aquaenforcers_crd.yaml
kubectl delete -f  deploy/crds/operator.aquasec.com_aquacsps_crd.yaml
kubectl delete -f  deploy/crds/operator.aquasec.com_aquascanners_crd.yaml
kubectl delete -f deploy/crds/operator.aquasec.com_aquakubeenforcers_crd.yaml

kubectl delete -f deploy/service_account.yaml -n aqua
kubectl delete -f deploy/role.yaml
kubectl delete -f deploy/role_binding.yaml
kubectl delete -f deploy/operator.yaml -n aqua
kubectl delete ns aqua

