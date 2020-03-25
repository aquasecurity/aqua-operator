kubectl create ns aqua
kubectl create -f  deploy/crds/operator.aquasec.com_aquadatabases_crd.yaml 
kubectl create -f  deploy/crds/operator.aquasec.com_aquagateways_crd.yaml 
kubectl create -f  deploy/crds/operator.aquasec.com_aquaservers_crd.yaml 
kubectl create -f  deploy/crds/operator.aquasec.com_aquaenforcers_crd.yaml
kubectl create -f  deploy/crds/operator.aquasec.com_aquacsps_crd.yaml
kubectl create -f  deploy/crds/operator.aquasec.com_aquascanners_crd.yaml

kubectl create -f deploy/service_account.yaml -n aqua
kubectl create -f deploy/role.yaml
kubectl create -f deploy/role_binding.yaml
kubectl create -f deploy/operator.yaml -n aqua
