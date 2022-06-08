The Aqua Security Operator is used to deploy and manage the Aqua Security platform and its components:
* Server (aka “console”)
* Database (optional, you can map an external database as well) 
* Gateway 
* Enforcer (aka “agent”)
* Scanner
* CSP (a simple package that contains the Server, Database, and Gateway)

Use the Aqua-Operator to: 
* Deploy the Aqua Security platform on OpenShift
* Scale up Aqua Security components with extra replicas
* Assign metadata tags to Aqua Security components
* Automatically scale the number of Aqua scanners based on the number of images in the scan queue
	
The Aqua Operator provides a few [Custom Resources](https://github.com/aquasecurity/aqua-operator/tree/master/config/crd) to manage the Aqua platform. 
Please make sure to read the Aqua installation manual (https://docs.aquasec.com/docs) before using the Operator. 
For advance configurations please consult with Aqua's support team.
    
How to deploy Aqua using the Operator -
1. Install the Aqua Operator from RH's OperatorHub
2. Manage all the prerequisites as covered in the instructions below (see "Before you begin using the Operator CRDs")
3. Use the AquaCSP CRD to install Aqua in your cluster. AquaCSP CRD defines how to deploy the Console, Database, Scanner, and Gateway Custom Resources
4. You can also use the AquaCSP CRD to deploy the default Enforcers, and an OpenShift Route to access the console 
5. You can install the Enforcers using the AquaEnforcer CRD, but you will need to first get a security token.  Access Aqua console and create a new Enforcer Group. Copy the group's 'token' and use it in the AquaEnforcer CRD
	

## Before You Begin Using the Operator CRDs
Install the Aqua Operator and obtain access to the Aqua registry - https://www.aquasec.com/about-us/contact-us/
You will need to supply two secrets during the installation - 
* A secret for the Docker registry
* A secret for the database

You can list the secrets in the YAML files or, you can define secrets in the OpenShift project (see example below) -
```bash
oc create project aqua 
oc create secret docker-registry aqua-registry --docker-server=registry.aquasec.com --docker-username=<AQUA_USERNAME> --docker-password=<AQUA_PASSWORD> --docker-email=<user email> -n aqua
oc create secret generic aqua-database-password --from-literal=db-password=<password> -n aqua
oc secrets add aqua-sa aqua-registry --for=pull -n aqua
```

## Installing AquaCSP
There are multiple options to deploy the AquaCSP CR. You can review the different options in the following [file](https://github.com/aquasecurity/aqua-operator/blob/master/config/crd/operator_v1alpha1_aquacsp_cr.yaml). 

Here is an example of a simple deployment  - 
```yaml
---
apiVersion: operator.aquasec.com/v1alpha1
kind: AquaCsp
metadata:
  name: aqua
  namespace: aqua
spec:
  infra:                                    
    serviceAccount: "aqua-sa"               
    namespace: "aqua"                       
    version: "2022.4"                          
    requirements: true                      
  common:
    imagePullSecret: "aqua-registry"        # Optional: if already created image pull secret then mention in here
    dbDiskSize: 10       
  database:                                 
    replicas: 1                            
    service: "ClusterIP"                    
  gateway:                                  
    replicas: 1                             
    service: "ClusterIP"                    
  server:                                   
    replicas: 1                             
    service: "NodePort" 
  enforcer:                                 # Optional: if defined the Operator will create the default Enforcer 
    enforcerMode: true                      # Defines weather the default enforcer will work in 'enforce' or 'audit' more 
  route: true                               # Optional: if defines and set to true, the operator will create a Route to enable access to the console
```

If you haven't used the Route option in the AquaCsp CRD, you should define the Route manually to enable external access to Aqua's console.

## Installing AquaEnforcer
If you haven't deployed the enforcer yet, or if you want to deploy additional enforcers, please follow the instruction below:
You can review the different options to implement AquaEnforcer in the following [file](https://github.com/aquasecurity/aqua-operator/blob/master/config/crd/operator_v1alpha1_aquaenforcer_cr.yaml).

Here is an example of a simple deployment  - 
```yaml
---
apiVersion: operator.aquasec.com/v1alpha1
kind: AquaEnforcer
metadata:
  name: aqua
spec:
  infra:                                    
    serviceAccount: "aqua-sa"                
    version: "2022.4"                          # Optional: auto generate to latest version
  common:
    imagePullSecret: "aqua-registry"            # Optional: if already created image pull secret then mention in here
  deploy:                                   # Optional: information about aqua enforcer deployment
    image:                                  # Optional: if not given take the default value and version from infra.version
      repository: "enforcer"                # Optional: if not given take the default value - enforcer
      registry: "registry.aquasec.com"      # Optional: if not given take the default value - registry.aquasec.com
      tag: "2022.4"                            # Optional: if not given take the default value - 4.5 (latest tested version for this operator version)
      pullPolicy: "IfNotPresent"            # Optional: if not given take the default value - IfNotPresent
  gateway:                                  # Required: data about the gateway address
    host: aqua-gateway
    port: 8443
  token: "<<your-token>>"                            # Required: enforcer group token also can use an existing secret instead (you can create a token from Aqua's console)
```
