The Aqua Security Operator is used to deploy and manage the Aqua Cloud Native Security Platform (CSP) and its components:
* Server (aka “console”)
* Database (optional; you can map an external database as well) 
* Gateway 
* Enforcer
* Scanner

Use the Aqua Operator to: 
* Deploy Aqua CSP on OpenShift
* Scale up Aqua Security components with extra replicas
* Assign metadata tags to Aqua CSP components
* Automatically scale the number of Aqua scanners based on the number of images in the scan queue
	
The Aqua Operator provides a few [Custom Resources](https://github.com/aquasecurity/aqua-operator/tree/master/deploy/crds) for managing the Aqua CSP platform. 
   
## Prerequisites 

Make sure you have a license and access to the Aqua registry. To obtain a license, please contact Aqua Security at https://www.aquasec.com/about-us/contact-us/.

It is advised that you read about the [Aqua Environment and Configuration](https://docs.aquasec.com/docs/purpose-of-this-section) before deploying and using the Operator. 

## Deploying the Aqua Operator

1. Create a new namespace/project called "aqua" for the Aqua deployment.
2. Install the Aqua Operator from Red Hat's OperatorHub and add it to the "aqua" namespace. The Operator will create the service account "aqua-sa" to run Aqua CSP. 

## Deploying the Aqua CSP custom resources

Before you start, you will need to supply two secrets for the deployment: 
* A secret for the Docker registry
* A secret for the database

You can list the secrets in the custom resource YAML files or you can define them in the OpenShift project (see example below):
```bash
oc create secret docker-registry aqua-registry --docker-server=registry.aquasec.com --docker-username=<AQUA_USERNAME> --docker-password=<AQUA_PASSWORD> --docker-email=<user email> -n aqua
oc create secret generic aqua-database-password --from-literal=db-password=<password> -n aqua
oc secrets add aqua-sa aqua-registry --for=pull -n aqua
```

There are several options for deploying the Aqua CSP custom resources. You can review the different options in [this file](https://github.com/aquasecurity/aqua-operator/blob/master/deploy/crds/operator_v1alpha1_aquacsp_cr.yaml).  
* The Aqua CSP CRD defines how to deploy the Server (Console), Database, Scanner, and Gateway. 
* You can instruct the Aqua CSP CR to automatically deploy the Enforcer by setting the "enforcer" and "enforcerMode" properties in the CR file. 
* If you want to deploy the Enforcers manually, you will need to first get a security token. Access Aqua console and create a new Enforcer Group. Copy the group's "token" and use it in the AquaEnforcer CR (see the example below).
* You can instruct the Aqua CSP CR to automatically deploy a Route by setting the "route" property to "true".
* The default service type for the console and gateway is ClusterIP. You can change this to a different service type.
* You can choose to deploy a different version of Aqua CSP by setting the "version" property.
	
#### Example: Deploying Aqua CSP

Here is an example of a simple deployment: 
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
    version: "4.6"                          
    requirements: true                      
  common:
    imagePullSecret: "aqua-registry"        # Optional: If already created image pull secret then mention in here
    dbDiskSize: 10       
    serverDiskSize: 4   
  database:                                 
    replicas: 1                            
    service: "ClusterIP"                    
  gateway:                                  
    replicas: 1                             
    service: "ClusterIP"                    
  server:                                   
    replicas: 1                             
    service: "ClusterIP" 
  enforcer:                                 # Optional: If defined, the Operator will create the default Enforcer 
    enforcerMode: audit                     # Defines whether the default Enforcer will work in "Enforce" or "Audit Only" mode 
  route: true                               # Optional: If defined and set to true, the Operator will create a Route to enable access to the console
```

If you haven't used the "route" option in the Aqua CSP CR, you should define a Route manually to enable external access to the Aqua Server (Console).

#### Example: Deploying Aqua Enforcer(s)

If you haven't deployed any Enforcers, or if you want to deploy additional Enforcers, follow the instructions [here](https://github.com/aquasecurity/aqua-operator/blob/master/deploy/crds/operator_v1alpha1_aquaenforcer_cr.yaml).

Here is an example of a simple Enforcer deployment: 
```yaml
---
apiVersion: operator.aquasec.com/v1alpha1
kind: AquaEnforcer
metadata:
  name: aqua
spec:
  infra:                                    
    serviceAccount: "aqua-sa"                
    version: "4.6"                          # Optional: auto generate to latest version
  common:
    imagePullSecret: "aqua-registry"        # Optional: if already created image pull secret then mention in here
  deploy:                                   # Optional: information about Aqua Enforcer deployment
    image:                                  # Optional: take the default value and version from infra.version
      repository: "enforcer"                # Optional: default = enforcer
      registry: "registry.aquasec.com"      # Optional: default = registry.aquasec.com
      tag: "4.6"                            # Optional: default = 4.6 (latest tested version for this operator version)
      pullPolicy: "IfNotPresent"            # Optional: default = IfNotPresent
  gateway:                                  # Required: data about the gateway address
    host: aqua-gateway
    port: 8443
  token: "<<your-token>>"                   # Required: The Enforcer group token can use an existing secret instead (you can create a token from the Aqua console)
```