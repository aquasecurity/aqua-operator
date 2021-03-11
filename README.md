<h1 align="center">Aqua Security Operator</h1>
<p align="center">
  <img width="150px" height="150px" src="images/logo.svg"/>
</p>

## About

The **aqua-operator** is a group of controllers that runs within a Kubernetes or OpenShift cluster. It provides a means to deploy and manage an Aqua Security cluster and components:
* Server (Console)
* Gateway
* Database (not recommended for production environments)
* Server components (package of Server, Gateway and Database)
* Aqua Enforcer
* Scanner CLI

**Use the aqua-operator to:**
 * Deploy Aqua Enterprise components in OpenShift clusters
 * Scale up Aqua Enterprise components with extra replicas
 * Assign metadata tags to Aqua Enterprise components

## Deployment requirements

The Operator is designed for OpenShift clusters.

* **OpenShift:** 4.0 +

## Documentation

The following documentation is available:

- [OpenShift installation and examples](docs/DeployOpenShiftOperator.md)
- [Aqua Enterprise documentation portal](https://docs.aquasec.com/)
- [Aqua Security Operator page on OperatorHub.io](https://operatorhub.io/operator/aqua)

## Issues and feedback

If you encounter any problems or would like to give us feedback on deployments, we encourage you to raise issues here on GitHub.