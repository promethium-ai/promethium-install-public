# ✅ Promethium Intelligent Edge Installation (AWS)

The following steps will describe how to deploy a secure Promethium Intelligent Edge in AWS. It will deploy an Amazon Elastic Kubernetes Service (EKS) within use the Promethium Application services will be deployed. The deployment will configure the following footprint;

![Promethium Intelligent Edge (AWS)](../images/AWS_IE.png)

## 📋 1. Environment Prerequisites

| Item                    | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| AWS Account             | Identify the AWS account where the data plane will be deployed              |
| Region                  | AWS region for deployment (e.g., `us-east-1`)                       |
| VPC                     | VPC ID that is at least /22 that will contain the Promethium Intelligent Edge |
| 3+ Private subnets      | Subnets (/24) that will support the kubernetes cluster |
| Outbound Internet Access| Ensure EKS nodes have HTTPS access to Promethium Control Plane + image registry |
| DNS & Ingress           | Allow cloud-native ingress (ALB) creation and domain assignment         |
| S3 Bucket               | Storage location for state persistence and materialized Datamaps |

---

## 🔐 2. IAM Roles & Policies (Customer-Managed)

Create the following IAM roles and policies using Promethium-provided templates. Ensure roles are tagged (e.g., `Service=PromethiumIE`).

| Role Name             | Used By                    | Required Permissions                          | Notes                                  |
|-----------------------|-----------------------------|-----------------------------------------------|----------------------------------------|
| `PromethiumInstall`   | Install VM                  |                                               | Access required to install Promethium Intelligent Edge (IE)|
| `promethium-efscsi-role` | Promethium Intelligent Edge (IE) |                                       | Allows EFS CSI driver in the EKS cluster to provision and manage EFS file systems and access points
| `promethium-eks-autoscaler-role` | Promethium Intelligent Edge (IE) | | Allows EKS Autoscaler to add or remove worker nodes in Auto Scaling Groupsand inspect EC2 and EKS resources to make scaling decisions |
| `promethium-lbcontroller-role` | Promethium Intelligent Edge (IE) | | Allows the Load Balancer Controller running the EKS cluster to provision and manage ALBs/NLBs and related networking/security resources on behalf of Kubernetes LoadBalancer ingresses and services |
| `promethium-s3-access-role` | Promethium Intelligent Edge (IE) | | Allows for postgres backups into S3 and lets workloads pull container images from ECR |
| `promethium-eks-cluster-role` | Promethium Intelligent Edge (IE) | | Gives cluster KMS access to encrypt and decrypt. Also allows cluster to interact with AWS services |
| `promethium-trino-oidc-role` | Promethium Intelligent Edge (IE) | | Query and manage data in Glue Data Catalog and SS3. Handle KMS encrypted data and launch and interact with Glue jobs using default servie role |

---

## 🧪 4. Role and Policy Validation

The following utilities can be used to verify that the roles created have the requisite permissions to execute the installation process.

| Utility                                           | Purpose         |
|------------------------------------------------|---------------|
| update-policies.sh        | Update the role and trust policies with account and region details         |
| tf_install_role_verifier.py    | Verfies permissions associated with PromethiumInstall role                 |
| promethium_app_role_verifier.py | Verifies roles needed for Promethium Intelligent Edge functioning         |
---
