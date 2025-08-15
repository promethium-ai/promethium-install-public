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

---

## 🧪 4. Role and Policy Validation

The following utilities can be used to verify that the roles created have the requisite permissions to execute the installation process.

| Utility                                           | Purpose         |
|------------------------------------------------|---------------|
|              |       |

---
