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

| Resource | What uses it | Attached Policies | Trust Policies | Notes |
|----------|--------------|-------------------|----------------|-------|
| `PromethiumInstall`   | Install VM | <ul><li> [promethium-terraform-acm-policy.json](policies_dir/promethium-terraform-acm-policy.json) </li> <li>[promethium-terraform-ec2-policy.json](policies_dir/promethium-terraform-ec2-policy.json)</li> <li>[promethium-terraform-efs-policy.json](policies_dir/promethium-terraform-efs-policy.json) </li> <li> [promethium-terraform-eks-policy.json](policies_dir/promethium-terraform-eks-policy.json)</li> <li>[promethium-terraform-elb-permissions.json](policies_dir/promethium-terraform-elb-permissions.json)</li> <li>[promethium-terraform-glue-policy.json](policies_dir/promethium-terraform-glue-policy.json)</li> </ul> | [promethium-terraform-install-role-trust-policy.json](policies_dir/promethium-terraform-install-role-trust-policy.json) | Access required to install Promethium Intelligent Edge (IE)|
| `promethium-efscsi-role` | Promethium Intelligent Edge (IE) | <ul> [promethium-efscsi-policy.json](policies_dir/promethium-efscsi-policy.json) </ul> | [promethium-efscsi-role-trust-policy.json](policies_dir/promethium-efscsi-role-trust-policy.json) | Allows EFS CSI driver in the EKS cluster to provision and manage EFS file systems and access points|
| `promethium-eks-autoscaler-role` | Promethium Intelligent Edge (IE) |  <ul> [promethium-eks-autoscaler-policy.json](policies_dir/promethium-eks-autoscaler-policy.json) </ul>| [promethium-eks-autoscaler-role-trust-policy.json](policies_dir/promethium-eks-autoscaler-role-trust-policy.json) | Allows EKS Autoscaler to add or remove worker nodes in Auto Scaling Groups and inspect EC2 and EKS resources to make scaling decisions |
| `promethium-lbcontroller-role` | Promethium Intelligent Edge (IE) | <ul> [promethium-lbcontroller-policy.json](policies_dir/promethium-lbcontroller-policy.json) </ul> | [promethium-lbcontroller-role-trust-policy.json](policies_dir/promethium-lbcontroller-role-trust-policy.json) | Allows the Load Balancer Controller running the EKS cluster to provision and manage ALBs/NLBs and related networking/security resources on behalf of Kubernetes LoadBalancer ingresses and services |
| `promethium-s3-access-role` | Promethium Intelligent Edge (IE) | <ul> [promethium-s3-access-policy.json](policies_dir/promethium-s3-access-policy.json) </ul>| [promethium-s3-access-role-trust-policy.json](policies_dir/promethium-s3-access-role-trust-policy.json) | Allows for postgres backups into S3 and pull container images from ECR |
| `promethium-eks-cluster-role` | Promethium Intelligent Edge (IE) | <ul><li> [AmazonEKSClusterPolicy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEKSClusterPolicy.html) </li> <li>  [AmazonEKSVPCResourceController](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEKSVPCResourceController.html) </li> </ul>| [promethium-eks-cluster-role-trust-policy.json](policies_dir/promethium-eks-cluster-role-trust-policy.json) | Gives the EKS control plane permissions to run the cluster, manage AWS infrastructure, and  manage pod-level networking |
| `promethium-trino-oidc-role` | Promethium Intelligent Edge (IE) | <ul> [promethium-trino-glue-policy.json](policies_dir/promethium-trino-glue-policy.json) </ul> | [promethium-trino-oidc-role-trust-policy.json](policies_dir/promethium-trino-oidc-role-trust-policy.json)| Query and manage data in Glue Data Catalog and S3. Handle KMS encrypted data and launch and interact with Glue jobs using default service role |
| `promethium-eks-worker-role` | Promethium Intelligent Edge (IE) | <ul><li> [promethium-efscsi-policy.json](policies_dir/promethium-efscsi-policy.json)</li> <li>[promethium-eks-kms-access-policy.json](policies_dir/promethium-eks-kms-access-policy.json) </li> <li> [AmazonEC2ContainerRegistryReadOnly](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEC2ContainerRegistryReadOnly.html)</li> <li> [AmazonEKS_CNI_Policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEKS_CNI_Policy.html)</li><li> [AmazonEKSWorkerNodePolicy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEKSWorkerNodePolicy.html)</li><li> [AmazonSSMManagedInstanceCore](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonSSMManagedInstanceCore.html)</li></ul>| [promethium-eks-worker-role-trust-policy.json](policies_dir/promethium-eks-worker-role-trust-policy.json) | EKS worker node IAM role to mount and manage EFS volumes (via CSI driver). Uses KMS keys for encrypted EFS volumes. Allows image pulls, network management within EKS|
| `promethium-ebscsi-role` | Promethium Intelligent Edge (IE) | <ul><li>[promethium-eks-kms-access-policy.json](policies_dir/promethium-eks-kms-access-policy.json)</li><li> [AmazonEBSCSIDriverPolicy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AmazonEBSCSIDriverPolicy.html)</li></ul>| [promethium-ebscsi-role-trust-policy.json](policies_dir/promethium-ebscsi-role-trust-policy.json)| Allows the EKS EBS CSI driver to provision, attach, delete, and snapshot encrypted EBS volumes in your cluster using your KMS keys. |

---

## 🧪 4. Role and Policy Validation

The following utilities can be used to verify that the roles created have the requisite permissions to execute the installation process.

| Utility                                           | Purpose         |
|------------------------------------------------|---------------|
| update-policies.sh        | Update the role and trust policies with account and region details         |
| tf_install_role_verifier.py    | Verifies permissions associated with PromethiumInstall role                 |
| promethium_app_role_verifier.py | Verifies roles needed for Promethium Intelligent Edge functioning         |

---
