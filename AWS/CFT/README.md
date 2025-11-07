# Promethium IAM CloudFormation Templates

This package contains two CloudFormation templates that configure the necessary IAM roles and permissions for deploying and operating Promethium Intelligent Edge on AWS.

## Overview

- **install_role.yaml** - Creates the deployment role used by Terraform to install Promethium infrastructure
- **operational_roles.yaml** - Creates the operational roles needed by the EKS cluster and its services

## Template 1: install_role.yaml

### Purpose
Creates an IAM role and instance profile that Terraform uses to deploy the Promethium EKS infrastructure.

### What It Creates
- **IAM Role**: `PromethiumDeploymentRole` (customizable)
- **Instance Profile**: Attached to EC2 instances running Terraform
- **Managed Policy**: AWS Systems Manager access for remote management

### Permissions Included
The deployment role has permissions to create and manage:
- EKS clusters and node groups
- VPC networking (subnets, security groups, routing)
- EFS file systems
- S3 buckets (Trino data, PostgreSQL backups)
- KMS encryption keys
- ACM certificates
- EC2 instances and launch templates
- AWS Glue databases and catalogs
- Elastic Load Balancers

### Parameters
- **PromethiumInstallRole**: Name for the deployment role (default: `PromethiumDeploymentRole`)

### Deployment
```bash
aws cloudformation create-stack \
  --stack-name promethium-install-role \
  --template-body file://install_role.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

## Template 2: operational_roles.yaml

### Purpose
Creates the IAM roles required by Kubernetes service accounts and EKS cluster operations after installation.

### What It Creates
Eight IAM roles for different operational components:

1. **EBS CSI Driver Role** - Manages EBS volumes for persistent storage
2. **EFS CSI Driver Role** - Manages EFS access points for shared storage
3. **Load Balancer Controller Role** - Creates and manages AWS load balancers
4. **Cluster Autoscaler Role** - Scales worker nodes based on demand
5. **EKS Cluster Role** - Core EKS control plane permissions
6. **EKS Worker Node Role** - Permissions for EC2 worker nodes
7. **PostgreSQL Backup Service Role** - Backs up databases to S3 and accesses ECR
8. **Glue Trino Service Role** - Accesses AWS Glue catalog and S3 data

### Parameters
All parameters are optional and allow customization:

- **ClusterName**: EKS cluster name (default: `promethium-datafabric-prod-eks-cluster`)
- **OIDCProviderUrl**: OIDC provider URL from your EKS cluster (required - replace the dummy value)
- **Role Name Parameters**: Custom names for each of the 8 roles (optional)

### Prerequisites
Before deploying this template, you need:
1. An EKS cluster already created
2. The OIDC provider URL from your cluster

To get your OIDC provider URL:
```bash
aws eks describe-cluster --name <cluster-name> --query "cluster.identity.oidc.issuer" --output text
```

### Deployment
```bash
aws cloudformation create-stack \
  --stack-name promethium-operational-roles \
  --template-body file://operational_roles.yaml \
  --parameters \
    ParameterKey=ClusterName,ParameterValue=your-cluster-name \
    ParameterKey=OIDCProviderUrl,ParameterValue=oidc.eks.region.amazonaws.com/id/YOUR_OIDC_ID \
  --capabilities CAPABILITY_NAMED_IAM
```

## Deployment Order

1. **First**: Deploy `install_role.yaml` to create the Terraform deployment role
2. **Second**: Use Terraform with the created role to deploy your EKS infrastructure
3. **Third**: Deploy `operational_roles.yaml` with your actual cluster OIDC provider URL

## Important Notes

### Security Considerations
- Both templates create IAM roles with specific, scoped permissions
- The install role includes cross-account assume role permissions for specific Promethium SaaS accounts
- All roles follow the principle of least privilege for their specific functions

### Customization
- Role names can be customized using template parameters
- Resource naming follows the pattern: `promethium-prod-*` (configurable)
- All resources are tagged with CloudFormation stack information

### Service Account Bindings
After deploying operational_roles.yaml, you'll need to annotate Kubernetes service accounts with the IAM role ARNs. Example:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebs-csi-controller-sa
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/promethium-prod-ebs-csi-driver-role
```

## Outputs

### install_role.yaml Outputs
- `RoleArn` - ARN of the Terraform deployment role
- `InstanceProfileArn` - ARN of the EC2 instance profile
- `InstanceProfileName` - Name of the instance profile

### operational_roles.yaml Outputs
- Role ARNs for all 8 operational roles (used in Kubernetes service account annotations)

## Support

For questions or issues with these templates, please contact your Promethium support team.
