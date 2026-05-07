# Promethium Intelligent Edge AWS Installation (Customer)

![Promethium Intelligent Edge (AWS)](../images/AWS_IE.png)

This page documents instructions for the customer on how to setup prerequisites for a secure Promethium IE on AWS. The full deployment is an Elastic Kubernetes Service (EKS) cluster within which the Promethium application services are deployed, fronted by an internal Application Load Balancer (ALB).

- [Promethium Intelligent Edge AWS Installation (Customer)](#promethium-intelligent-edge-aws-installation-customer)
- [Overview](#overview)
    - [How it works](#how-it-works)
    - [Environment Prerequisites](#environment-prerequisites)
    - [Subnet Requirements](#subnet-requirements)
    - [Networking Requirements](#networking-requirements)
      - [Install VM - Outbound Access](#install-vm---outbound-access)
      - [EKS Nodes - Outbound Access](#eks-nodes---outbound-access)
- [Setup Customer Prerequisites](#setup-customer-prerequisites)
  - [1. IAM Install Roles](#1-iam-install-roles)
  - [2. VPC subnet](#2-vpc-subnet)
    - [4.a Option A — Create VPC with Promethium Network CFT](#4a-option-a--create-vpc-with-promethium-network-cft)
      - [What it creates](#what-it-creates)
      - [Deploy the network stack](#deploy-the-network-stack)
    - [4.b Option B — Tag Your Existing Subnets](#4b-option-b--tag-your-existing-subnets)
  - [5. Jumpbox](#5-jumpbox)
    - [5.a Option A — Create Jumpbox with Promethium Jumpbox CFT](#5a-option-a--create-jumpbox-with-promethium-jumpbox-cft)
      - [Required inputs (from previous stack outputs)](#required-inputs-from-previous-stack-outputs)
      - [Deploy the jumpbox stack](#deploy-the-jumpbox-stack)
    - [5.b Option B - Attach the instance profile to your provided install VM](#5b-option-b---attach-the-instance-profile-to-your-provided-install-vm)
  - [6. Operational Roles](#6-operational-roles)
      - [6.a Option A — New cluster (default name format)](#6a-option-a--new-cluster-default-name-format)
      - [6.b Option B — Pre-existing cluster (custom name override)](#6b-option-b--pre-existing-cluster-custom-name-override)
  - [7. Operational Roles](#7-operational-roles)
  - [8. Customer Information Required by Promethium](#8-customer-information-required-by-promethium)
    - [AWS Environment](#aws-environment)
    - [VPC and Subnets](#vpc-and-subnets)
    - [Install VM](#install-vm)
    - [Provided by Promethium](#provided-by-promethium)
  - [7. Additional Resources](#7-additional-resources)

---
# Overview

TODO: get outputs automatically with aws cloudformation describe-stacks with outputs, rather than asking user to keep track of them.

### How it works

Installing a Promethium Intelligent Edge (IE) cluster requires two parties:
- The customer will first provide prerequisite AWS infrastructure - VPC, subnets, install VM, install role, and operational IAM roles, etc.
- The Promethium associate will then deploy the EKS cluster with Terraform, configure OIDC trust policies, and install the full Promethium application stack.

Promethium is always deployed with an **internal load balancer** — accessible via VPN only.

Once the customer has provided the prerequisite infrastructure and variables, the Promethium associate will then follow a separate [AWS Install Guide](aws-install.md)

---

### Environment Prerequisites

| Item | Description |
|------|-------------|
| AWS Account | The AWS account where the Promethium Intelligent Edge will be deployed |
| Region | AWS region for deployment (e.g., `eu-central-1`) |
| Install VM/jumpbox | An EC2 instance with an attached Security Group |
| VPC | An existing VPC of at least `/22` CIDR |
| Private Subnets | Minimum 3 private subnets across 3 availability zones (recommended: 4) — for EKS worker nodes and internal ALB |
| Outbound Internet Access | The install VM and EKS nodes require outbound HTTPS access via NAT Gateway |
| Company Name | A `<company_name>` variable used throughout the deployment — max 15 characters, lowercase, no spaces |
| GitHub PAT | A GitHub Personal Access Token with `read:packages` scope (provided by Promethium) |
| Promethium Image Tag | Application release version (e.g., `24.2.2`) — provided by Promethium |

### Subnet Requirements

Only private subnets are required. No public subnets are needed.

| Configuration | Count | AZs | Routing | Required Tags |
|---|---|---|---|---|
| **Required (minimum)** | 3 | 3 different AZs | NAT Gateway | `kubernetes.io/role/internal-elb=1` |
| **Recommended** | 4 | 2+ different AZs | NAT Gateway | `kubernetes.io/role/internal-elb=1` |

> **Note:** Public subnets must never have `kubernetes.io/*` tags to avoid unintended ALB subnet discovery.

### Networking Requirements

#### Install VM - Outbound Access

| Endpoint | Purpose |
|----------|---------|
| `github.com`, `*.githubusercontent.com` | Clone Terraform wrapper repo |
| `ghcr.io` | Pull Helm charts |
| `releases.hashicorp.com` | Download Terraform binary |
| `registry.terraform.io` | Terraform provider and module downloads |
| `dl.k8s.io` | Download kubectl |
| `*.amazonaws.com` | AWS API endpoints (EKS, EC2, IAM, S3, ACM, Route 53) |
| `sts.amazonaws.com` | AWS STS assume-role |

#### EKS Nodes - Outbound Access

| Endpoint | Port | Purpose |
|----------|------|---------|
| `*.eks.amazonaws.com` | 443 | EKS API server communication |
| `*.ecr.*.amazonaws.com` | 443 | Promethium container images (AWS ECR) |
| `sts.amazonaws.com` | 443 | AWS STS for ECR token refresh |
| `ghcr.io` | 443 | Promethium Helm charts |
| `s3.amazonaws.com`, `*.s3.amazonaws.com` | 443 | S3 access for EKS and application data |

---

# Setup Customer Prerequisites

## 1. IAM Install Roles


Deploy [`CFT/install_role.yaml`](CFT/install_role.yaml). This creates:

| Role | Used By | Purpose |
|------|---------|---------|
| `PromethiumDeploymentRole` | Install VM (jumpbox) | Terraform deployment role — attached to the install VM as an EC2 instance profile. Used to create and configure all Promethium infrastructure |

> The role is created as an **EC2 Instance Profile** and attached directly to the install VM. No access keys are needed.

Create the IAM role and EC2 instance profile that Terraform uses to provision infrastructure.

```bash
aws cloudformation create-stack \
  --stack-name promethium-install-role-<company_name> \
  --template-body file://AWS/CFT/install_role.yaml \
  --parameters \
    ParameterKey=PromethiumInstallRole,ParameterValue=PromethiumDeploymentRole-<company_name> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <aws_region>
```

Then run the following command in your AWS-authenticated terminal to allow the role to assume itself (allowing terraform on EC2 to chain credential sessions):
```bash
STACK_NAME="promethium-install-role-<company_name>"
ROLE_ARN=$(aws cloudformation describe-stacks --stack-name "$STACK_NAME" --query 'Stacks[0].Outputs[?OutputKey==`RoleArn`].OutputValue' --output text)
ROLE_NAME="${ROLE_ARN##*/}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
CURRENT_POLICY=$(aws iam get-role --role-name "$ROLE_NAME" --query 'Role.AssumeRolePolicyDocument' --output json)

NEW_POLICY=$(echo "$CURRENT_POLICY" | jq --arg arn "$ROLE_ARN" '.Statement += [{"Effect":"Allow","Principal":{"AWS":$arn},"Action":"sts:AssumeRole"}]')

aws iam update-assume-role-policy --role-name "$ROLE_NAME" --policy-document "$NEW_POLICY"
```


Wait for completion and record the outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name promethium-install-role-<company_name> \
  --query "Stacks[0].Outputs" \
  --region <aws_region>
```

| Output Key | Description | Used In |
|---|---|---|
| `RoleArn` | ARN of the Terraform deployment role | `terraform_assume_role_arn` in tfvars |
| `InstanceProfileName` | Name of the EC2 instance profile | `jumpbox_instance_profile_name` in tfvars; attach to install VM |


## 2. VPC subnet

- If you don't yet have a VPC with subnets, follow `4.a` and skip `4.b`. 
- If you already have a VPC with subnets, follow `4.b` and skip `4.a`.

### 4.a Option A — Create VPC with Promethium Network CFT

If you do not have an existing VPC, Promethium provides a CloudFormation template (CFT) that creates all required networking resources.

The template is located at [`AWS/CFT/network.yaml`](CFT/network.yaml) in this repository.

#### What it creates

TODO: reword this

Internal ALB only (no public subnets needed for ALB) — 3 private + 1 public (for NAT GW) works, but requires customers to access Promethium over VPN/Direct Connect, not the public internet.

- VPC with configurable CIDR
- 3 private subnets (NAT Gateway routing) — for EKS nodes
- 1 public subnets (for VPN access)
- Internet Gateway and NAT Gateway
- Route tables and associations

#### Deploy the network stack

```bash
aws cloudformation create-stack \
  --stack-name pmie-network-<company_name> \
  --template-body file://AWS/CFT/network.yaml \
  --parameters \
    ParameterKey=VpcName,ParameterValue=<company_name>-vpc \
    ParameterKey=VpcCidrBlock,ParameterValue=10.0.0.0/22 \
    ParameterKey=EksClusterName,ParameterValue=promethium-datafabric-<env>-<company_name>-eks-cluster \
  --region <aws_region>
```

Wait for completion and note the outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name pmie-network-<company_name> \
  --query "Stacks[0].Outputs" \
  --region <aws_region>
```

**Outputs to record:**

| Output Key | Used In |
|---|---|
| `VpcId` | `vpc_info.vpc_id` in tfvars; required input for jumpbox stack |
| `Subnet1Id` | `vpc_info.subnet_ids` (private); required input for jumpbox stack |
| `Subnet2Id` | `vpc_info.subnet_ids` (private) |
| `Subnet3Id` | `vpc_info.subnet_ids` (private) |
| `Subnet4Id` | public subnet, NAT Gateway only (not used in tfvars) |

---

### 4.b Option B — Tag Your Existing Subnets

If you are bringing your own VPC, apply the required EKS tags using the tagging utility:

```bash
cd AWS
./utilities/tag_subnets.sh <vpc_id> <aws_region> <company_name>
```

Or apply them manually:

```bash
CLUSTER_NAME="promethium-datafabric-<env>-<company_name>-eks-cluster"
REGION="<aws_region>"

# Private subnets (EKS nodes)
for SUBNET_ID in <private_subnet_1> <private_subnet_2>; do
  aws ec2 create-tags --resources $SUBNET_ID --region $REGION --tags \
    Key="kubernetes.io/cluster/${CLUSTER_NAME}",Value=owned \
    Key="kubernetes.io/role/internal-elb",Value=1
done

# Public subnets (ALB) — must be in 2 different AZs
# for SUBNET_ID in <public_subnet_1> <public_subnet_2>; do
#   aws ec2 create-tags --resources $SUBNET_ID --region $REGION --tags \
#     Key="kubernetes.io/cluster/${CLUSTER_NAME}",Value=owned \
#     Key="kubernetes.io/role/elb",Value=1
# done
```

## 5. Jumpbox

- If you don't yet have an install VM, follow `5.a` (skip `5.b`) to create one with the Promethium jumpbox CFT.
- If you already have an install VM, follow `5.b` (skip `5.a`) to attach the instance profile to it.

### 5.a Option A — Create Jumpbox with Promethium Jumpbox CFT

The template is located at [`AWS/CFT/jumpbox.yaml`](CFT/jumpbox.yaml).

#### Required inputs (from previous stack outputs)

| Parameter | Value | Source |
|---|---|---|
| `VpcId` | VPC ID | `pmie-network-<company_name>` output `VpcId`, or your existing VPC ID |
| `PrivateSubnet1Id` | Private Subnet 1 ID (AZ-a) | `pmie-network-<company_name>` output `Subnet1Id`, or your existing private subnet ID |

#### Deploy the jumpbox stack

```bash
aws cloudformation create-stack \
  --stack-name pmie-jumpbox-<company_name> \
  --template-body file://AWS/CFT/jumpbox.yaml \
  --parameters \
    ParameterKey=VpcId,ParameterValue=<vpc_id> \
    ParameterKey=PrivateSubnet1Id,ParameterValue=<private_subnet_1_id> \
    ParameterKey=JumpboxName,ParameterValue=<company_name>-jumpbox \
    ParameterKey=UseExistingInstanceProfile,ParameterValue=PromethiumDeploymentRole-<company_name>InstanceProfile \
  --region <aws_region>
```

> ℹ️ Deploy the install role (Section 3) **before** this stack to attach the instance profile automatically via `UseExistingInstanceProfile`.

Wait for completion and record the outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name pmie-jumpbox-<company_name> \
  --query "Stacks[0].Outputs" \
  --region <aws_region>
```

**Outputs to record:**

| Output Key | Description | Used In |
|---|---|---|
| `JumpboxInstanceId` | Install VM instance ID | Reference when connecting via SSM |
| `JumpboxSecurityGroupId` | Jumpbox security group ID | `jumpbox_sg_id` in tfvars |

### 5.b Option B - Attach the instance profile to your provided install VM

```bash
aws ec2 associate-iam-instance-profile \
  --instance-id <install_vm_instance_id> \
  --iam-instance-profile Name=<InstanceProfileName> \
  --region <aws_region>
```

---

## 6. Operational Roles

Deploy [`CFT/operational_roles.yaml`](CFT/operational_roles.yaml).

- If you don't yet have an EKS cluster, follow `6.a` (skip `6.b`) since we will be using a default cluster name format.
- If you already have an EKS cluster, follow `6.b` (skip `6.a`) to use your cluster's custom name.

> `OIDCProviderUrl` is left as the default dummy value — it is updated after Phase 1a once the EKS cluster and OIDC provider exist.

#### 6.a Option A — New cluster (default name format)

Use this when Promethium will create the EKS cluster. The cluster name defaults to `promethium-datafabric-prod-<company_name>-eks-cluster`.

```bash
aws cloudformation create-stack \
  --stack-name promethium-eks-base-roles-<company_name> \
  --template-body file://AWS/CFT/operational_roles.yaml \
  --parameters \
    ParameterKey=CompanyName,ParameterValue=<company_name> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <aws_region>
```

#### 6.b Option B — Pre-existing cluster (custom name override)

Use this when the customer already has an EKS cluster whose name differs from the default format. Set `CustomClusterName` to the existing cluster's name.

```bash
aws cloudformation create-stack \
  --stack-name promethium-eks-base-roles-<company_name> \
  --template-body file://AWS/CFT/operational_roles.yaml \
  --parameters \
    ParameterKey=CompanyName,ParameterValue=<company_name> \
    ParameterKey=CustomClusterName,ParameterValue=<existing_cluster_name> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <aws_region>
```
---

Whichever option you chose, wait for completion and record the outputs:

```bash
aws cloudformation describe-stacks \
  --stack-name promethium-eks-base-roles-<company_name> \
  --query "Stacks[0].Outputs" \
  --region <aws_region>
```

This creates all 8 operational roles (all names are suffixed with `<company_name>`):

| Role | Used By | Purpose |
|------|---------|---------|
| `promethium-prod-eks-cluster-role-<company_name>` | EKS control plane | Gives the EKS control plane permissions to run the cluster, manage AWS infrastructure, and manage pod-level networking |
| `promethium-prod-eks-worker-role-<company_name>` | EKS worker nodes | Allows nodes to pull container images from ECR, manage EFS volumes via CSI driver, and handle network management within EKS |
| `promethium-prod-ebs-csi-driver-role-<company_name>` | EBS CSI driver | Allows the EBS CSI driver to provision, attach, delete, and snapshot encrypted EBS volumes using KMS keys |
| `promethium-prod-efs-csi-driver-role-<company_name>` | EFS CSI driver | Allows the EFS CSI driver to provision and manage EFS file systems and access points |
| `promethium-prod-lb-controller-role-<company_name>` | Load Balancer Controller | Allows the LB Controller to provision and manage ALBs/NLBs on behalf of Kubernetes ingress and service resources |
| `promethium-prod-cluster-autoscaler-role-<company_name>` | Cluster Autoscaler | Allows the autoscaler to add or remove worker nodes in Auto Scaling Groups based on cluster demand |
| `promethium-prod-pg-backup-role-<company_name>` | Postgres backup | Allows postgres backups to be written to S3 and container images to be pulled from ECR |
| `promethium-prod-glue-trino-role-<company_name>` | Trino / Glue crawlers | Allows Trino to query and manage data in Glue Data Catalog and S3, handle KMS-encrypted data, and interact with Glue jobs |

**Outputs to record:**

| Output Key | Used In |
|---|---|
| `EKSClusterRoleArn` | `cluster_role_arn` in tfvars |
| `EKSWorkerNodeRoleArn` | `worker_role_arn` in tfvars |
| `EBSCSIDriverRoleArn` | `aws_ebs_driver_role_arn` in tfvars |
| `EFSCSIDriverRoleArn` | `aws_efs_driver_role_arn` in tfvars |
| `LoadBalancerControllerRoleArn` | `aws_lb_controller_role_arn` in tfvars |
| `ClusterAutoscalerRoleArn` | `aws_eks_autoscaler_role_arn` in tfvars |
| `PGBackupServiceRoleArn` | `pg_backup_cronjob_oidc_role_arn` in tfvars |
| `GlueTrinoServiceRoleArn` | `trino_oidc_role_arn` in tfvars |

---


## 7. Operational Roles

## 8. Customer Information Required by Promethium

### AWS Environment

| # | Item | Where to find it |
|---|------|-----------------|
| 1 | AWS Account ID | Console → top-right menu |
| 2 | AWS Region | Console → top navigation bar |
| 3 | Agreed `company_name` | Agreed with Promethium representative |

### VPC and Subnets

**AWS Console → VPC → Your VPCs** → note VPC ID and CIDR

**AWS Console → VPC → Subnets** → filter by VPC → find subnets routing via NAT Gateway

| # | Item |
|---|------|
| 4 | VPC ID |
| 5 | VPC CIDR block |
| 6 | Private Subnet IDs (3 minimum, in different AZs) |

### Install VM

**AWS Console → EC2 → Instances** → find jumpbox

| # | Item |
|---|------|
| 7 | Jumpbox Instance ID (`i-xxx`) |
| 8 | Jumpbox Security Group ID (`sg-xxx`) |

### Provided by Promethium

| Item | Description |
|------|-------------|
| `promethium_image_tag` | Application version to deploy |
| `company_name` | Agreed jointly with your Promethium representative |
| GitHub PAT | Personal Access Token for private Terraform modules |
| GHCR Token | Token for pulling Helm charts |

---

## 7. Additional Resources

| Resource | Description |
|----------|-------------|
| [AWS Install Guide](aws-install.md) | Step-by-step installation guide for Promethium associates |
| [Install Role CFT](CFT/install_role.yaml) | Creates the Terraform deployment role and instance profile |
| [Verifier Policy CFT](CFT/verifier_policy.yaml) | Adds read-only permissions for running pre-install verifier scripts from the jumpbox |
| [Operational Roles CFT](CFT/operational_roles.yaml) | Creates EKS cluster role, worker role, and all 6 OIDC/IRSA roles |
| [S3 Private Crawler](CFT/s3-private-crawler/) | VPC gateway endpoint and Glue network connection for private S3 access |

> For customers needing private S3 access for Trino and Glue crawlers, see the `CFT/s3-private-crawler` folder, which includes the deployment guidance and CloudFormation template for the gateway endpoint and Glue NETWORK connection.
| [Utilities](utilities/) | Helper scripts for tool installation, role verification, and diagnostics |
