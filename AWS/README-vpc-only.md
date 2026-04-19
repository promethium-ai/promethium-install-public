# ✅ Promethium Intelligent Edge — AWS VPC-Only Installation Guide

In this mode, the customer provides an existing VPC (with subnets and routing). Promethium's Terraform creates all IAM roles, the EKS cluster, EKS add-ons, and all Promethium application services.

---

## 📋 1. Prerequisites

| Requirement | Detail |
|---|---|
| AWS Account | Account ID where the Intelligent Edge will be deployed |
| Region | AWS region for deployment (e.g., `us-east-1`) |
| VPC | At least `/22` CIDR block — see [Section 2](#-2-vpc--subnet-requirements) for subnet layout |
| `company_name` | Agreed with your Promethium representative — max 15 characters, lowercase, no spaces |
| Image tag | Promethium release version (e.g., `24.2.2`) — provided by Promethium |
| Install VM | Amazon Linux 2023 or Ubuntu 22.04/24.04, with outbound HTTPS — see [Section 5](#-5-tool-installation) |
| Outbound Internet | EKS nodes must reach the Promethium image registry and control plane over HTTPS (port 443) |

---

## 🌐 2. VPC & Subnet Requirements

Your VPC must be at least a `/22` CIDR (e.g., `10.0.0.0/22`). Within it, you need **4 subnets** across **2 availability zones**:

| Subnet | Count | AZs | Routing | Required Tags |
|---|---|---|---|---|
| **Public** (for ALB) | 2 | 2 different AZs | Internet Gateway | `kubernetes.io/role/elb=1` |
| **Private** (for EKS nodes) | 2 | 2 different AZs | NAT Gateway | `kubernetes.io/role/internal-elb=1` |

> ⚠️ **Two public subnets in different AZs are required.** AWS Application Load Balancer (ALB) requires subnets in at least 2 availability zones. A single public subnet will cause the ALB provisioning to fail.

> ⚠️ **EKS worker nodes must be placed in private subnets only.** Public subnets auto-assign public IPs to instances, which causes EKS node group creation to fail.

### Example layout for a `10.0.0.0/22` VPC

| Subnet | CIDR | AZ | Type | Purpose |
|---|---|---|---|---|
| subnet-1 | `10.0.0.0/24` | `us-east-1a` | Private | EKS worker nodes |
| subnet-2 | `10.0.1.0/24` | `us-east-1b` | Private | EKS worker nodes |
| subnet-3 | `10.0.2.0/24` | `us-east-1b` | Public | ALB (internet-facing) |
| subnet-4 | `10.0.3.0/24` | `us-east-1a` | Public | ALB (internet-facing) |

### Required subnet tags

All 4 subnets must be tagged with the EKS cluster name tag **before** running Terraform:

| Subnet type | Tag Key | Tag Value |
|---|---|---|
| Public | `kubernetes.io/role/elb` | `1` |
| Public | `kubernetes.io/cluster/<cluster_name>` | `owned` |
| Private | `kubernetes.io/role/internal-elb` | `1` |
| Private | `kubernetes.io/cluster/<cluster_name>` | `owned` |

Where `<cluster_name>` = `promethium-datafabric-<env>-<company_name>-eks-cluster`

---

## 🏗️ 3. Option A — Use the Promethium Network CloudFormation Template

If you do not have an existing VPC, Promethium provides a CloudFormation template that creates all required networking resources.

The template is located at [`AWS/CFT/network.yaml`](CFT/network.yaml) in this repository.

### What it creates

- VPC with configurable CIDR
- 2 private subnets (NAT Gateway routing) — for EKS nodes
- 2 public subnets (Internet Gateway routing) — for ALB
- Internet Gateway and NAT Gateway
- Route tables and associations
- Optional: jumpbox EC2 instance for running the Terraform installation

### Deploy the network stack

```bash
aws cloudformation create-stack \
  --stack-name pmie-network-<company_name> \
  --template-body file://AWS/CFT/network.yaml \
  --parameters \
    ParameterKey=VpcName,ParameterValue=<company_name>-vpc \
    ParameterKey=VpcCidrBlock,ParameterValue=10.0.0.0/22 \
    ParameterKey=EksClusterName,ParameterValue=promethium-datafabric-<env>-<company_name>-eks-cluster \
    ParameterKey=JumpboxName,ParameterValue=<company_name>-jumpbox \
    ParameterKey=UseExistingInstanceProfile,ParameterValue=PromethiumDeploymentRole-<company_name>InstanceProfile \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <aws_region>
```

> ℹ️ Deploy the install role (Section 4) **before** this stack if you want to attach the instance profile to the jumpbox automatically.

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
| `VpcId` | `vpc_info.vpc_id` in tfvars |
| `Subnet1Id` | `vpc_info.subnet_ids` (private) |
| `Subnet2Id` | `vpc_info.subnet_ids` (private) |
| `Subnet3Id` | ALB public subnet (auto-tagged) |
| `Subnet4Id` | ALB public subnet (auto-tagged) |
| `JumpboxInstanceId` | Install VM instance ID |
| `JumpboxSecurityGroupId` | `jumpbox_sg_id` in tfvars |

---

## 🏗️ 4. Option B — Tag Your Existing Subnets

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
for SUBNET_ID in <public_subnet_1> <public_subnet_2>; do
  aws ec2 create-tags --resources $SUBNET_ID --region $REGION --tags \
    Key="kubernetes.io/cluster/${CLUSTER_NAME}",Value=owned \
    Key="kubernetes.io/role/elb",Value=1
done
```

---

## 🔐 5. Deploy the Install Role (CloudFormation)

This CloudFormation stack creates the IAM role and EC2 instance profile that Terraform uses to provision infrastructure. Deploy it in the customer AWS account **before** running Terraform.

```bash
aws cloudformation create-stack \
  --stack-name promethium-install-role-<company_name> \
  --template-body file://AWS/CFT/install_role.yaml \
  --parameters \
    ParameterKey=PromethiumInstallRole,ParameterValue=PromethiumDeploymentRole-<company_name> \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <aws_region>
```

Wait for completion:

```bash
aws cloudformation describe-stacks \
  --stack-name promethium-install-role-<company_name> \
  --query "Stacks[0].Outputs" \
  --region <aws_region>
```

**Outputs to record:**

| Output Key | Description | Used In |
|---|---|---|
| `RoleArn` | ARN of the Terraform deployment role | `terraform_assume_role_arn` in tfvars |
| `InstanceProfileName` | Name of the EC2 instance profile | `jumpbox_instance_profile_name` in tfvars; attach to install VM |

Attach the instance profile to your install VM:

```bash
aws ec2 associate-iam-instance-profile \
  --instance-id <install_vm_instance_id> \
  --iam-instance-profile Name=<InstanceProfileName> \
  --region <aws_region>
```

---

## 🔗 6. Promethium-Side: Grant Cross-Account Trust

> ⚠️ **This step is performed by Promethium**, not the customer. It must be completed before Terraform runs.

Promethium's two internal accounts need to trust the customer's deployment role so that:
- The S3 Terraform state backend can be accessed (account `734236616923`)
- The DynamoDB tenant lookup can run (account `308611924187`)

Add `PromethiumDeploymentRole-<company_name>` to the trust policy of `promethium-terraform-saas-assume-role` in **both** accounts:

```bash
# Account 734236616923 (S3 state backend)
aws iam update-assume-role-policy \
  --role-name promethium-terraform-saas-assume-role \
  --policy-document "$(aws iam get-role \
    --role-name promethium-terraform-saas-assume-role \
    --query 'Role.AssumeRolePolicyDocument' \
    --output json | jq '.Statement += [{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<customer_account_id>:role/PromethiumDeploymentRole-<company_name>"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"iac-terraform"}}}]')" \
  --profile <734236616923-profile>

# Account 308611924187 (DynamoDB tenant lookup)
aws iam update-assume-role-policy \
  --role-name promethium-terraform-saas-assume-role \
  --policy-document "$(aws iam get-role \
    --role-name promethium-terraform-saas-assume-role \
    --query 'Role.AssumeRolePolicyDocument' \
    --output json | jq '.Statement += [{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::<customer_account_id>:role/PromethiumDeploymentRole-<company_name>"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"iac-terraform"}}}]')" \
  --profile <308611924187-profile>
```

---

## 🛠️ 7. Tool Installation

SSH or SSM into your install VM, then run:

```bash
# Terraform >= 1.14
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum install -y terraform
terraform -v

# kubectl >= 1.29
curl -LO "https://dl.k8s.io/release/$(curl -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
kubectl version --client

# Helm >= 3.20
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm version

# AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install
aws --version

# Python 3.10+
python3 --version
```

Or use the install script provided in this repo:

```bash
cd AWS && ./utilities/install_tools.sh
```

---

## ⚙️ 8. Configure Terraform

### 7.1 Clone the deployment repo

```bash
git clone https://github.com/promethium-ai/promethium-internal-ie-aws.git
cd promethium-internal-ie-aws
git checkout <release_branch>   # provided by Promethium
```

### 7.2 Configure `backend.tf`

```hcl
terraform {
  backend "s3" {
    bucket  = "pm61-iac-terraform-state"
    key     = "<env>/<company_name>/terraform.tfstate"
    region  = "us-east-1"
  }
}
```

### 7.3 Create `terraform.tfvars`

Replace all `<placeholder>` values before proceeding:

```hcl
# ── Core ──────────────────────────────────────────────────────────────────────
env          = "<env>"            # dev | qa | preview | prod
company_name = "<company_name>"   # max 15 chars, lowercase, no spaces
aws_region   = "<aws_region>"     # e.g. us-east-1

# ── Terraform identity ────────────────────────────────────────────────────────
terraform_assume_role_arn = "<RoleArn from CFT output>"

# ── VPC (customer-provided) ───────────────────────────────────────────────────
vpc_enabled = false

vpc_info = {
  vpc_id         = "<vpc_id>"
  # Private subnets only — do NOT include public subnets here
  subnet_ids     = ["<private_subnet_1>", "<private_subnet_2>"]
  vpc_cidr_block = "<vpc_cidr>"   # e.g. 10.0.0.0/22
}

# ── IAM ───────────────────────────────────────────────────────────────────────
iam_role_create      = true   # Terraform creates EKS cluster + worker roles
aws_iam_oidc_enabled = true   # Terraform creates all OIDC/IRSA roles

# ── EKS ───────────────────────────────────────────────────────────────────────
custom_cluster_name = true
eks_cluster_name    = "promethium-datafabric-<env>-<company_name>-eks-cluster"
eks_cluster_type    = "public"   # public | private
jumpbox_enabled     = false

jumpbox_sg_id                 = "<JumpboxSecurityGroupId from network CFT output>"
jumpbox_instance_profile_name = "<InstanceProfileName from install role CFT output>"

# ── Promethium application ────────────────────────────────────────────────────
promethium_image_tag = "<image_tag>"   # e.g. 24.2.2

# ── Tagging ───────────────────────────────────────────────────────────────────
default_tags = {
  Environment = "<env>"
  Product     = "Promethium"
  Owner       = "support@promethium.ai"
  created-by  = "Terraform"
  Project     = "Intelligentedge"
  persist     = "false"
}
```

> ⚠️ **`subnet_ids` must contain only private subnets.** EKS worker nodes are placed in these subnets. Public subnets auto-assign public IPs to instances and will cause the node group to fail.

---

## 🚀 9. Deployment

### Phase 1 — AWS Infrastructure

Creates IAM roles, EKS cluster and node groups, S3 buckets, KMS keys, EFS, Glue database, OIDC provider, and all IRSA roles.

All Promethium clusters are private (`eks_cluster_type = "private"`). Because the EKS API endpoint is VPC-internal, the jumpbox security group must be explicitly authorized to reach it on port 443 **after** the cluster is created but **before** Terraform attempts to configure it. Phase 1 is therefore split into three steps.

#### Phase 1a — Create EKS cluster

```bash
terraform init
terraform apply -target=module.aws.module.eks.aws_eks_cluster.ekscluster
```

> Expected duration: 10–15 minutes.

#### Phase 1b — Authorize jumpbox to cluster API

```bash
CLUSTER_SG=$(aws eks describe-cluster \
  --name promethium-datafabric-prod-<company_name>-eks-cluster \
  --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' \
  --output text --region <aws_region>)

aws ec2 authorize-security-group-ingress \
  --group-id $CLUSTER_SG \
  --protocol tcp \
  --port 443 \
  --source-group <jumpbox_sg_id> \
  --region <aws_region>
```

Verify kubectl connectivity from the jumpbox:

```bash
aws eks update-kubeconfig --region <aws_region> \
  --name promethium-datafabric-prod-<company_name>-eks-cluster
kubectl get nodes
```

#### Phase 1c — Complete AWS infrastructure

```bash
terraform apply -target=module.aws
```

> Expected duration: 10–15 minutes (node groups, OIDC, S3, KMS, EFS).

Before typing `yes`, verify the plan includes:
- `aws_iam_role` entries for EKS cluster, worker, and OIDC roles
- `aws_eks_node_group`
- `aws_efs_file_system` and `aws_s3_bucket`
- `aws_kms_key` entries

### Phase 2 — Not required for AWS

There is no Phase 2 for AWS deployments. Proceed directly to Phase 3.

### Phase 3 — Promethium Services

Installs Postgres, Redash, Trino, pipeline services, ingress, and monitoring.

```bash
terraform apply
```

> Expected duration: 10–20 minutes.

> ℹ️ If you see an ingress hostname timing error on first run (the ALB takes a few minutes to provision after the LB controller starts), wait 3–5 minutes and re-run `terraform apply`.

---

## ✅ 10. Post-Install Verification

### Get cluster credentials

```bash
aws eks update-kubeconfig \
  --name promethium-datafabric-<env>-<company_name>-eks-cluster \
  --region <aws_region>
```

### Check pods

```bash
kubectl get pods -n intelligentedge
kubectl get pods -n cluster-management
```

All pods should be `Running` or `Completed`.

### Check the ALB hostname

```bash
kubectl get ingress -n intelligentedge
```

Note the `ADDRESS` field — this is the ALB DNS name to use for DNS records.

### Update DNS

Create CNAME records pointing your Promethium subdomains to the ALB DNS name:

| Record | Value |
|---|---|
| `<company_name>.prod.promethium.ai` | `<alb_dns_name>` |
| `<company_name>-redash.prod.promethium.ai` | `<alb_dns_name>` |
| `<company_name>-trino.prod.promethium.ai` | `<alb_dns_name>` |

---

## 🔧 11. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `subnets count less than minimal required count: 1 < 2` in LB controller logs | Only 1 public subnet tagged `kubernetes.io/role/elb` | Add a second public subnet in a different AZ and tag it; restart `aws-load-balancer-controller` deployment |
| `unable to resolve at least one subnet (0 match VPC and tags: [kubernetes.io/role/elb])` | Public subnets missing `kubernetes.io/role/elb=1` tag | Tag both public subnets per Section 4 |
| EKS node group fails: `instances do not support public IP assignment` | Public subnet included in `subnet_ids` | Remove public subnets from `vpc_info.subnet_ids`; private subnets only |
| Pods stuck `Pending` | Node group not scaled, or subnets missing EKS cluster tag | Check ASG in EC2 console; verify `kubernetes.io/cluster/<cluster_name>=owned` tag on all subnets |
| Ingress hostname empty after Phase 3 | ALB not yet provisioned | Wait 3–5 min, check `aws-load-balancer-controller` logs, re-run `terraform apply` |
| Terraform `iam:GetRole` denied on `aws-service-role/*` | Install role missing `aws-service-role/*` resource on `iam:GetRole` | Redeploy `install_role.yaml` — latest version covers this |
| `filter_tenant.sh: AWS credentials are not set` | Script checking for env vars instead of instance profile | Run `export $(aws configure export-credentials --format env)` before `terraform apply`, or use the latest `promethium-iac-terraform` version which uses instance profile detection |
