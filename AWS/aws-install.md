# Promethium Intelligent Edge AWS Installation (Promethium Associate)

This page documents instructions for the Promethium associate on completing the AWS install, once the customer prerequisites ([`README.md`](README.md)) are completed.

The customer provides an existing VPC (with subnets and routing), an EC2 install VM/jumpbox, the Terraform install role (`install_role.yaml`), and all operational IAM roles (`operational_roles.yaml`). Promethium's Terraform creates the EKS cluster, configures OIDC trust policies, deploys EKS add-ons, and installs the full Promethium application stack.

Promethium is deployed with an **internal load balancer** — accessible via VPN only.

- [Promethium Intelligent Edge AWS Installation (Promethium Associate)](#promethium-intelligent-edge-aws-installation-promethium-associate)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [0. Create Customer Branch](#0-create-customer-branch)
  - [1. Setup: Connect to the Install VM and Load Variables](#1-setup-connect-to-the-install-vm-and-load-variables)
    - [1.1 Tool Installation](#11-tool-installation)
    - [1.2 Github Token](#12-github-token)
    - [1.3 Login to Helm OCI registry](#13-login-to-helm-oci-registry)
  - [2. Configure Terraform Branch](#2-configure-terraform-branch)
    - [2.1 Clone the deployment repo](#21-clone-the-deployment-repo)
    - [2.2 Configure `backend.tf`](#22-configure-backendtf)
    - [2.3 Create `terraform.tfvars`](#23-create-terraformtfvars)
  - [3. Grant Cross-Account Trust](#3-grant-cross-account-trust)
  - [4. Verification (optional)](#4-verification-optional)
      - [4.1 Verifier Permissions (required before running verifier scripts)](#41-verifier-permissions-required-before-running-verifier-scripts)
      - [4.2 Verifier Steps (Promethium Associate)](#42-verifier-steps-promethium-associate)
  - [5. Deployment](#5-deployment)
    - [Phase 1 — AWS Infrastructure](#phase-1--aws-infrastructure)
      - [Phase 1a — Create EKS cluster](#phase-1a--create-eks-cluster)
      - [Phase 1b — Authorize jumpbox to cluster API](#phase-1b--authorize-jumpbox-to-cluster-api)
      - [Phase 1c — Complete AWS infrastructure](#phase-1c--complete-aws-infrastructure)
    - [Phase 2 — Not required for AWS](#phase-2--not-required-for-aws)
    - [Phase 3 — Promethium Services](#phase-3--promethium-services)
  - [6. Post-Install Steps](#6-post-install-steps)
    - [6.1 Check pods](#61-check-pods)
    - [6.2 Update support password](#62-update-support-password)
  - [7. Troubleshooting](#7-troubleshooting)
  - [8. Teardown](#8-teardown)


---

# Prerequisites

| Requirement | Detail |
|---|---|
| AWS Account | Account ID where the Intelligent Edge will be deployed |
| Region | AWS region for deployment (e.g., `us-east-1`) |
| VPC | At least `/22` CIDR block — see [Section 2](#-2-vpc--subnet-requirements) for subnet layout |
| `company_name` | Agreed with your Promethium representative — max 15 characters, lowercase, no spaces |
| Image tag | Promethium release version (e.g., `24.2.2`) — provided by Promethium |
| Install VM | Amazon Linux 2023 or Ubuntu 22.04/24.04, with outbound HTTPS — see [Section 6](#-6-tool-installation) |
| Outbound Internet | EKS nodes must reach the Promethium image registry and control plane over HTTPS (port 443) |

---

# Installation

## 0. Create Customer Branch

> ⚠️ **Run this on your local machine**, not the jumpbox — this is the only step in the guide that is not run on the install VM.

Copy `promethium-outputs-<company_name>.sh` (generated in [README.md Section 6](README.md#6-customer-information-required-by-promethium)) to the jumpbox, then source it at the start of each session:

> Replace `<company_name>` with the customer's company name before running.

```bash
source promethium-outputs-<company_name>.sh
```

Create the customer branch:
```bash
git clone https://github.com/promethium-ai/promethium-internal-ie-aws.git
cd promethium-internal-ie-aws
git checkout main && git pull
git checkout -b ${COMPANY_NAME}
git push -u origin ${COMPANY_NAME}
```

## 1. Setup: Connect to the Install VM and Load Variables

All following commands in this guide are run from the **install VM (jumpbox)** (unless explicitly stated). Connect to it via **AWS Console → EC2 → Instances → select the jumpbox → Connect → Session Manager**.

First run as root and get into the default directory `/root`:
```bash
sudo su
cd
```

> The rest of the jumpbox commands must be run in this `/root` environment.

Copy `promethium-outputs-<company_name>.sh` (generated in [README.md Section 6](README.md#6-customer-information-required-by-promethium)) to the jumpbox, then source it at the start of each session:

> Replace `<company_name>` with the customer's company name before running.

```bash
source promethium-outputs-<company_name>.sh
```
---

### 1.1 Tool Installation

We need to install tools like git. In the install VM, run:

```bash
curl -O https://raw.githubusercontent.com/promethium-ai/promethium-install-public/main/AWS/utilities/install_tools.sh
bash install_tools.sh
```

### 1.2 Github Token

> Replace `<github_pat>` and `<ghcr_token>` with the Github PAT values provided by Promethium.

```bash
# GitHub tokens
export GH_TOKEN="<github_pat>"
export GHCR_TOKEN="<ghcr_token>"
git config --global url."https://${GH_TOKEN}@github.com/".insteadOf "https://github.com/"
```

### 1.3 Login to Helm OCI registry

```bash
# TODO research this
export HELM_EXPERIMENTAL_OCI=1
helm registry login ghcr.io -u promethium-ai --password-stdin <<< "$GHCR_TOKEN"
```

## 2. Configure Terraform Branch

### 2.1 Clone the deployment repo

From the Install VM/jumpbox, do:

```bash
git clone -b ${COMPANY_NAME} --single-branch https://github.com/promethium-ai/promethium-internal-ie-aws.git
cd promethium-internal-ie-aws
```

### 2.2 Configure `backend.tf`

```bash
cat > backend.tf << EOF
terraform {
  backend "s3" {
    bucket  = "pm61-iac-terraform-state"
    key     = "prod/${COMPANY_NAME}/terraform.tfstate"
    region  = "us-east-1"
  }
}
EOF
```

### 2.3 Create `terraform.tfvars`

> Before/After running, you must also manually replace `<image_tag>` in `terraform.tfvars` with the Promethium release version provided by Promethium.

```bash
cat > terraform.tfvars << EOF
# ── Core ──────────────────────────────────────────────────────────────────────
env          = "prod"
company_name = "${COMPANY_NAME}"
aws_region   = "${AWS_REGION}"

# ── Terraform identity ────────────────────────────────────────────────────────
terraform_assume_role_arn = "${TERRAFORM_ASSUME_ROLE_ARN}"

# ── VPC (customer-provided) ───────────────────────────────────────────────────
vpc_enabled = false

vpc_info = {
  vpc_id         = "${VPC_ID}"
  # Private subnets only — do NOT include public subnets here
  subnet_ids     = ["${SUBNET1_ID}", "${SUBNET2_ID}", "${SUBNET3_ID}"]
  vpc_cidr_block = "${VPC_CIDR}"
}

# ── IAM ───────────────────────────────────────────────────────────────────────
# All IAM roles pre-created by customer via operational_roles.yaml CFT
iam_role_create      = false
aws_iam_oidc_enabled = false

cluster_role_arn                = "${EKS_CLUSTER_ROLE_ARN}"
worker_role_arn                 = "${EKS_WORKER_ROLE_ARN}"
aws_ebs_driver_role_arn         = "${EBS_CSI_ROLE_ARN}"
aws_efs_driver_role_arn         = "${EFS_CSI_ROLE_ARN}"
aws_lb_controller_role_arn      = "${LB_CONTROLLER_ROLE_ARN}"
aws_eks_autoscaler_role_arn     = "${AUTOSCALER_ROLE_ARN}"
pg_backup_cronjob_oidc_role_arn = "${PG_BACKUP_ROLE_ARN}"
trino_oidc_role_arn             = "${TRINO_ROLE_ARN}"

# ── EKS ───────────────────────────────────────────────────────────────────────
custom_cluster_name = true
eks_cluster_name    = "promethium-datafabric-prod-${COMPANY_NAME}-eks-cluster"
eks_cluster_type    = "private"
jumpbox_enabled     = false
loadbalancer_type   = "internal"

jumpbox_sg_id                 = "${JUMPBOX_SG_ID}"
jumpbox_instance_profile_name = "${INSTANCE_PROFILE_NAME}"

# ── Promethium application ────────────────────────────────────────────────────
promethium_image_tag = "<image_tag>"   # e.g. 24.2.2

# ── Tagging ───────────────────────────────────────────────────────────────────
default_tags = {
  Environment = "prod"
  Product     = "Promethium"
  Owner       = "support@promethium.ai"
  created-by  = "Terraform"
  Project     = "Intelligentedge"
  persist     = "false"
}
EOF
```

> ⚠️ **`subnet_ids` must contain only private subnets.** EKS worker nodes are placed in these subnets. Public subnets auto-assign public IPs to instances and will cause the node group to fail.

## 3. Grant Cross-Account Trust

> These commands must be run from your local machine where your AWS is authenticated, not from the install VM / jumpbox

Promethium's two internal accounts need to trust the customer's deployment role so that:
- The S3 Terraform state backend can be accessed (account `734236616923`)
- The DynamoDB tenant lookup can run (account `308611924187`)

Add `PromethiumDeploymentRole-${COMPANY_NAME}` to the trust policy of `promethium-terraform-saas-assume-role` in **both** accounts:

> Replace `<734236616923-profile>` and `<308611924187-profile>` with your local AWS CLI profile names for each account.

```bash
# Account 734236616923 (S3 state backend)
aws iam update-assume-role-policy --role-name promethium-terraform-saas-assume-role --policy-document "$(aws iam get-role --role-name promethium-terraform-saas-assume-role --query 'Role.AssumeRolePolicyDocument' --output json | jq '.Statement += [{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"${CUSTOMER_ACCOUNT_ID}"':role/PromethiumDeploymentRole-'"${COMPANY_NAME}"'"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"iac-terraform"}}}]')" --profile <734236616923-profile>

# Account 308611924187 (DynamoDB tenant lookup)
aws iam update-assume-role-policy --role-name promethium-terraform-saas-assume-role --policy-document "$(aws iam get-role --role-name promethium-terraform-saas-assume-role --query 'Role.AssumeRolePolicyDocument' --output json | jq '.Statement += [{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'"${CUSTOMER_ACCOUNT_ID}"':role/PromethiumDeploymentRole-'"${COMPANY_NAME}"'"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"iac-terraform"}}}]')" --profile <308611924187-profile>
```
---

## 4. Verification (optional)

#### 4.1 Verifier Permissions (required before running verifier scripts)

> This command must be run from your local machine where your AWS is authenticated, not from the install VM / jumpbox

Run the following if the customer has not run verification or something went wrong with their verification.

Before running the Promethium pre-install verifier scripts on then install VM/jumpbox, deploy [`CFT/verifier_policy.yaml`](CFT/verifier_policy.yaml) to add the necessary read-only permissions to the install role:

```bash
aws cloudformation create-stack --stack-name promethium-verifier-policy --template-body file://AWS/CFT/verifier_policy.yaml --parameters ParameterKey=PromethiumInstallRole,ParameterValue=PromethiumDeploymentRole-${COMPANY_NAME} --capabilities CAPABILITY_NAMED_IAM --region ${AWS_REGION}
```

> This policy grants read-only access to CloudFormation, IAM, and EKS — used only by the verifier scripts. It can be removed after the install is complete.

#### 4.2 Verifier Steps (Promethium Associate)

> The following command must be run inside the install VM / jumpbox, in the `/root` environment.

```bash
curl -O https://raw.githubusercontent.com/promethium-ai/promethium-install-public/main/AWS/utilities/verify_cross_account_trust.sh
bash verify_cross_account_trust.sh PromethiumDeploymentRole-${COMPANY_NAME} ${AWS_REGION}
```

---

## 5. Deployment

### Phase 1 — AWS Infrastructure

Creates the EKS cluster (using the customer-provided cluster and worker roles), OIDC provider, all 6 IRSA roles, EKS node groups, S3 buckets, KMS keys, EFS, and Glue database.

All Promethium clusters are private (`eks_cluster_type = "private"`). Because the EKS API endpoint is VPC-internal, the jumpbox security group must be explicitly authorized to reach it on port 443 **after** the cluster is created but **before** Terraform attempts to configure it. Phase 1 is therefore split into three steps.

#### Phase 1a — Create EKS cluster

```bash
terraform init
terraform apply -target=module.aws.module.eks.aws_eks_cluster.ekscluster
```

> Expected duration: 10–15 minutes.

#### Phase 1b — Authorize jumpbox to cluster API

```bash
CLUSTER_SG=$(aws eks describe-cluster --name promethium-datafabric-prod-${COMPANY_NAME}-eks-cluster --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' --output text --region ${AWS_REGION})
aws ec2 authorize-security-group-ingress --group-id $CLUSTER_SG --protocol tcp --port 443 --source-group ${JUMPBOX_SG_ID} --region ${AWS_REGION}
```

Verify kubectl connectivity from the jumpbox:

```bash
aws eks update-kubeconfig --region ${AWS_REGION} --name promethium-datafabric-prod-${COMPANY_NAME}-eks-cluster
kubectl get nodes
```

#### Phase 1c — Complete AWS infrastructure

```bash
terraform apply -target=module.aws
```

> Expected duration: 10–15 minutes (node groups, OIDC, S3, KMS, EFS).

Before typing `yes`, verify the plan includes:
- `aws_eks_cluster` referencing your `cluster_role_arn` — **not** creating a new cluster role
- `aws_iam_openid_connect_provider` — Terraform creates the OIDC provider
- `aws_iam_role` entries for the 6 OIDC/IRSA roles (EBS CSI, EFS CSI, LB controller, autoscaler, PG backup, Trino)
- `aws_eks_node_group` referencing your `worker_role_arn`
- `aws_efs_file_system`, `aws_s3_bucket`, `aws_kms_key`

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

## 6. Post-Install Steps

### 6.1 Check pods

```bash
kubectl get pods -n intelligentedge
```

All pods should be `Running` or `Completed`. The ingress `ADDRESS` is the internal ALB DNS name — accessible via VPN.


### 6.2 Update support password

Post-deployment, the Promethium associate must reset the default support user password and update dependent services. Please follow the [post-install credentials runbook](https://pm61data.atlassian.net/wiki/x/AgBfmw).

---

## 7. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `subnets count less than minimal required count: 1 < 2` in LB controller logs | Only 1 public subnet tagged `kubernetes.io/role/elb` | Add a second public subnet in a different AZ and tag it; restart `aws-load-balancer-controller` deployment |
| `unable to resolve at least one subnet (0 match VPC and tags: [kubernetes.io/role/elb])` | Public subnets missing `kubernetes.io/role/elb=1` tag | Tag both public subnets per Section 4 |
| EKS node group fails: `instances do not support public IP assignment` | Public subnet included in `subnet_ids` | Remove public subnets from `vpc_info.subnet_ids`; private subnets only |
| `aws_eks_cluster` fails: `InvalidParameterException` on cluster role | `cluster_role_arn` missing `sts:AssumeRole` trust for `eks.amazonaws.com` | Verify trust policy on the EKS cluster role from Stack 2 |
| `AccessDenied` creating OIDC provider | Install role missing `iam:CreateOpenIDConnectProvider` | Redeploy `install_role.yaml` — latest version includes OIDC provider management |
| Node group fails to launch | Worker role ARN wrong or worker role missing required policies | Confirm `EKSWorkerRoleArn` from Stack 2 is correct; verify `AmazonEKSWorkerNodePolicy`, `AmazonEKS_CNI_Policy`, and `AmazonEC2ContainerRegistryReadOnly` are attached |
| IRSA trust policy mismatch | OIDC URL not matching cluster | Run `terraform output` to compare OIDC URLs; re-apply if needed |
| ALB not provisioning | LB controller IRSA role misconfigured | Check `aws-load-balancer-controller` pod logs in `kube-system`; verify service account annotation |
| Ingress hostname empty after Phase 3 | ALB not yet provisioned | Wait 3–5 min and re-run `terraform apply` |
| Pods stuck `Pending` | Node group not scaled, or subnets missing EKS cluster tag | Check ASG in EC2 console; verify `kubernetes.io/cluster/<cluster_name>=owned` tag on all subnets |

---

## 8. Teardown

```bash
terraform destroy -target=module.promethium.module.postgres -var="ghcr_token=$GHCR_TOKEN"

terraform destroy -var="ghcr_token=$GHCR_TOKEN"
```

---