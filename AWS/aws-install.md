# Promethium Intelligent Edge AWS Installation (Customer)

This page documents the AWS install steps run by the **customer**, on-call with the Promethium associate. It follows after the customer completes prerequisites ([`README.md`](README.md)) and the Promethium associate completes pre-call setup ([aws-install-pre-call.md](aws-install-pre-call.md)).

The customer provides an existing VPC (with subnets and routing), an EC2 install VM/jumpbox, the Terraform install role (`install_role.yaml`), and all operational IAM roles (`operational_roles.yaml`). Promethium's Terraform creates the EKS cluster, configures OIDC trust policies, deploys EKS add-ons, and installs the full Promethium application stack.

> Promethium is deployed with an **internal load balancer** — accessible via VPN only.

- [Promethium Intelligent Edge AWS Installation (Customer)](#promethium-intelligent-edge-aws-installation-customer)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Setup: Connect to the Install VM and configure the environment](#1-setup-connect-to-the-install-vm-and-configure-the-environment)
    - [1.1 Tool Installation](#11-tool-installation)
    - [1.2 Github Token](#12-github-token)
    - [1.3 Login to Helm OCI registry](#13-login-to-helm-oci-registry)
  - [2. Configure Terraform Branch](#2-configure-terraform-branch)
    - [2.1 Clone the deployment repo](#21-clone-the-deployment-repo)
    - [2.2 Source all customer outputs](#22-source-all-customer-outputs)
  - [3. Verify Cross-Account Trust (optional)](#3-verify-cross-account-trust-optional)
    - [3.1 Verifier Permissions (required before running verifier scripts)](#31-verifier-permissions-required-before-running-verifier-scripts)
    - [3.2 Verifier Steps](#32-verifier-steps)
  - [4. Deployment](#4-deployment)
    - [Phase 1 — AWS Infrastructure](#phase-1--aws-infrastructure)
      - [Phase 1a — Create EKS cluster](#phase-1a--create-eks-cluster)
      - [Phase 1b — Authorize jumpbox to cluster API](#phase-1b--authorize-jumpbox-to-cluster-api)
      - [Phase 1c — Complete AWS infrastructure](#phase-1c--complete-aws-infrastructure)
    - [Phase 2 — Not required for AWS](#phase-2--not-required-for-aws)
    - [Phase 3 — Promethium Services](#phase-3--promethium-services)
  - [5. Post-Install Steps](#5-post-install-steps)
    - [5.1 Check pods](#51-check-pods)
    - [5.2 Update support password](#52-update-support-password)
  - [Troubleshooting](#troubleshooting)
  - [Teardown](#teardown)


---

# Prerequisites

| Requirement | Detail |
|---|---|
| AWS Account | Account ID where the Intelligent Edge will be deployed |
| Region | AWS region for deployment (e.g., `us-east-1`) |
| VPC | At least `/22` CIDR block — see [README.md Section 2](README.md#2-vpc-subnet) for subnet layout |
| `company_name` | Agreed with your Promethium representative — max 15 characters, lowercase, no spaces |
| Image tag | Promethium release version (e.g., `24.2.2`) — provided by Promethium |
| Install VM | Amazon Linux 2023 or Ubuntu 22.04/24.04, with outbound HTTPS — see [Section 1.1](#11-tool-installation) |
| Outbound Internet | EKS nodes must reach the Promethium image registry and control plane over HTTPS (port 443) |

---

# Installation

> ⚠️ Unless explicitly stated, all of the commands in this guide shall run from the **Install VM / Jumpbox**. ⚠️

## 1. Setup: Connect to the Install VM and configure the environment 

Connect to the Install VM via SSM: **AWS Console → EC2 → Instances → select the jumpbox → Connect → Session Manager**.

First run as root and get into the default directory `/root`:
```bash
sudo su
cd
```

> The rest of the jumpbox commands must be run in this `/root` environment.

Next, replace `<company_name>` below and export the `COMPANY_NAME`:
```bash
export COMPANY_NAME="<company_name>"
```

### 1.1 Tool Installation

Install required tools (Terraform, kubectl, Helm, git, jq) on the install VM:

```bash
curl -fsSL -O https://raw.githubusercontent.com/promethium-ai/promethium-install-public/main/AWS/utilities/install_tools.sh
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
helm registry login ghcr.io -u promethium-ai --password-stdin <<< "$GHCR_TOKEN"
```

## 2. Configure Terraform Branch

### 2.1 Clone the deployment repo

From the Install VM / Jumpbox, clone the tenant's branch from the deployment repository:

```bash
git clone -b ${COMPANY_NAME} --single-branch https://github.com/promethium-ai/promethium-internal-ie-aws.git
cd promethium-internal-ie-aws
```

### 2.2 Source all customer outputs

Source the `promethium-outputs-${COMPANY_NAME}.sh` file on the branch (originally generated from [README.md Section 6](README.md#6-customer-information-required-by-promethium)) inside the Jumpbox at the start of **each** session:

```bash
source promethium-outputs-${COMPANY_NAME}.sh
```

This allows us to retrieve customer output variables like `$AWS_REGION` and `$JUMPBOX_SG_ID` needed in following commands.

---

## 3. Verify Cross-Account Trust (optional)

### 3.1 Verifier Permissions (required before running verifier scripts)

> ⚠️ This command must be run from your local machine where your AWS CLI is authenticated, **NOT** from the Install VM / Jumpbox ⚠️

Before running the Promethium pre-install verifier scripts on the Install VM / Jumpbox, deploy [`CFT/verifier_policy.yaml`](CFT/verifier_policy.yaml) to add the necessary read-only permissions to the install role:

```bash
aws cloudformation create-stack --stack-name promethium-verifier-policy-${COMPANY_NAME} --template-body file://AWS/CFT/verifier_policy.yaml --parameters ParameterKey=PromethiumInstallRole,ParameterValue=PromethiumDeploymentRole-${COMPANY_NAME} --capabilities CAPABILITY_NAMED_IAM --region ${AWS_REGION}
```

> This policy grants read-only access to CloudFormation, IAM, and EKS — used only by the verifier scripts. It can be removed after the install is complete.

### 3.2 Verifier Steps

> The following command must be run inside the Install VM / Jumpbox in the `/root` environment.

```bash
curl -fsSL -O https://raw.githubusercontent.com/promethium-ai/promethium-install-public/main/AWS/utilities/verify_cross_account_trust.sh
bash verify_cross_account_trust.sh PromethiumDeploymentRole-${COMPANY_NAME} ${AWS_REGION}
```

---

## 4. Deployment

### Phase 1 — AWS Infrastructure

Creates the EKS cluster (using the customer-provided cluster and worker roles), OIDC provider, all 6 IRSA roles, EKS node groups, S3 buckets, KMS keys, EFS, and Glue database.

All Promethium clusters are private (`eks_cluster_type = "private"`). Because the EKS API endpoint is VPC-internal, the jumpbox security group must be explicitly authorized to reach it on port 443 **after** the cluster is created but **before** Terraform attempts to configure it. Phase 1 is therefore split into three steps.

#### Phase 1a — Create EKS cluster

```bash
terraform init
terraform apply -target=module.aws.module.eks.aws_eks_cluster.ekscluster -var="ghcr_token=$GHCR_TOKEN"
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
terraform apply -target=module.aws -var="ghcr_token=$GHCR_TOKEN"
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
terraform apply -var="ghcr_token=$GHCR_TOKEN"
```

> Expected duration: 10–20 minutes.

> ℹ️ If you see an ingress hostname timing error on first run (the ALB takes a few minutes to provision after the LB controller starts), wait 3–5 minutes and re-run `terraform apply`.

---

## 5. Post-Install Steps

### 5.1 Check pods

```bash
kubectl get pods -n intelligentedge
```

All pods should be `Running` or `Completed`. The ingress `ADDRESS` is the internal ALB DNS name — accessible via VPN.


### 5.2 Update support password

Post-deployment, the Promethium associate must reset the default support user password and update dependent services. Please follow the [post-install credentials runbook](https://pm61data.atlassian.net/wiki/x/AgBfmw).


The AWS install is now complete.

---

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `subnets count less than minimal required count: 1 < 2` in LB controller logs | Only 1 private subnet tagged `kubernetes.io/role/internal-elb` | Add a second private subnet in a different AZ and tag it; restart `aws-load-balancer-controller` deployment |
| `unable to resolve at least one subnet (0 match VPC and tags: [kubernetes.io/role/internal-elb])` | Private subnets missing `kubernetes.io/role/internal-elb=1` tag | Tag all private subnets per README.md Section 2 |
| EKS node group fails: `instances do not support public IP assignment` | Public subnet included in `subnet_ids` | Remove public subnets from `vpc_info.subnet_ids`; private subnets only |
| `aws_eks_cluster` fails: `InvalidParameterException` on cluster role | `cluster_role_arn` missing `sts:AssumeRole` trust for `eks.amazonaws.com` | Verify trust policy on the EKS cluster role from the `promethium-eks-base-roles-${COMPANY_NAME}` stack |
| `AccessDenied` creating OIDC provider | Install role missing `iam:CreateOpenIDConnectProvider` | Redeploy `install_role.yaml` — latest version includes OIDC provider management |
| Node group fails to launch | Worker role ARN wrong or worker role missing required policies | Confirm `EKSWorkerRoleArn` from the `promethium-eks-base-roles-${COMPANY_NAME}` stack is correct; verify `AmazonEKSWorkerNodePolicy`, `AmazonEKS_CNI_Policy`, and `AmazonEC2ContainerRegistryReadOnly` are attached |
| IRSA trust policy mismatch | OIDC URL not matching cluster | Run `terraform output` to compare OIDC URLs; re-apply if needed |
| ALB not provisioning | LB controller IRSA role misconfigured | Check `aws-load-balancer-controller` pod logs in `kube-system`; verify service account annotation |
| Ingress hostname empty after Phase 3 | ALB not yet provisioned | Wait 3–5 min and re-run `terraform apply` |
| Pods stuck `Pending` | Node group not scaled, or subnets missing EKS cluster tag | Check ASG in EC2 console; verify `kubernetes.io/cluster/<cluster_name>=owned` tag on all subnets |

---

## Teardown

The following command will delete the resources provisioned by the earlier `terraform apply` steps.

```bash
terraform destroy -target=module.promethium.module.postgres -var="ghcr_token=$GHCR_TOKEN"

terraform destroy -var="ghcr_token=$GHCR_TOKEN"
```

---