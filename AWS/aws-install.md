# Promethium Intelligent Edge AWS Installation (Promethium Associate)

This page documents instructions for the Promethium associate on completing the AWS install, once the customer prerequisites ([`README.md`](README.md)) are completed.

The customer provides an existing VPC (with subnets and routing), an EC2 install VM/jumpbox, the Terraform install role (`install_role.yaml`), and all operational IAM roles (`operational_roles.yaml`). Promethium's Terraform creates the EKS cluster, configures OIDC trust policies, deploys EKS add-ons, and installs the full Promethium application stack.

Promethium is deployed with an **internal load balancer** — accessible via VPN only.

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

# Requirements

### VPC & Subnet Requirements

Your VPC must be at least a `/22` CIDR (e.g., `10.0.0.0/22`). Promethium uses an **internal load balancer** — only private subnets are required. No public subnets are needed.

| Configuration | Private Subnets | AZs | Routing | Required Tags |
|---|---|---|---|---|
| **Required (minimum)** | 3 | 3 different AZs | NAT Gateway | `kubernetes.io/role/internal-elb=1` |
| **Recommended** | 4 | 2+ different AZs | NAT Gateway | `kubernetes.io/role/internal-elb=1` |

> ⚠️ **Minimum 3 private subnets across 3 availability zones are required.** The internal ALB and EKS node groups both use these subnets. More subnets across more AZs improve availability and provide additional IP space for nodes.

> ⚠️ **EKS worker nodes must be placed in private subnets only.** Public subnets auto-assign public IPs to instances, which causes EKS node group creation to fail.

> ℹ️ **Public subnets must not have kubernetes tags.** If your VPC has public subnets, ensure they have no `kubernetes.io/*` tags to avoid unintended ALB subnet discovery.

### Example layout for a `10.0.0.0/22` VPC (recommended — 3 private subnets + 1 public)

| Subnet | CIDR | AZ | Type | Purpose |
|---|---|---|---|---|
| subnet-1 | `10.0.0.0/24` | `us-east-1a` | Private | EKS worker nodes + internal ALB |
| subnet-2 | `10.0.1.0/24` | `us-east-1b` | Private | EKS worker nodes + internal ALB |
| subnet-3 | `10.0.2.0/24` | `us-east-1c` | Private | EKS worker nodes + internal ALB |
| subnet-4 | `10.0.3.0/24` | `us-east-1a` | Public | NAT Gateway |

### Required subnet tags

All 3 private subnets must be tagged with the EKS cluster name **before** running Terraform:

| Subnet type | Tag Key | Tag Value |
|---|---|---|
| Private | `kubernetes.io/role/internal-elb` | `1` |
| Private | `kubernetes.io/cluster/<cluster_name>` | `owned` |

Where `<cluster_name>` = `promethium-datafabric-prod-<company_name>-eks-cluster` if the customer did not already have a cluster with a custom name.

---

# Installation

## 1. Grant Cross-Account Trust

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

## 2. Tool Installation

TODO: how to login without interactive username/password

SSH or SSM into the install VM, then run:

```bash
sudo su
cd
curl -O https://raw.githubusercontent.com/promethium-ai/promethium-install-public/main/AWS/utilities/install_tools.sh
bash install_tools.sh
```

Or use the install script provided in this repo:

TODO: need to git clone the repo before doing this

```bash
cd AWS && ./utilities/install_tools.sh
```

---

## 3. Configure Terraform

### 3.1 Clone the deployment repo

From the Install VM/jumpbox, do:

TODO: how to login without interactive username/password
TODO: if we are going to do everything in VM, then the internal-ie-aws branch name needs to be created there also

```bash
# git clone -b <company_name> --single-branch https://github.com/promethium-ai/promethium-internal-ie-aws.git
```

```bash
git clone https://github.com/promethium-ai/promethium-internal-ie-aws.git
cd promethium-internal-ie-aws
git checkout -b <release_branch>   # provided by Promethium (company name)
```

TODO: there are no regular release tags for promethium-internal-ie-aws, I am doing this from main branch.

### 3.2 Configure `backend.tf`

> Remember, `<env>` is `prod`

```hcl
terraform {
  backend "s3" {
    bucket  = "pm61-iac-terraform-state"
    key     = "<env>/<company_name>/terraform.tfstate"
    region  = "us-east-1"
  }
}
```

### 3.3 Create `terraform.tfvars`

Replace all `<placeholder>` values before proceeding:

```hcl
# ── Core ──────────────────────────────────────────────────────────────────────
env          = "prod"            # dev | qa | preview | prod
company_name = "<company_name>"   # max 15 chars, lowercase, no spaces
aws_region   = "<aws_region>"     # e.g. us-east-1

# ── Terraform identity ────────────────────────────────────────────────────────
terraform_assume_role_arn = "<RoleArn from Stack 1>"

# ── VPC (customer-provided) ───────────────────────────────────────────────────
vpc_enabled = false

vpc_info = {
  vpc_id         = "<vpc_id>"
  # Private subnets only — do NOT include public subnets here
  subnet_ids     = ["<private_subnet_1>", "<private_subnet_2>"]
  vpc_cidr_block = "<vpc_cidr>"   # e.g. 10.0.0.0/22
}

# ── IAM ───────────────────────────────────────────────────────────────────────
# All IAM roles pre-created by customer via operational_roles.yaml CFT
iam_role_create      = false
aws_iam_oidc_enabled = false

cluster_role_arn                = "<EKSClusterRoleArn from operational_roles stack>"
worker_role_arn                 = "<EKSWorkerNodeRoleArn from operational_roles stack>"
aws_ebs_driver_role_arn         = "<EBSCSIDriverRoleArn from operational_roles stack>"
aws_efs_driver_role_arn         = "<EFSCSIDriverRoleArn from operational_roles stack>"
aws_lb_controller_role_arn      = "<LoadBalancerControllerRoleArn from operational_roles stack>"
aws_eks_autoscaler_role_arn     = "<ClusterAutoscalerRoleArn from operational_roles stack>"
pg_backup_cronjob_oidc_role_arn = "<PGBackupServiceRoleArn from operational_roles stack>"
trino_oidc_role_arn             = "<GlueTrinoServiceRoleArn from operational_roles stack>"

# ── EKS ───────────────────────────────────────────────────────────────────────
custom_cluster_name = true
eks_cluster_name    = "promethium-datafabric-prod-<company_name>-eks-cluster"
eks_cluster_type    = "private"
jumpbox_enabled     = false
loadbalancer_type   = "internal"

jumpbox_sg_id                 = "<JumpboxSecurityGroupId>"
jumpbox_instance_profile_name = "<InstanceProfileName from install_role stack>"

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
```

TODO add isntructions for dev2 IAC

> ⚠️ **`subnet_ids` must contain only private subnets.** EKS worker nodes are placed in these subnets. Public subnets auto-assign public IPs to instances and will cause the node group to fail.


TODO: Why are there no instructions to change main.tf IAC ref from dev2 to release tag e.g. `24.2.2`?
---

## 4. Deployment

TODO: describe all in jumpbox

### Phase 1 — AWS Infrastructure

Creates the EKS cluster (using the customer-provided cluster and worker roles), OIDC provider, all 6 IRSA roles, EKS node groups, S3 buckets, KMS keys, EFS, and Glue database.

All Promethium clusters are private (`eks_cluster_type = "private"`). Because the EKS API endpoint is VPC-internal, the jumpbox security group must be explicitly authorized to reach it on port 443 **after** the cluster is created but **before** Terraform attempts to configure it. Phase 1 is therefore split into three steps.

TODO: describe this command

```
sudo su
```


### Github Token
```bash
# GitHub tokens
export GH_TOKEN="<github_pat>"
export GHCR_TOKEN="<ghcr_token>"
```

### Login to Helm OCI registry

```bash
export HELM_EXPERIMENTAL_OCI=1
helm registry login ghcr.io -u promethium-ai --password-stdin <<< "$GHCR_TOKEN"
```

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

## 5. Post-Install Verification

### Get cluster credentials

```bash
aws eks update-kubeconfig \
  --name promethium-datafabric-prod-<company_name>-eks-cluster \
  --region <aws_region>
```

### Check pods

```bash
kubectl get pods -n intelligentedge
kubectl get pods -n cluster-management
kubectl get pods -n kube-system   # verify EBS/EFS CSI, LB controller, autoscaler
```

All pods should be `Running` or `Completed`. The ingress `ADDRESS` is the internal ALB DNS name — accessible via VPN.

> **Important:** Post-deployment, the Promethium associate must reset the default support user password and update dependent services. See the [post-install credentials runbook](https://pm61data.atlassian.net/wiki/x/AgBfmw).

### Verify OIDC role bindings

Confirm that the IRSA roles Terraform created are correctly bound to Kubernetes service accounts:

```bash
kubectl get sa ebs-csi-controller-sa -n kube-system -o yaml | grep role-arn
kubectl get sa efs-csi-controller-sa -n kube-system -o yaml | grep role-arn
kubectl get sa aws-load-balancer-controller -n kube-system -o yaml | grep role-arn
kubectl get sa trino-sa -n intelligentedge -o yaml | grep role-arn
kubectl get sa s3-backup-sa -n intelligentedge -o yaml | grep role-arn
```

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

## 6. Troubleshooting

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

## 7. Teardown

```bash
terraform destroy \
  -target=module.promethium.module.postgres \
  -var="ghcr_token=$GHCR_TOKEN"

terraform destroy -var="ghcr_token=$GHCR_TOKEN"
```

---