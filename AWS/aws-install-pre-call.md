
# Promethium Intelligent Edge AWS Pre-call Installation (Promethium Associate)

This page documents instructions for the Promethium associate to complete pre-call instructions, before the main AWS install ([aws-install.md](aws-install.md)), but after the customer completes prerequisites ([`README.md`](README.md)).

The instructions here create and configure a new branch for the customer from the Promethium associate's local machine.

## 1. Create customer branch

> ⚠️ **Run these commands on your local machine**, not the jumpbox

Copy `promethium-outputs-<company_name>.sh` (generated in [README.md Section 6](README.md#6-customer-information-required-by-promethium)) to your local machine, then source it at the start of each terminal session:

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

## 2. Code changes

### 2.1 Configure `backend.tf`

```bash
cat > backend.tf << EOF
terraform {
  backend "s3" {
    bucket  = "pm61-iac-terraform-state"
    key     = "prod/${COMPANY_NAME}/terraform.tfstate"
    region  = "us-east-1"
    use_lockfile = "false"
    assume_role = {
      role_arn = "arn:aws:iam::734236616923:role/promethium-terraform-saas-assume-role"
    }
  }
}
EOF
```

### 2.2 Create `terraform.tfvars`

> After running the following command, replace `<image_tag>` in `terraform.tfvars` with the Promethium release version provided by Promethium.

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
promethium_image_tag = "<image_tag>" # <-- REPLACE HERE e.g. 24.2.2

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

---

## 3. Push changes


```bash
git add backend.tf terraform.tfvars
git commit -m "Create new tenant: ${COMPANY_NAME}"
git push origin ${COMPANY_NAME}
```

---

You may now proceed to the main AWS install instructions