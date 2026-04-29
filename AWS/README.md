# Promethium Intelligent Edge Installation (AWS)

![Promethium Intelligent Edge (AWS)](../images/AWS_IE.png)

The following steps describe how to deploy a secure Promethium Intelligent Edge on AWS. It will deploy an Amazon Elastic Kubernetes Service (EKS) cluster within which the Promethium application services are deployed, fronted by an internal AWS Application Load Balancer (ALB).

---

## 1. How it works

The customer provides the AWS infrastructure — VPC, subnets, install role, and operational IAM roles. Promethium's Terraform deploys the EKS cluster, configures OIDC trust policies, and installs the full Promethium application stack.

Promethium is always deployed with an **internal load balancer** — accessible via VPN only.

For detailed step-by-step installation instructions, your Promethium associate will follow:
- [AWS Install Guide](README-aws-install.md)

---

## 2. Environment Prerequisites

| Item | Description |
|------|-------------|
| AWS Account | The AWS account where the Promethium Intelligent Edge will be deployed |
| Region | AWS region for deployment (e.g., `eu-central-1`) |
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

> **Note:** Public subnets must have no `kubernetes.io/*` tags to avoid unintended ALB subnet discovery.

### Networking Requirements

#### Install VM — Outbound Access

| Endpoint | Purpose |
|----------|---------|
| `github.com`, `*.githubusercontent.com` | Clone Terraform wrapper repo |
| `ghcr.io` | Pull Helm charts |
| `releases.hashicorp.com` | Download Terraform binary |
| `registry.terraform.io` | Terraform provider and module downloads |
| `dl.k8s.io` | Download kubectl |
| `*.amazonaws.com` | AWS API endpoints (EKS, EC2, IAM, S3, ACM, Route 53) |
| `sts.amazonaws.com` | AWS STS assume-role |

#### EKS Nodes — Outbound Access

| Endpoint | Port | Purpose |
|----------|------|---------|
| `*.eks.amazonaws.com` | 443 | EKS API server communication |
| `*.ecr.*.amazonaws.com` | 443 | Promethium container images (AWS ECR) |
| `sts.amazonaws.com` | 443 | AWS STS for ECR token refresh |
| `ghcr.io` | 443 | Promethium Helm charts |
| `s3.amazonaws.com`, `*.s3.amazonaws.com` | 443 | S3 access for EKS and application data |

---

## 3. IAM Roles — CloudFormation Templates

Deploy these two CFTs in the customer account before starting the Promethium install.

### Step 1 — Install Role

Deploy [`CFT/install_role.yaml`](CFT/install_role.yaml). This creates:

| Role | Used By | Purpose |
|------|---------|---------|
| `PromethiumDeploymentRole` | Install VM (jumpbox) | Terraform deployment role — attached to the install VM as an EC2 instance profile. Used to create and configure all Promethium infrastructure |

> The role is created as an **EC2 Instance Profile** and attached directly to the install VM. No access keys are needed.

### Step 1b — Verifier Permissions (required before running verifier scripts)

Before running the Promethium pre-install verifier scripts from the jumpbox, deploy [`CFT/verifier_policy.yaml`](CFT/verifier_policy.yaml) to add the necessary read-only permissions to the install role:

```bash
aws cloudformation create-stack \
  --stack-name promethium-verifier-policy \
  --template-body file://AWS/CFT/verifier_policy.yaml \
  --parameters \
    ParameterKey=PromethiumInstallRole,ParameterValue=PromethiumDeploymentRole \
  --capabilities CAPABILITY_NAMED_IAM \
  --region <aws_region>
```

> This policy grants read-only access to CloudFormation, IAM, and EKS — used only by the verifier scripts. It can be removed after the install is complete.

---

### Step 2 — Operational Roles

Deploy [`CFT/operational_roles.yaml`](CFT/operational_roles.yaml) with:

- `ClusterName` = `promethium-datafabric-prod-<company_name>-eks-cluster`
- `OIDCProviderUrl` = leave as default dummy value (updated automatically after Phase 1a)

This creates all 8 operational roles:

| Role | Used By | Purpose |
|------|---------|---------|
| `promethium-prod-eks-cluster-role` | EKS control plane | Gives the EKS control plane permissions to run the cluster, manage AWS infrastructure, and manage pod-level networking |
| `promethium-prod-eks-worker-role` | EKS worker nodes | Allows nodes to pull container images from ECR, manage EFS volumes via CSI driver, and handle network management within EKS |
| `promethium-prod-ebs-csi-driver-role` | EBS CSI driver | Allows the EBS CSI driver to provision, attach, delete, and snapshot encrypted EBS volumes using KMS keys |
| `promethium-prod-efs-csi-driver-role` | EFS CSI driver | Allows the EFS CSI driver to provision and manage EFS file systems and access points |
| `promethium-prod-lb-controller-role` | Load Balancer Controller | Allows the LB Controller to provision and manage ALBs/NLBs on behalf of Kubernetes ingress and service resources |
| `promethium-prod-cluster-autoscaler-role` | Cluster Autoscaler | Allows the autoscaler to add or remove worker nodes in Auto Scaling Groups based on cluster demand |
| `promethium-prod-pg-backup-role` | Postgres backup | Allows postgres backups to be written to S3 and container images to be pulled from ECR |
| `promethium-prod-glue-trino-role` | Trino / Glue crawlers | Allows Trino to query and manage data in Glue Data Catalog and S3, handle KMS-encrypted data, and interact with Glue jobs |

---

## 4. Customer Information Required

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

## 5. Verification

After deployment your Promethium associate will confirm:

```bash
aws eks update-kubeconfig \
  --name promethium-datafabric-<env>-<company_name>-eks-cluster \
  --region <aws_region>

kubectl get pods -n intelligentedge
kubectl get pods -n cluster-management
kubectl get ingress -n intelligentedge
```

All pods should be `Running` or `Completed`. The ingress `ADDRESS` is the internal ALB DNS name — accessible via VPN.

> **Important:** Post-deployment, the Promethium associate must reset the default support user password and update dependent services. See the [post-install credentials runbook](https://pm61data.atlassian.net/wiki/x/AgBfmw).

---

## 6. Teardown

```bash
terraform destroy \
  -target=module.promethium.module.postgres \
  -var="ghcr_token=$GHCR_TOKEN"

terraform destroy -var="ghcr_token=$GHCR_TOKEN"
```

---

## 7. Additional Resources

| Resource | Description |
|----------|-------------|
| [AWS Install Guide](README-aws-install.md) | Step-by-step installation guide for Promethium associates |
| [Install Role CFT](CFT/install_role.yaml) | Creates the Terraform deployment role and instance profile |
| [Verifier Policy CFT](CFT/verifier_policy.yaml) | Adds read-only permissions for running pre-install verifier scripts from the jumpbox |
| [Operational Roles CFT](CFT/operational_roles.yaml) | Creates EKS cluster role, worker role, and all 6 OIDC/IRSA roles |
| [S3 Private Crawler](CFT/s3-private-crawler/) | VPC gateway endpoint and Glue network connection for private S3 access |

> For customers needing private S3 access for Trino and Glue crawlers, see the `CFT/s3-private-crawler` folder, which includes the deployment guidance and CloudFormation template for the gateway endpoint and Glue NETWORK connection.
| [Utilities](utilities/) | Helper scripts for tool installation, role verification, and diagnostics |
