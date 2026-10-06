# Promethium IAM CloudFormation Templates

This directory contains the CloudFormation templates used to install
Promethium Intelligent Edge on AWS — IAM roles, networking, and the jumpbox.

## Overview

The **scripted Model A′ install** ([../scripts/README.md](../scripts/README.md))
deploys four of these templates via `AWS/scripts/prereqs.sh`, in order:

| Template | Creates |
|---|---|
| [`network.yaml`](network.yaml) | VPC, 3 private subnets + 1 public subnet, Internet Gateway + NAT Gateway, route tables (skipped for BYO VPC) |
| [`foundation.yaml`](foundation.yaml) | The Terraform deploy/install role (+ instance profile) and the Terraform state S3 bucket |
| [`operational_roles.yaml`](operational_roles.yaml) | The 9 EKS/OIDC operational roles (EBS/EFS CSI driver, LB controller, cluster autoscaler, EKS cluster + worker-node, PG backup, Glue/Trino, ArgoCD ECR refresher) + the Lambda-backed `TagResolver` custom resource |
| [`jumpbox.yaml`](jumpbox.yaml) | The EC2 install VM (self-installs git/Terraform/kubectl/Helm via `UserData` at boot) |

`prereqs.sh` deploys all four locally (`aws cloudformation deploy
--template-file`, no S3 bucket, no upload credentials) and idempotently, in
the order above. See [../scripts/README.md](../scripts/README.md) for exact
usage and why `foundation.yaml` and `operational_roles.yaml` are two
templates rather than one (CloudFormation's 51,200-byte inline-template size
limit — a single combined template ran to ~64.9 KB).

> **Legacy / manual-path templates.** [`install_role.yaml`](install_role.yaml)
> and [`verifier_policy.yaml`](verifier_policy.yaml) predate this split and
> remain here for the **manual (non-agent) install** path documented in
> [../README.md → Reference: manual (non-agent) install](../README.md#reference-manual-non-agent-install)
> — they are not used by the scripted flow.
> [`tfstate-bootstrap.yaml`](tfstate-bootstrap.yaml) is superseded entirely:
> its `TfStateBucket` resource was folded directly into `foundation.yaml`
> (same bucket name, `promethium-tfstate-${AWS::AccountId}`), and it is not
> deployed by either path.

---

## `network.yaml`

**Purpose:** Creates the VPC, subnets, and NAT Gateway for a greenfield
(Promethium-created) install. Skipped entirely when the customer brings
their own VPC (`prereqs.sh --vpc-id ... --subnet-ids ...` /
`deploy.sh --vpc-id ... --subnet-ids ...`).

**Creates:**
- VPC with configurable CIDR (minimum `/22`)
- 3 private subnets (EKS nodes + internal ALB) + 1 public subnet (NAT Gateway only)
- Internet Gateway, NAT Gateway, route tables and associations

**Parameters:** `Environment`, `CompanyName` (both required, no default — used
to compute the default EKS cluster name for subnet tagging), `VpcName`,
`VpcCidrBlock` (default `10.0.0.0/22`), `EksClusterName` (optional override).

**Outputs:** `VpcId`, `VpcCidrBlock`, `Subnet1Id`, `Subnet2Id`, `Subnet3Id`
(private), `Subnet4Id` (public).

## `foundation.yaml`

**Purpose:** Creates **only** the Terraform deploy/install role (+ instance
profile) and the Terraform state S3 bucket, for one customer AWS
account/company. Deploy once per customer AWS account/company, before
Terraform runs.

**Permissions included** — the deploy role can create and manage:
- EKS clusters and node groups; VPC networking (subnets, security groups, routing); EFS file systems; S3 buckets (Trino data, PostgreSQL backups, tfstate); KMS encryption keys; ACM certificates; EC2 instances and launch templates; AWS Glue databases and catalogs; Elastic Load Balancers
- Plus, beyond the legacy `install_role.yaml`: patching the operational
  roles' OIDC trust policies once the real cluster/OIDC provider exists
  (`iam-operational-role-trust-mgmt`), invoking the tenant-registration API
  (`registry-invoke`), reading/writing the gitops secret bundles used by
  agent enrollment (`gitops-secret-bundles`), and the tfstate bucket's own
  object/bucket operations (`tfstate-bucket`)

**Parameters:** `CompanyName`, `Environment` (both required), `PromethiumInstallRole` (optional name override).

**Outputs:** `DeployRoleArn`, `InstanceProfileArn`, `InstanceProfileName`, `TfStateBucket`.

## `operational_roles.yaml`

**Purpose:** Creates the 9 IAM roles required by EKS cluster operations and
Kubernetes service accounts, plus the Lambda-backed `TagResolver` custom
resource that tags them. Deploy after `foundation.yaml`; `OIDCProviderUrl` is
left at its dummy default here — Terraform creates the real cluster + OIDC
provider later, then patches these roles' trust policies to the real URL
(see `foundation.yaml`'s `iam-operational-role-trust-mgmt` policy).

**The 9 roles:**
- EKS cluster role, EKS worker-node role
- EBS CSI driver role, EFS CSI driver role
- Load Balancer Controller role
- Cluster Autoscaler role
- PG backup role
- Glue/Trino role (`trino-oidc-role`)
- ArgoCD ECR refresher role — mints short-lived ECR tokens so the cluster can
  pull the Promethium OCI umbrella chart/images (agent / Model A′ installs)

Default role names follow `promethium-<Environment>-<CompanyName>-<role>`
(e.g. `promethium-prod-acme-ebs-csi-driver-role`).

**Parameters:** `CompanyName`, `Environment` (both required), `CustomClusterName`, `OIDCProviderUrl` (dummy default until Terraform creates the real cluster), and a per-role name override for each of the 9 roles (all optional).

**Outputs:** `EKSClusterRoleArn`, `EKSWorkerNodeRoleArn`, `EBSCSIDriverRoleArn`, `EFSCSIDriverRoleArn`, `LoadBalancerControllerRoleArn`, `ClusterAutoscalerRoleArn`, `PGBackupServiceRoleArn`, `GlueTrinoServiceRoleArn`, `ArgocdEcrRefresherRoleArn`.

## `jumpbox.yaml`

**Purpose:** Creates the EC2 install VM (in a private subnet) that Terraform
runs from. Its `UserData` self-installs git, Terraform, kubectl, and Helm at
boot — no AMI baking or hand-run tool-install script needed. Optional in both
install paths (`prereqs.sh --no-jumpbox` skips it) — it's only *where you run
`deploy.sh` from*, not a hard dependency `deploy.sh` checks for.

**Parameters:** `Environment` (required), `VpcId`, `PrivateSubnet1Id` (from
the network stack, or your own VPC), `JumpboxName`, `JumpboxInstanceType`,
`UseExistingInstanceProfile`.

**Outputs:** `JumpboxInstanceId`, `JumpboxSecurityGroupId`.

---

## Legacy: `install_role.yaml` (manual, non-agent path)

**Purpose:** Creates the IAM role and instance profile Terraform uses in the
manual (non-agent) install — the predecessor to `foundation.yaml`'s deploy
role, before the per-account-plus-operational-roles split.

**Parameters:** `PromethiumInstallRole` (name for the deployment role,
default `PromethiumDeploymentRole`), `Environment` (default `prod`).

**Deployment:**
```bash
aws cloudformation create-stack \
  --stack-name promethium-install-role \
  --template-body file://install_role.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

**Outputs:** `RoleArn`, `InstanceProfileArn`, `InstanceProfileName`.

## Legacy: `verifier_policy.yaml` (manual, non-agent path)

**Purpose:** Adds read-only CloudFormation/IAM/EKS permissions to the install
role so the manual path's verifier scripts can run from the jumpbox. Not
needed by the scripted flow.

---

## Deployment order

**Scripted (Model A′):** `prereqs.sh` deploys, in order, `network.yaml`
(skipped for BYO VPC) → `foundation.yaml` → `operational_roles.yaml` →
`jumpbox.yaml` (skipped with `--no-jumpbox`). All four are local deploys (no
S3 bucket) and idempotent — safe to re-run if an earlier step failed partway
through. See [../scripts/README.md](../scripts/README.md).

**Manual (non-agent) reference:**
1. Deploy `install_role.yaml` to create the Terraform deployment role
2. Deploy `operational_roles.yaml` — leave `OIDCProviderUrl` at its dummy
   default (same template and two-pass model the scripted flow uses; see
   above)
3. Use Terraform with the created role to deploy your EKS infrastructure;
   Terraform patches the operational roles' trust policies to the real OIDC
   provider once the cluster exists

## Service Account Bindings

After deploying `operational_roles.yaml`, Kubernetes service accounts are
annotated with the IAM role ARNs. Example:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ebs-csi-controller-sa
  namespace: kube-system
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/promethium-prod-<company>-ebs-csi-driver-role
```

## Security Considerations

- All templates create IAM roles with specific, scoped permissions
- `foundation.yaml`'s deploy role includes cross-account assume-role
  permissions for the Promethium SaaS accounts (state backend, agent
  enrollment secrets)
- All roles follow the principle of least privilege for their specific
  functions
- Role names can be customized using template parameters; resource naming
  follows `promethium-<environment>-<company>-*` for the current templates
  (`promethium-prod-*`-style defaults for the legacy `install_role.yaml`)

## Support

For questions or issues with these templates, please contact your Promethium support team.
