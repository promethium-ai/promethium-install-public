#!/usr/bin/env bash
# =============================================================================
# Promethium Intelligent-Edge — customer-account self-serve install
# =============================================================================
# Collapses the install to two commands:
#   1. ./prereqs.sh <company> <environment> [--vpc-id ID --subnet-ids a,b,c]
#      stands up the local CloudFormation prerequisites: network[skipped for
#      BYO VPC] + foundation + operational_roles [+ jumpbox] — see
#      AWS/scripts/README.md.
#   2. ./deploy.sh <company> <environment> [--vpc-id ID --subnet-ids a,b,c]
#
# This script does everything after the CFT stacks exist: resolves the VPC +
# the Foundation/operational-roles stack outputs, renders this tenant's
# terraform.tfvars, applies the Terraform (EKS + infra + tenant registration),
# then enrolls the argocd-agent (Model A') — hub-side cert issuance +
# spoke-side agent install.
#
# WHERE TO RUN THIS: on a host with (a) the customer AWS credentials active
# (e.g. the promethium-jumpbox-<company> instance profile) and (b) private
# network reach to the spoke EKS API once created — i.e. the jumpbox itself,
# or an equivalent bastion in the same VPC. It also needs Promethium
# control-plane credentials for the agent-enrollment step — see --hub-profile.
#
# Usage:
#   ./deploy.sh <company> <environment> [options]
#
# Required:
#   <company>       lowercase, [a-z0-9-], <=15 chars, matches the tenant branch
#                   name in promethium-internal-ie-aws
#   <environment>   dev | qa | preview | prod
#
# Options:
#   --vpc-id ID --subnet-ids a,b,c   BYO VPC (both required together). Without
#                                     these, the VPC is read from the
#                                     promethium-network-<company> stack.
#   --region REGION                  default: $AWS_REGION env / `aws configure
#                                     get region` / us-east-1
#   --iac-ref REF                    promethium-iac-terraform module ref to pin
#                                     in main.tf. default: feat/ie-carveout-dev2
#   --eks-version V                  default: 1.35
#   --image-tag TAG                  default: 24.6.0
#   --loadbalancer-type TYPE         internet-facing | internal. default: internal
#                                    (customer installs = private cluster + internal ALB,
#                                    validated via in-VPC curl; pass internet-facing only
#                                    for internal Promethium public-cluster deployments)
#   --registry-api-url URL           default: derived, see ASSUMPTIONS in README
#   --operator-email EMAIL           default: support@promethium.ai
#   --jumpbox-sg-id SG               default: self-discovered via IMDSv2
#   --hub-profile PROFILE            AWS CLI profile for Promethium hub-side
#                                     steps (cert issuance). See README.
#   --agent-server-addr HOST:PORT    default: argocdagent.<environment>.promethium.ai:443
#                                     (argocd-hub.<env> after task #13's PKI cutover)
#   --argocd-agent-ref REF           default: v0.9.0
#   --workdir DIR                    default: current directory
#   --skip-agent                     stop after Terraform apply (infra only)
#   --yes                            skip the pre-apply confirmation gate
#   -h, --help
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./lib-tenant.sh
. "${SCRIPT_DIR}/lib-tenant.sh"

usage() { grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ---- args --------------------------------------------------------------------
[ $# -ge 2 ] || { usage; exit 2; }
COMPANY_NAME="$1"; ENVIRONMENT="$2"; shift 2

VPC_ID_OVERRIDE=""; SUBNET_IDS_OVERRIDE=""
AWS_REGION="${AWS_REGION:-}"
IAC_REF="feat/ie-carveout-dev2"
EKS_VERSION="1.35"
PROMETHIUM_IMAGE_TAG="24.6.0"
LOADBALANCER_TYPE="internal"
TENANT_REGISTRY_API_URL=""
OPERATOR_EMAIL="support@promethium.ai"
JUMPBOX_SG_ID_OVERRIDE=""
HUB_PROFILE=""
AGENT_SERVER_ADDR=""
ARGOCD_AGENT_REF="v0.9.0"
WORKDIR="$PWD"
SKIP_AGENT=false
ASSUME_YES=false

while [ $# -gt 0 ]; do
  case "$1" in
    --vpc-id) VPC_ID_OVERRIDE="$2"; shift 2 ;;
    --subnet-ids) SUBNET_IDS_OVERRIDE="$2"; shift 2 ;;
    --region) AWS_REGION="$2"; shift 2 ;;
    --iac-ref) IAC_REF="$2"; shift 2 ;;
    --eks-version) EKS_VERSION="$2"; shift 2 ;;
    --image-tag) PROMETHIUM_IMAGE_TAG="$2"; shift 2 ;;
    --loadbalancer-type) LOADBALANCER_TYPE="$2"; shift 2 ;;
    --registry-api-url) TENANT_REGISTRY_API_URL="$2"; shift 2 ;;
    --operator-email) OPERATOR_EMAIL="$2"; shift 2 ;;
    --jumpbox-sg-id) JUMPBOX_SG_ID_OVERRIDE="$2"; shift 2 ;;
    --hub-profile) HUB_PROFILE="$2"; shift 2 ;;
    --agent-server-addr) AGENT_SERVER_ADDR="$2"; shift 2 ;;
    --argocd-agent-ref) ARGOCD_AGENT_REF="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --skip-agent) SKIP_AGENT=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

case "$ENVIRONMENT" in dev|qa|preview|prod) ;; *) echo "ERROR: environment must be dev|qa|preview|prod" >&2; exit 2 ;; esac
[[ "$COMPANY_NAME" =~ ^[a-z0-9-]{1,15}$ ]] || { echo "ERROR: company must match ^[a-z0-9-]{1,15}\$" >&2; exit 2; }
if [ -n "$VPC_ID_OVERRIDE" ] || [ -n "$SUBNET_IDS_OVERRIDE" ]; then
  [ -n "$VPC_ID_OVERRIDE" ] && [ -n "$SUBNET_IDS_OVERRIDE" ] || { echo "ERROR: --vpc-id and --subnet-ids must be given together" >&2; exit 2; }
fi

require_tools

[ -n "$AWS_REGION" ] || AWS_REGION="$(aws configure get region 2>/dev/null || true)"
AWS_REGION="${AWS_REGION:-us-east-1}"
# Live hub cert SAN is argocdagent.<env> — the argocdagent->argocd-hub rename
# (task #13) is NOT cut over yet, so this must stay argocdagent.<env> or the
# agent mTLS fails on a SAN mismatch. Flip to argocd-hub.<env> once the hub PKI
# is reissued. Override anytime with --agent-server-addr.
[ -n "$AGENT_SERVER_ADDR" ] || AGENT_SERVER_ADDR="argocdagent.${ENVIRONMENT}.promethium.ai:443"
[ -n "$TENANT_REGISTRY_API_URL" ] || TENANT_REGISTRY_API_URL="https://ol77z8v5j2.execute-api.us-east-1.amazonaws.com/${ENVIRONMENT}/onboarding/registry/tenants"

NETWORK_STACK="promethium-network-${COMPANY_NAME}"
FOUNDATION_STACK="promethium-foundation-${COMPANY_NAME}"
OPROLES_STACK="promethium-operational-roles-${COMPANY_NAME}"
REPO_DIR="${WORKDIR}/promethium-internal-ie-aws-${COMPANY_NAME}"
BYO_VPC=false; [ -n "$VPC_ID_OVERRIDE" ] && BYO_VPC=true

cat <<PLAN

== Promethium IE deploy — plan ==
  company              : ${COMPANY_NAME}
  environment          : ${ENVIRONMENT}
  region               : ${AWS_REGION}
  VPC                  : $([ "$BYO_VPC" = true ] && echo "BYO (${VPC_ID_OVERRIDE})" || echo "from stack ${NETWORK_STACK}")
  foundation stack     : ${FOUNDATION_STACK}
  operational roles    : ${OPROLES_STACK}
  iac-terraform ref    : ${IAC_REF}
  eks version          : ${EKS_VERSION}
  image tag            : ${PROMETHIUM_IMAGE_TAG}
  loadbalancer type    : ${LOADBALANCER_TYPE}
  agent server address : ${AGENT_SERVER_ADDR}
  working directory    : ${REPO_DIR}
  agent enrollment     : $([ "$SKIP_AGENT" = true ] && echo "SKIPPED (--skip-agent)" || echo "yes (hub cert issuance + spoke install-agent.sh)")

PLAN

if [ "$ASSUME_YES" != true ]; then
  read -r -p "Proceed? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "aborted"; exit 1; }
fi

# ---- Step 1: VPC resolution --------------------------------------------------
echo; echo "== Step 1: VPC resolution =="
if [ "$BYO_VPC" = true ]; then
  VPC_ID="$VPC_ID_OVERRIDE"
  IFS=',' read -r SUBNET1_ID SUBNET2_ID SUBNET3_ID <<< "$SUBNET_IDS_OVERRIDE"
  [ -n "${SUBNET3_ID:-}" ] || { echo "ERROR: --subnet-ids needs exactly 3 comma-separated subnet ids" >&2; exit 2; }
  VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --region "$AWS_REGION" --query 'Vpcs[0].CidrBlock' --output text)
  echo "  BYO VPC ${VPC_ID} (${VPC_CIDR}), subnets ${SUBNET1_ID},${SUBNET2_ID},${SUBNET3_ID}"
else
  stack_exists "$NETWORK_STACK" "$AWS_REGION" || { echo "ERROR: stack ${NETWORK_STACK} not found in ${AWS_REGION} — deploy AWS/CFT/network.yaml first, or pass --vpc-id/--subnet-ids for a BYO VPC" >&2; exit 1; }
  VPC_ID=$(stack_output "$NETWORK_STACK" VpcId "$AWS_REGION")
  VPC_CIDR=$(stack_output "$NETWORK_STACK" VpcCidrBlock "$AWS_REGION")
  SUBNET1_ID=$(stack_output "$NETWORK_STACK" Subnet1Id "$AWS_REGION")
  SUBNET2_ID=$(stack_output "$NETWORK_STACK" Subnet2Id "$AWS_REGION")
  SUBNET3_ID=$(stack_output "$NETWORK_STACK" Subnet3Id "$AWS_REGION")
  echo "  ${NETWORK_STACK}: VPC ${VPC_ID} (${VPC_CIDR}), subnets ${SUBNET1_ID},${SUBNET2_ID},${SUBNET3_ID}"
fi

# ---- Step 2: Foundation + operational-roles stack outputs --------------------
# The 8 operational role ARNs live in the SEPARATE promethium-operational-roles-
# <company> stack, not in Foundation — foundation.yaml was split into two CFTs
# (Foundation: deploy role + tfstate bucket; operational_roles.yaml: the 8
# EKS/OIDC roles) so each rendered template stays under CloudFormation's
# 51,200-byte inline (--template-file) size limit. See AWS/scripts/prereqs.sh,
# which deploys both.
echo; echo "== Step 2: Foundation + operational-roles stack outputs =="
stack_exists "$FOUNDATION_STACK" "$AWS_REGION" || { echo "ERROR: stack ${FOUNDATION_STACK} not found in ${AWS_REGION} — run AWS/scripts/prereqs.sh first" >&2; exit 1; }
DEPLOY_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" DeployRoleArn "$AWS_REGION")
INSTANCE_PROFILE_NAME=$(stack_output "$FOUNDATION_STACK" InstanceProfileName "$AWS_REGION")
TF_STATE_BUCKET=$(stack_output "$FOUNDATION_STACK" TfStateBucket "$AWS_REGION")

stack_exists "$OPROLES_STACK" "$AWS_REGION" || { echo "ERROR: stack ${OPROLES_STACK} not found in ${AWS_REGION} — run AWS/scripts/prereqs.sh first" >&2; exit 1; }
EBS_ROLE_ARN=$(stack_output "$OPROLES_STACK" EBSCSIDriverRoleArn "$AWS_REGION")
EFS_ROLE_ARN=$(stack_output "$OPROLES_STACK" EFSCSIDriverRoleArn "$AWS_REGION")
LB_ROLE_ARN=$(stack_output "$OPROLES_STACK" LoadBalancerControllerRoleArn "$AWS_REGION")
CA_ROLE_ARN=$(stack_output "$OPROLES_STACK" ClusterAutoscalerRoleArn "$AWS_REGION")
EKS_CLUSTER_ROLE_ARN=$(stack_output "$OPROLES_STACK" EKSClusterRoleArn "$AWS_REGION")
EKS_WORKER_ROLE_ARN=$(stack_output "$OPROLES_STACK" EKSWorkerNodeRoleArn "$AWS_REGION")
PG_BACKUP_ROLE_ARN=$(stack_output "$OPROLES_STACK" PGBackupServiceRoleArn "$AWS_REGION")
TRINO_ROLE_ARN=$(stack_output "$OPROLES_STACK" GlueTrinoServiceRoleArn "$AWS_REGION")
echo "  deploy role   : ${DEPLOY_ROLE_ARN}"
echo "  tfstate bucket: ${TF_STATE_BUCKET}"

if [ -n "$JUMPBOX_SG_ID_OVERRIDE" ]; then
  JUMPBOX_SG_ID="$JUMPBOX_SG_ID_OVERRIDE"
else
  JUMPBOX_SG_ID="$(discover_jumpbox_sg_id "$AWS_REGION")"
  if [ -z "$JUMPBOX_SG_ID" ]; then
    echo "  WARN: could not self-discover a jumpbox security group (not running on EC2?)." >&2
    echo "        Pass --jumpbox-sg-id explicitly — Step 6b's cluster-API authorization needs it." >&2
  fi
fi
echo "  jumpbox SG    : ${JUMPBOX_SG_ID:-<none>}"

CUSTOMER_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# ---- Step 3: clone the tenant branch + pin the module ref -------------------
echo; echo "== Step 3: tenant Terraform branch (promethium-internal-ie-aws @ ${COMPANY_NAME}) =="
clone_or_refresh_tenant_repo "$COMPANY_NAME" "$REPO_DIR"
pin_iac_ref "$IAC_REF" "${REPO_DIR}/main.tf"
grep -q "ref=${IAC_REF}" "${REPO_DIR}/main.tf" || { echo "ERROR: main.tf's module source doesn't show ref=${IAC_REF} after pinning — check main.tf's 'source = \"git::...?ref=...\"' lines by hand" >&2; exit 1; }
echo "  pinned promethium-iac-terraform ref -> ${IAC_REF}"

# ---- Step 4: render terraform.tfvars / register-enable.auto.tfvars / backend.tf --
echo; echo "== Step 4: render terraform.tfvars =="
export COMPANY_NAME ENVIRONMENT AWS_REGION DEPLOY_ROLE_ARN VPC_ID SUBNET1_ID SUBNET2_ID \
  SUBNET3_ID VPC_CIDR INSTANCE_PROFILE_NAME JUMPBOX_SG_ID EKS_CLUSTER_ROLE_ARN \
  EKS_WORKER_ROLE_ARN LB_ROLE_ARN CA_ROLE_ARN EFS_ROLE_ARN EBS_ROLE_ARN \
  PG_BACKUP_ROLE_ARN TRINO_ROLE_ARN EKS_VERSION PROMETHIUM_IMAGE_TAG LOADBALANCER_TYPE \
  TENANT_REGISTRY_API_URL OPERATOR_EMAIL
render_terraform_tfvars "${REPO_DIR}/terraform.tfvars"
render_register_enable_tfvars "${REPO_DIR}/register-enable.auto.tfvars"
render_backend_tf "${REPO_DIR}/backend.tf"
echo "  wrote ${REPO_DIR}/{terraform.tfvars,register-enable.auto.tfvars,backend.tf}"

# ghcr_token: declared in vars.tf (no default) but not referenced by main.tf's
# module blocks in this ref — TF still requires SOME value to avoid an
# interactive prompt. See README assumptions.
export TF_VAR_ghcr_token="${TF_VAR_ghcr_token:-unused}"

# =============================================================================
# Step 5: PRE-APPLY GATE — Promethium-side cross-account grants (S4)
# =============================================================================
# The tenant_register submodule (inside Step 7's `terraform apply`) SigV4-POSTs
# the new tenant to the registry API; it 403s unless this account is already
# granted. Deliberately NOT automated here: onboard-customer-account's
# `customers` map is SHARED, persistent, multi-tenant state (734236616923) —
# applying it from THIS script's fresh per-company checkout with
# `-var="customers={ <this company only> }"` would REPLACE the whole map and
# silently revoke every other onboarded customer's ECR pull grant (see
# onboard-customer-account/main.tf: "an ECR repository policy is a SINGLE
# document per repo"). That must be run by Promethium against the real,
# shared onboard-customer-account state (add this company's key, keep the
# rest), not improvised here. See README "assumptions" for the exact command.
echo
echo "== Step 5: pre-apply gate — Promethium-side S4 grants =="
cat <<GATE
  Before continuing, confirm BOTH are already done for '${COMPANY_NAME}' (account ${CUSTOMER_ACCOUNT_ID}):
    1. onboard-customer-account 'customers' map (734236616923) has an entry for
       ${COMPANY_NAME} -> { account_id = "${CUSTOMER_ACCOUNT_ID}", deployment_role_arn = "${DEPLOY_ROLE_ARN}" }
       applied against its real persistent state (not this script).
    2. Its 'registry_resource_policy_json' output has been folded into the
       CDK-managed registry RestApi resource policy (onboard-registry-writer)
       and that stack redeployed.
  Without both, the tenant-registration SigV4 POST in Step 7 will 403.
GATE
if [ "$ASSUME_YES" != true ]; then
  read -r -p "Both done? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "aborted — complete the S4 grants first (see README.md)"; exit 1; }
fi

# ---- Step 5b: agent-mode preflight — operational-roles refresher output ------
# Fail fast on the #1 silent agent-mode failure: if operational_roles.yaml
# predates the refresher-role codify its stack has no ArgocdEcrRefresherRoleArn
# output, so Step 7's apply never wires the ECR/IRSA image-pull chain and the
# umbrella OCI sync stalls ~90% in (ImagePullBackOff) instead of failing here.
# Read-only + idempotent; skipped for --skip-agent (infra-only) runs.
if [ "$SKIP_AGENT" != true ]; then
  echo; echo "== Step 5b: agent-mode preflight — operational-roles refresher output =="
  REFRESHER_ROLE_ARN="$(stack_output "$OPROLES_STACK" ArgocdEcrRefresherRoleArn "$AWS_REGION" 2>/dev/null || true)"
  if [ -z "$REFRESHER_ROLE_ARN" ]; then
    echo "ERROR: operational_roles.yaml stack '${OPROLES_STACK}' has no ArgocdEcrRefresherRoleArn output — it predates the refresher-role codify. Re-deploy the operational-roles stack from the current CFT (prereqs.sh) before continuing." >&2
    exit 1
  fi
  echo "  refresher role: ${REFRESHER_ROLE_ARN}"
fi

# ---- Step 6: terraform init ---------------------------------------------------
echo; echo "== Step 6: terraform init (S3 backend, no DynamoDB) =="
(
  cd "$REPO_DIR"
  terraform init -input=false \
    -backend-config="bucket=${TF_STATE_BUCKET}" \
    -backend-config="key=${COMPANY_NAME}/terraform.tfstate" \
    -backend-config="region=${AWS_REGION}" \
    -backend-config="use_lockfile=true"
)

# =============================================================================
# Step 7: terraform apply — staged (mirrors phase1-customer-infra.sh)
# =============================================================================
# NOT a single `terraform apply -auto-approve`: the cluster is private, so
# nothing on this host can reach the EKS API — including Terraform's own
# kubernetes/helm providers used later in the SAME apply — until the SG rule
# below exists. That rule is an aws_security_group_rule OUTSIDE this Terraform
# run's own dependency graph (added by hand here, same as phase1), so the
# cluster must be created FIRST, in its own targeted apply, before anything
# that needs the API can run.
echo; echo "== Step 7: terraform apply — cluster, then infra =="
CLUSTER_NAME="promethium-datafabric-${ENVIRONMENT}-${COMPANY_NAME}-eks-cluster"
(
  cd "$REPO_DIR"
  echo "  7a. create the EKS cluster only (~10-15 min)"
  terraform apply -input=false -auto-approve \
    -target=module.aws.module.eks.aws_eks_cluster.ekscluster

  echo "  7b. authorize this host -> the new private cluster API:443"
  CLUSTER_SG=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" \
    --query 'cluster.resourcesVpcConfig.clusterSecurityGroupId' --output text)
  if [ -n "$JUMPBOX_SG_ID" ]; then
    aws ec2 authorize-security-group-ingress --group-id "$CLUSTER_SG" \
      --protocol tcp --port 443 --source-group "$JUMPBOX_SG_ID" --region "$AWS_REGION" \
      2>/dev/null || echo "      (ingress rule already present)"
  else
    echo "      WARN: no jumpbox SG known — skipping the ingress rule; the rest of this apply will hang/fail if this host can't already reach ${CLUSTER_SG}" >&2
  fi
  aws eks update-kubeconfig --region "$AWS_REGION" --name "$CLUSTER_NAME"

  echo "  7c. rest of the infra + in-cluster prerequisites + tenant registration (~20-25 min)"
  export TF_VAR_install_spoke_argocd=false TF_VAR_enable_argocd_bootstrap=true TF_VAR_gitops_mode=true
  export TF_VAR_enable_tenant_registration=true
  terraform apply -input=false -auto-approve -target=module.aws
  terraform apply -input=false -auto-approve
)
echo "  cluster + infra + tenant registration complete."

if [ "$SKIP_AGENT" = true ]; then
  echo; echo "== --skip-agent: stopping before agent enrollment. Infra-only deploy complete. =="
  exit 0
fi

# =============================================================================
# Step 8: Agent enrollment — hub-side cert issuance (folds phase2, steps 4-5)
# =============================================================================
# Uses the REAL productized hub-side script already in promethium-internal-ie-aws
# (scripts/issue-and-export-agent-cert.sh) rather than re-inlining the
# scratchpad phase2 draft's raw kubectl/openssl — it does the same wait-for-cert
# + register-agent work with CN validation and a manifest.txt. Needs Promethium
# hub-cluster credentials (734236616923 for dev/qa, 308611924187 for
# preview/prod) — see --hub-profile / README "assumptions" if your ambient
# credentials don't already cover the hub account.
echo; echo "== Step 8: hub-side agent cert issuance =="
BUNDLE_DIR="${WORKDIR}/cert-bundle-${COMPANY_NAME}"
(
  [ -n "$HUB_PROFILE" ] && export AWS_PROFILE="$HUB_PROFILE"
  case "$ENVIRONMENT" in
    dev|qa)       HUB_CLUSTER="promethium-saas-backend"      ; HUB_REGION="us-east-1" ;;
    preview|prod) HUB_CLUSTER="promethium-preview-eks-cluster"; HUB_REGION="us-east-2" ;;
  esac
  chmod +x "${REPO_DIR}/scripts/issue-and-export-agent-cert.sh"
  "${REPO_DIR}/scripts/issue-and-export-agent-cert.sh" \
    --tenant "$COMPANY_NAME" --env "$ENVIRONMENT" --out "$BUNDLE_DIR" \
    --hub "$HUB_CLUSTER" --region "$HUB_REGION"
)
# issue-and-export-agent-cert.sh runs its own `aws eks update-kubeconfig` for
# the HUB cluster, which flips kubectl's current-context on the shared
# ~/.kube/config — restore it to the spoke before Step 9 reads current-context.
aws eks update-kubeconfig --region "$AWS_REGION" --name "$CLUSTER_NAME" >/dev/null
echo "  cert bundle -> ${BUNDLE_DIR} (tls.crt tls.key ca.crt manifest.txt)"

echo "  relaying the bundle to s3://${TF_STATE_BUCKET}/_${COMPANY_NAME}-bundle/ (destroy.sh cleans this up)"
aws s3 cp --recursive "$BUNDLE_DIR" "s3://${TF_STATE_BUCKET}/_${COMPANY_NAME}-bundle/" --region "$AWS_REGION"

# =============================================================================
# Step 9: Agent enrollment — spoke-side install (folds phase3)
# =============================================================================
# Calls this repo's own productized installer (AWS/agent/install-agent.sh)
# instead of re-inlining the scratchpad phase3 draft's raw kubectl — same
# script a customer running this by hand would use. ECR_REFRESHER_ROLE_ARN is
# in the CUSTOMER's account (confirmed against promethium-iac-terraform
# aws/infrastructure/modules/iam_oidc/argocd-ecr-refresher-oidc.tf — the role
# is same-account IRSA, created by Step 7's terraform apply when
# deploy_mode=agent); it auto-confirms install-agent.sh's y/N prompt since
# this whole script is meant to run non-interactively end-to-end.
echo; echo "== Step 9: spoke-side agent install =="
AGENT_ENV_FILE="${WORKDIR}/agent-install-${COMPANY_NAME}.env"
cat > "$AGENT_ENV_FILE" <<EOF
TENANT=${COMPANY_NAME}
PRINCIPAL_ADDRESS=${AGENT_SERVER_ADDR%%:*}
PRINCIPAL_PORT=${AGENT_SERVER_ADDR##*:}
ARGOCD_AGENT_REF=${ARGOCD_AGENT_REF}
UMBRELLA_SOURCE=oci
ECR_REFRESHER_ROLE_ARN=arn:aws:iam::${CUSTOMER_ACCOUNT_ID}:role/promethium-${ENVIRONMENT}-${COMPANY_NAME}-argocd-ecr-refresher
ECR_REGION=us-west-1
ECR_REGISTRY=734236616923.dkr.ecr.us-west-1.amazonaws.com
CHART_NS=charts
EOF
echo "  wrote ${AGENT_ENV_FILE}"

SPOKE_CONTEXT="$(kubectl config current-context)"
chmod +x "${SCRIPT_DIR}/../agent/install-agent.sh"
printf 'y\n' | "${SCRIPT_DIR}/../agent/install-agent.sh" \
  --config "$AGENT_ENV_FILE" --bundle "$BUNDLE_DIR" --context "$SPOKE_CONTEXT"

# ---- Step 9 verify: ECR image-pull credential chain (agent-mode fail-fast) ---
# Surface the #1 silent agent-mode failure here at minute ~1 instead of a
# mid-umbrella (~90%) ImagePullBackOff hang: the refresher must have written a
# usable OCI pull credential into argocd/ie-ecr-oci. Read-only + idempotent.
echo; echo "== Step 9 verify: ECR image-pull credentials on the spoke =="
IE_ECR_OCI_PW="$(kubectl --context "$SPOKE_CONTEXT" -n argocd get secret ie-ecr-oci \
  -o jsonpath='{.data.password}' 2>/dev/null || true)"
IE_ECR_OCI_PW_DECODED="$(printf '%s' "$IE_ECR_OCI_PW" | base64 -d 2>/dev/null || true)"
if [ -z "$IE_ECR_OCI_PW_DECODED" ]; then
  echo "ERROR: argocd secret 'ie-ecr-oci' has no usable password — the ECR OCI pull credential was never written. The refresher role 'promethium-${ENVIRONMENT}-${COMPANY_NAME}-argocd-ecr-refresher' must exist and be assumable (IRSA), and the 734236616923 ECR repo policy must grant it pull. The umbrella OCI sync will fail until this is fixed." >&2
  exit 1
fi
echo "  ie-ecr-oci password present (${#IE_ECR_OCI_PW_DECODED} bytes)."

# ---- Step 9b: seed the intelligentedge image-pull secret (agent BYO) ----------
# The OCI umbrella's pods pull container images cross-account from 734 ECR via
# aws-ecr-docker-creds. In BYO the internal 10-min ecr-cron-job (same-account
# design) does not provide this, so seed it here from the refresher token once
# Argo has created the intelligentedge namespace, and give the ns default SA the
# pull secret (bitnami postgres + any secret-less pod rely on the SA-injected
# one). One-shot — the ECR token TTL (~12h) covers an install/demo; the durable
# 6h refresh of THIS secret is tracked as codify C (umbrella/refresher).
echo "  seeding intelligentedge image-pull secret (aws-ecr-docker-creds)..."
for i in $(seq 1 30); do
  kubectl --context "$SPOKE_CONTEXT" get ns intelligentedge >/dev/null 2>&1 && break
  [ "$i" = 1 ] && echo "    waiting for the intelligentedge namespace (Argo umbrella sync)..."
  sleep 10
done
if kubectl --context "$SPOKE_CONTEXT" get ns intelligentedge >/dev/null 2>&1; then
  kubectl --context "$SPOKE_CONTEXT" -n intelligentedge create secret docker-registry aws-ecr-docker-creds \
    --docker-server=734236616923.dkr.ecr.us-west-1.amazonaws.com \
    --docker-username=AWS --docker-password="$IE_ECR_OCI_PW_DECODED" \
    --dry-run=client -o yaml | kubectl --context "$SPOKE_CONTEXT" apply -f -
  kubectl --context "$SPOKE_CONTEXT" -n intelligentedge patch sa default \
    -p '{"imagePullSecrets":[{"name":"aws-ecr-docker-creds"}]}' >/dev/null 2>&1 || true
  # bitnami postgres injects the pull secret from its SA at pod-creation → recreate the stuck pod
  kubectl --context "$SPOKE_CONTEXT" -n intelligentedge delete pod -l app.kubernetes.io/name=postgresql >/dev/null 2>&1 || true
  echo "  seeded aws-ecr-docker-creds + patched default SA in intelligentedge."
else
  echo "  WARN: intelligentedge namespace not present after ~5m — image pull will stall until aws-ecr-docker-creds is seeded there." >&2
fi

if kubectl --context "$SPOKE_CONTEXT" -n intelligentedge get secret aws-ecr-docker-creds >/dev/null 2>&1; then
  echo "  aws-ecr-docker-creds present in intelligentedge."
else
  echo "  WARN: intelligentedge secret 'aws-ecr-docker-creds' not present yet — the namespace may not exist until the umbrella first syncs. Pods will ImagePullBackOff until the refresher writes this image-pull secret." >&2
fi

echo
echo "== DONE. ${COMPANY_NAME}/${ENVIRONMENT} deployed. =="
echo "   Verify: kubectl -n intelligentedge get pods   (~21 Running once the hub Application lands)"
echo "   Then:   https://${COMPANY_NAME}.${ENVIRONMENT}.promethium.ai/  -> login -> SHOW CATALOGS"
