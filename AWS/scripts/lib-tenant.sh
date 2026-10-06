#!/usr/bin/env bash
# =============================================================================
# Promethium IE self-serve install — shared helpers for deploy.sh / destroy.sh
# =============================================================================
# Sourced by both scripts (`. "$(dirname "$0")/lib-tenant.sh"`) — not meant to
# be executed directly. Callers set `set -euo pipefail` themselves.
#
# Provides:
#   require_tools                 — fail fast if a required CLI is missing
#   stack_exists / stack_output   — CloudFormation output lookups
#   discover_jumpbox_sg_id        — this host's own EC2 security group (IMDSv2)
#   clone_or_refresh_tenant_repo  — clone/refresh the per-company Terraform branch
#   pin_iac_ref                   — sed the promethium-iac-terraform module ref
#   render_backend_tf             — write a partial-config S3 backend block
#   render_terraform_tfvars       — write terraform.tfvars from resolved values
#   render_register_enable_tfvars — write register-enable.auto.tfvars
#   empty_versioned_bucket        — delete every object version + delete marker
#
# render_terraform_tfvars / render_register_enable_tfvars read a well-known set
# of variables that the CALLER must export before invoking them (documented on
# each function). They are plain functions, not subshells, so this works.
# =============================================================================

require_tools() {
  local missing=() t
  for t in aws git sed jq curl terraform kubectl envsubst openssl; do
    command -v "$t" >/dev/null 2>&1 || missing+=("$t")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    echo "ERROR: missing required tool(s) on PATH: ${missing[*]}" >&2
    echo "       (install-VM CloudFormation user-data / install_tools=true can bootstrap most of these)" >&2
    exit 1
  fi
}

# ---- CloudFormation ---------------------------------------------------------

stack_exists() {
  # $1 = stack name ; $2 = region
  aws cloudformation describe-stacks --stack-name "$1" --region "$2" >/dev/null 2>&1
}

stack_output() {
  # $1 = stack name ; $2 = output key ; $3 = region
  local val
  val=$(aws cloudformation describe-stacks --stack-name "$1" --region "$3" \
    --query "Stacks[0].Outputs[?OutputKey=='${2}'].OutputValue" --output text 2>/dev/null || true)
  if [ -z "$val" ] || [ "$val" = "None" ]; then
    echo "ERROR: stack '$1' has no output '$2' (region $3) — has it finished deploying?" >&2
    return 1
  fi
  echo "$val"
}

# ---- Jumpbox self-discovery --------------------------------------------------

discover_jumpbox_sg_id() {
  # Best-effort: THIS host's own primary security group, via IMDSv2. Used only
  # when --jumpbox-sg-id isn't given. Echoes "" (not an error) if unavailable —
  # e.g. not running on an EC2 instance — so callers can fall back / warn.
  local region="$1" token instance_id sg
  token=$(curl -sf -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null) || true
  [ -n "$token" ] || { echo ""; return 0; }
  instance_id=$(curl -sf -m 2 -H "X-aws-ec2-metadata-token: $token" \
    "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null) || true
  [ -n "$instance_id" ] || { echo ""; return 0; }
  sg=$(aws ec2 describe-instances --instance-ids "$instance_id" --region "$region" \
    --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text 2>/dev/null) || true
  [ "$sg" = "None" ] && sg=""
  echo "$sg"
}

# ---- Tenant Terraform branch --------------------------------------------------

clone_or_refresh_tenant_repo() {
  # $1 = company name (== branch name) ; $2 = target dir
  local company="$1" dir="$2"
  local repo="https://github.com/promethium-ai/promethium-internal-ie-aws.git"
  local tmpl="${TENANT_TEMPLATE_BRANCH:-template/agent-dev}"
  local auth_repo="$repo"
  [ -n "${GITHUB_TOKEN:-}" ] && auth_repo="https://x-access-token:${GITHUB_TOKEN}@github.com/promethium-ai/promethium-internal-ie-aws.git"

  # Bootstrap: create the per-tenant branch from the template if it does not
  # exist yet (a fresh tenant). The wrapper branch is generic — deploy.sh renders
  # the per-tenant tfvars — so a branch off the template needs no edits. Keep the
  # template (default template/agent-dev) re-synced whenever wrapper fixes land.
  if ! git ls-remote --exit-code --heads "$repo" "$company" >/dev/null 2>&1; then
    echo "  tenant branch '${company}' not found on origin — bootstrapping from '${tmpl}'" >&2
    local btmp; btmp="$(mktemp -d)"
    if ! git clone -q -b "$tmpl" --single-branch "$auth_repo" "$btmp" >&2; then
      echo "  ERROR: could not clone template branch '${tmpl}' — create it or set TENANT_TEMPLATE_BRANCH" >&2
      rm -rf "$btmp"; return 1
    fi
    if ! ( cd "$btmp" && git checkout -q -b "$company" && git push -q "$auth_repo" "$company" ) >&2; then
      echo "  ERROR: could not push new tenant branch '${company}' — need a GITHUB_TOKEN with push, or create the branch by hand" >&2
      rm -rf "$btmp"; return 1
    fi
    rm -rf "$btmp"
    echo "  created origin/${company} from ${tmpl}" >&2
  fi

  if [ -d "$dir/.git" ]; then
    echo "  ${dir} already present — refreshing branch '${company}'" >&2
    (cd "$dir" && git fetch origin "$company" && git checkout "$company" && git reset --hard "origin/${company}")
  else
    git clone -b "$company" --single-branch "$repo" "$dir"
  fi
}

pin_iac_ref() {
  # $1 = ref (branch/tag) ; $2 = path to main.tf
  # GNU sed syntax (matches phase1-customer-infra.sh) — this is expected to run
  # on the Linux jumpbox. On macOS (BSD sed) use gsed instead, or edit main.tf
  # by hand before running deploy.sh.
  sed -i -E "s|(source[[:space:]]*=[[:space:]]*\".*?ref=)[^\"]+|\1${1}|g" "$2"
}

# ---- Rendered Terraform inputs ----------------------------------------------

render_backend_tf() {
  # $1 = path to backend.tf. Partial config on purpose: bucket/key/region/
  # use_lockfile are supplied at `terraform init` time via -backend-config (see
  # deploy.sh/destroy.sh), so this same file works for every company/env.
  cat > "$1" <<'EOF'
# Rendered by deploy.sh/destroy.sh — partial config. bucket/key/region/
# use_lockfile are supplied at `terraform init` time via -backend-config.
terraform {
  backend "s3" {}
}
EOF
}

render_terraform_tfvars() {
  # $1 = output path (terraform.tfvars). Reads, from the caller's environment:
  #   COMPANY_NAME ENVIRONMENT AWS_REGION DEPLOY_ROLE_ARN
  #   VPC_ID SUBNET1_ID SUBNET2_ID SUBNET3_ID VPC_CIDR
  #   INSTANCE_PROFILE_NAME JUMPBOX_SG_ID
  #   EKS_CLUSTER_ROLE_ARN EKS_WORKER_ROLE_ARN LB_ROLE_ARN CA_ROLE_ARN
  #   EFS_ROLE_ARN EBS_ROLE_ARN PG_BACKUP_ROLE_ARN TRINO_ROLE_ARN
  #   EKS_VERSION PROMETHIUM_IMAGE_TAG LOADBALANCER_TYPE
  # Mirrors the proven cust646 BYO-VPC/BYO-IAM tfvars (promethium-internal-ie-aws
  # examples/example2.tfvars structure) with every value that used to be
  # hand-typed now sourced from the Foundation/Network CFT outputs or CLI flags.
  #
  # Tenant-registration/gitops keys (enable_tenant_registration,
  # tenant_registry_api_url, operator_email, enable_argocd_bootstrap,
  # gitops_mode) are DELIBERATELY NOT set here — see render_register_enable_tfvars.
  # Terraform loads *.auto.tfvars AFTER terraform.tfvars, so setting the same
  # key in both files means the auto.tfvars value silently wins; keeping each
  # key in exactly one file avoids that trap.
  local out="$1"
  cat > "$out" <<EOF
## Rendered by $(basename "$0") on $(date -u +%Y-%m-%dT%H:%M:%SZ) — DO NOT hand-edit.
## Re-run deploy.sh (or destroy.sh, to re-derive the same inputs for a
## terraform destroy) to regenerate. company=${COMPANY_NAME} environment=${ENVIRONMENT}
## Structure: promethium-internal-ie-aws examples/example2.tfvars (BYO VPC + IAM),
## values sourced from the Foundation/Network CFT stack outputs.

## ── Enablers: Foundation/Network CFT own the VPC + IAM; TF creates EKS + infra only ──
install_tools        = false
vpc_enabled          = false
iam_role_create      = false
jumpbox_enabled      = false
aws_iam_oidc_enabled = false
custom_cluster_name  = true
eks_cluster_name     = "promethium-datafabric-${ENVIRONMENT}-${COMPANY_NAME}-eks-cluster" # MUST match the network CFT subnet tags (EksClusterName param)

## ── Access + environment ──
terraform_assume_role_arn = "${DEPLOY_ROLE_ARN}"
cloud_provider            = "aws"
aws_region                = "${AWS_REGION}"
eks_cluster_type          = "private"
env                       = "${ENVIRONMENT}"

## ── Customer VPC (BYO --vpc-id, or promethium-network-${COMPANY_NAME} outputs) ──
vpc_info = {
  vpc_id         = "${VPC_ID}"
  subnet_ids     = ["${SUBNET1_ID}", "${SUBNET2_ID}", "${SUBNET3_ID}"]
  vpc_cidr_block = "${VPC_CIDR}"
}

## ── EKS + jumpbox ──
eks_version                   = "${EKS_VERSION}"
jumpbox_sg_id                 = "${JUMPBOX_SG_ID}"
jumpbox_instance_profile_name = "${INSTANCE_PROFILE_NAME}"

## ── Foundation-provided operational roles (promethium-foundation-${COMPANY_NAME} outputs) ──
cluster_role_arn                = "${EKS_CLUSTER_ROLE_ARN}"
worker_role_arn                 = "${EKS_WORKER_ROLE_ARN}"
aws_lb_controller_role_arn      = "${LB_ROLE_ARN}"
aws_eks_autoscaler_role_arn     = "${CA_ROLE_ARN}"
aws_efs_driver_role_arn         = "${EFS_ROLE_ARN}"
aws_ebs_driver_role_arn         = "${EBS_ROLE_ARN}"
pg_backup_cronjob_oidc_role_arn = "${PG_BACKUP_ROLE_ARN}"
trino_oidc_role_arn             = "${TRINO_ROLE_ARN}"

## ── App ──
company_name         = "${COMPANY_NAME}"
promethium_image_tag = "${PROMETHIUM_IMAGE_TAG}"
image_repo_url       = "734236616923.dkr.ecr.us-west-1.amazonaws.com" # ECR always 734
loadbalancer_type    = "${LOADBALANCER_TYPE}"

## ── Model A' (argocd-agent) ──
deploy_mode          = "agent"
umbrella_source      = "oci"
install_spoke_argocd = false
tenant_authorship    = "api"

## ── Tags ──
default_tags = {
  Environment = "${ENVIRONMENT}"
  Product     = "Promethium"
  Owner       = "support@promethium.ai"
  created-by  = "Terraform"
  Project     = "Intelligentedge"
  persist     = "false"
}
EOF
}

render_register_enable_tfvars() {
  # $1 = output path (register-enable.auto.tfvars). Reads TENANT_REGISTRY_API_URL
  # and OPERATOR_EMAIL from the caller's environment. Overwrites the tenant
  # branch's committed copy of this file (which typically has dev-only /
  # personal placeholder values baked in) with values correct for THIS
  # company/environment — see the precedence note in render_terraform_tfvars.
  local out="$1"
  cat > "$out" <<EOF
# Rendered by $(basename "$0") — tenant registration + gitops/argocd bootstrap enablement.
# (Auto-loaded by Terraform: *.auto.tfvars needs no -var-file flag.)
enable_tenant_registration = true
tenant_registry_api_url    = "${TENANT_REGISTRY_API_URL}"
operator_email             = "${OPERATOR_EMAIL}"
enable_argocd_bootstrap    = true
gitops_mode                = true
EOF
}

# ---- S3 (versioned tfstate bucket teardown) ---------------------------------

empty_versioned_bucket() {
  # $1 = bucket name ; $2 = region. Deletes ALL object versions + delete
  # markers (a plain `aws s3 rm --recursive` does not touch old versions on a
  # versioned bucket). No-op if the bucket doesn't exist.
  local bucket="$1" region="$2"
  if ! aws s3api head-bucket --bucket "$bucket" --region "$region" 2>/dev/null; then
    echo "  bucket ${bucket} not found — skipping"
    return 0
  fi
  echo "  emptying all object versions + delete markers: s3://${bucket}"
  local key_marker="" version_id_marker="" extra_args resp batch count is_truncated
  while true; do
    extra_args=()
    [ -n "$key_marker" ] && extra_args+=(--key-marker "$key_marker")
    [ -n "$version_id_marker" ] && extra_args+=(--version-id-marker "$version_id_marker")
    resp=$(aws s3api list-object-versions --bucket "$bucket" --region "$region" \
      --max-items 1000 --output json "${extra_args[@]}")
    batch=$(echo "$resp" | jq -c '{Objects: ((.Versions // []) + (.DeleteMarkers // [])) | map({Key, VersionId})}')
    count=$(echo "$batch" | jq '.Objects | length')
    if [ "$count" -gt 0 ]; then
      aws s3api delete-objects --bucket "$bucket" --region "$region" --delete "$batch" >/dev/null
      echo "    deleted ${count} version(s)/marker(s)"
    fi
    is_truncated=$(echo "$resp" | jq -r '.IsTruncated // false')
    if [ "$is_truncated" = "true" ]; then
      key_marker=$(echo "$resp" | jq -r '.NextKeyMarker // empty')
      version_id_marker=$(echo "$resp" | jq -r '.NextVersionIdMarker // empty')
    else
      break
    fi
  done
}
