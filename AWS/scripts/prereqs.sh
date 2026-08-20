#!/usr/bin/env bash
# =============================================================================
# Promethium Intelligent-Edge — local CloudFormation prerequisites
# =============================================================================
# Deploys the CFT stacks that must exist before ./deploy.sh can run, ALL as
# local files (`aws cloudformation deploy --template-file`, no --s3-bucket,
# no upload step). This only works because each template renders under
# CloudFormation's 51,200-byte inline-template size limit — that is exactly
# why AWS/CFT/foundation.yaml was split into foundation.yaml (Terraform
# deploy/install role + tfstate bucket) and operational_roles.yaml (the 8
# EKS/OIDC operational roles + TagResolver): the old combined template was
# ~64.9 KB, over the limit, and could only be deployed via an S3-staged
# `--template-url`. Two small local templates avoid needing an S3 bucket (or
# any bucket policy / upload credentials) just to bootstrap a brand-new
# customer account.
#
# Usage:
#   ./prereqs.sh <company> <environment> [options]
#
# Required:
#   <company>       lowercase, [a-z0-9-], <=15 chars, matches the tenant branch
#                   name in promethium-internal-ie-aws
#   <environment>   dev | qa | preview | prod
#
# Options:
#   --vpc-id ID --subnet-ids a,b,c   BYO VPC (both required together). Skips
#                                     deploying network.yaml entirely — pass
#                                     the SAME values to deploy.sh/destroy.sh
#                                     afterwards.
#   --region REGION                  default: $AWS_REGION env / `aws configure
#                                     get region` / us-east-1
#   --no-jumpbox                     skip jumpbox.yaml (steps 1-3 only)
#   --yes                            skip the pre-deploy confirmation gate
#   -h, --help
#
# What this deploys, in order (each step printed, each stack's Outputs shown
# on completion; every step is idempotent — safe to re-run):
#   1. network.yaml          -> promethium-network-<company>          (skipped if --vpc-id given)
#   2. foundation.yaml       -> promethium-foundation-<company>       (CAPABILITY_NAMED_IAM)
#   3. operational_roles.yaml -> promethium-operational-roles-<company> (CAPABILITY_NAMED_IAM)
#   4. jumpbox.yaml          -> promethium-jumpbox-<company>          (skipped if --no-jumpbox)
#
# operational_roles.yaml's OIDCProviderUrl is deliberately left at its DUMMY
# default here — this is a two-pass model: Terraform creates the real EKS
# cluster + OIDC provider later (inside ./deploy.sh), then patches these
# roles' trust policies to the real URL via iam:UpdateAssumeRolePolicy (see
# foundation.yaml's TerraformInstallRole iam-operational-role-trust-mgmt
# inline policy). There is no valid OIDC URL to give it at this point.
#
# After this script, connect to the jumpbox (SSM Session Manager) or an
# equivalent host with the customer account's credentials, then run
# ./deploy.sh <company> <environment>.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFT_DIR="$(cd "${SCRIPT_DIR}/../CFT" && pwd)"
# shellcheck source=./lib-tenant.sh
. "${SCRIPT_DIR}/lib-tenant.sh"

usage() { grep '^#' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ---- args --------------------------------------------------------------------
[ $# -ge 2 ] || { usage; exit 2; }
COMPANY_NAME="$1"; ENVIRONMENT="$2"; shift 2

VPC_ID_OVERRIDE=""; SUBNET_IDS_OVERRIDE=""
AWS_REGION="${AWS_REGION:-}"
SKIP_JUMPBOX=false
ASSUME_YES=false

while [ $# -gt 0 ]; do
  case "$1" in
    --vpc-id) VPC_ID_OVERRIDE="$2"; shift 2 ;;
    --subnet-ids) SUBNET_IDS_OVERRIDE="$2"; shift 2 ;;
    --region) AWS_REGION="$2"; shift 2 ;;
    --no-jumpbox) SKIP_JUMPBOX=true; shift ;;
    --yes) ASSUME_YES=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

case "$ENVIRONMENT" in dev|qa|preview|prod) ;; *) echo "ERROR: environment must be dev|qa|preview|prod" >&2; exit 2 ;; esac
[[ "$COMPANY_NAME" =~ ^[a-z0-9-]{1,15}$ ]] || { echo "ERROR: company must match ^[a-z0-9-]{1,15}\$" >&2; exit 2; }

BYO_VPC=false; [ -n "$VPC_ID_OVERRIDE" ] && BYO_VPC=true
if [ "$BYO_VPC" = true ] || [ -n "$SUBNET_IDS_OVERRIDE" ]; then
  [ -n "$VPC_ID_OVERRIDE" ] && [ -n "$SUBNET_IDS_OVERRIDE" ] || { echo "ERROR: --vpc-id and --subnet-ids must be given together" >&2; exit 2; }
fi

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found on PATH" >&2; exit 1; }

[ -n "$AWS_REGION" ] || AWS_REGION="$(aws configure get region 2>/dev/null || true)"
AWS_REGION="${AWS_REGION:-us-east-1}"

NETWORK_STACK="promethium-network-${COMPANY_NAME}"
FOUNDATION_STACK="promethium-foundation-${COMPANY_NAME}"
OPROLES_STACK="promethium-operational-roles-${COMPANY_NAME}"
JUMPBOX_STACK="promethium-jumpbox-${COMPANY_NAME}"

if [ "$BYO_VPC" = true ]; then
  IFS=',' read -r SUBNET1_ID SUBNET2_ID SUBNET3_ID <<< "$SUBNET_IDS_OVERRIDE"
  [ -n "${SUBNET3_ID:-}" ] || { echo "ERROR: --subnet-ids needs exactly 3 comma-separated subnet ids" >&2; exit 2; }
fi

cat <<PLAN

== Promethium IE local CFT prerequisites — plan ==
  company              : ${COMPANY_NAME}
  environment          : ${ENVIRONMENT}
  region               : ${AWS_REGION}
  1. network stack     : $([ "$BYO_VPC" = true ] && echo "SKIPPED (--vpc-id given: ${VPC_ID_OVERRIDE})" || echo "${NETWORK_STACK}")
  2. foundation stack  : ${FOUNDATION_STACK}
  3. operational-roles : ${OPROLES_STACK}
  4. jumpbox stack     : $([ "$SKIP_JUMPBOX" = true ] && echo "SKIPPED (--no-jumpbox)" || echo "${JUMPBOX_STACK}")
  CFT directory        : ${CFT_DIR}

  All deploys are local (--template-file, no S3 bucket) and idempotent —
  safe to re-run this script if an earlier step failed partway through.

PLAN

if [ "$ASSUME_YES" != true ]; then
  read -r -p "Proceed? [y/N] " ans
  [ "$ans" = "y" ] || [ "$ans" = "Y" ] || { echo "aborted"; exit 1; }
fi

# ---- helpers -----------------------------------------------------------------

deploy_cft() {
  # $1 = template path ; $2 = stack name ; $3.. = extra `aws cloudformation
  # deploy` args (--parameter-overrides ..., --capabilities ...).
  # --no-fail-on-empty-changeset is what makes this idempotent: re-running
  # against a stack that's already up to date is a no-op, not an error.
  local template="$1" stack="$2"
  shift 2
  echo "  deploying ${stack}  (template: ${template})"
  aws cloudformation deploy --region "$AWS_REGION" \
    --template-file "$template" \
    --stack-name "$stack" \
    --no-fail-on-empty-changeset \
    "$@"
}

print_outputs() {
  # $1 = stack name
  echo "  -- ${1} outputs --"
  aws cloudformation describe-stacks --stack-name "$1" --region "$AWS_REGION" \
    --query 'Stacks[0].Outputs' --output table
}

# ---- Step 1: network.yaml (skipped for BYO VPC) ------------------------------
echo; echo "== Step 1: network.yaml =="
if [ "$BYO_VPC" = true ]; then
  echo "  --vpc-id given (${VPC_ID_OVERRIDE}) — skipping network.yaml; using the customer's own VPC/subnets"
else
  deploy_cft "${CFT_DIR}/network.yaml" "$NETWORK_STACK" \
    --parameter-overrides "Environment=${ENVIRONMENT}" "CompanyName=${COMPANY_NAME}"
  print_outputs "$NETWORK_STACK"
fi

# ---- Step 2: foundation.yaml (deploy/install role + tfstate bucket) --------
echo; echo "== Step 2: foundation.yaml =="
deploy_cft "${CFT_DIR}/foundation.yaml" "$FOUNDATION_STACK" \
  --parameter-overrides "CompanyName=${COMPANY_NAME}" "Environment=${ENVIRONMENT}" \
  --capabilities CAPABILITY_NAMED_IAM
print_outputs "$FOUNDATION_STACK"

# =============================================================================
# Step 3: operational_roles.yaml (the 8 EKS/OIDC operational roles)
# =============================================================================
# OIDCProviderUrl is DELIBERATELY left at its dummy default (not overridden
# below) — see the header comment. Terraform patches the real trust policies
# in later, once the EKS cluster + its OIDC provider actually exist.
echo; echo "== Step 3: operational_roles.yaml =="
deploy_cft "${CFT_DIR}/operational_roles.yaml" "$OPROLES_STACK" \
  --parameter-overrides "CompanyName=${COMPANY_NAME}" "Environment=${ENVIRONMENT}" \
  --capabilities CAPABILITY_NAMED_IAM
print_outputs "$OPROLES_STACK"

# ---- Step 4: jumpbox.yaml (optional) -----------------------------------------
echo; echo "== Step 4: jumpbox.yaml =="
if [ "$SKIP_JUMPBOX" = true ]; then
  echo "  --no-jumpbox given — skipping. Run deploy.sh from any host with the customer account's credentials and (once the cluster exists) private network reach to its API."
else
  if [ "$BYO_VPC" = true ]; then
    JB_VPC_ID="$VPC_ID_OVERRIDE"
    JB_SUBNET1_ID="$SUBNET1_ID"
  else
    JB_VPC_ID=$(stack_output "$NETWORK_STACK" VpcId "$AWS_REGION")
    JB_SUBNET1_ID=$(stack_output "$NETWORK_STACK" Subnet1Id "$AWS_REGION")
  fi
  INSTANCE_PROFILE_NAME=$(stack_output "$FOUNDATION_STACK" InstanceProfileName "$AWS_REGION")
  deploy_cft "${CFT_DIR}/jumpbox.yaml" "$JUMPBOX_STACK" \
    --parameter-overrides "Environment=${ENVIRONMENT}" "VpcId=${JB_VPC_ID}" \
      "PrivateSubnet1Id=${JB_SUBNET1_ID}" "UseExistingInstanceProfile=${INSTANCE_PROFILE_NAME}"
  print_outputs "$JUMPBOX_STACK"
fi

echo
echo "== DONE. CloudFormation prerequisites for ${COMPANY_NAME}/${ENVIRONMENT} are up to date. =="
if [ "$SKIP_JUMPBOX" = true ]; then
  echo "   Next: from a host with the customer account's credentials, run ./deploy.sh ${COMPANY_NAME} ${ENVIRONMENT}"
else
  echo "   Next: connect to the jumpbox (SSM Session Manager), then run ./deploy.sh ${COMPANY_NAME} ${ENVIRONMENT}"
fi
