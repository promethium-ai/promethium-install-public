#!/usr/bin/env bash
# =============================================================================
# Promethium Intelligent-Edge — customer-account teardown (one command)
# =============================================================================
#   ./destroy.sh <company> <environment> [--yes] [options]
#
# Reproduces the proven teardown recipe in order: stop the agent re-syncing,
# strip ExternalSecret finalizers, terraform destroy (with a bounded
# state-rm-and-retry for helm_release/kubernetes_namespace stragglers — the
# EKS cluster deletion nukes the rest of the in-cluster content), remove the
# hub Application + cluster registration, remove the gitops tenant file,
# best-effort cross-account 734 cleanup, then (ONLY if we created the VPC)
# tear down the VPC chain, then the Foundation stack + tfstate bucket.
#
# *** DO NOT run this from the promethium-jumpbox-<company> instance being
# *** torn down. Step 7 below deletes that jumpbox's own CloudFormation stack —
# *** if this script is running ON that instance, the instance (and this
# *** script) dies mid-teardown, before Steps 8-9 ever run. Run this from a
# *** separate host with AWS creds for the customer account and network/kube
# *** access to the spoke cluster (e.g. a standing ops bastion in the same
# *** VPC, or your own machine if the cluster API is reachable from it).
#
# Usage:
#   ./destroy.sh <company> <environment> [--yes] [options]
#
# Required:
#   <company>       must match the tenant branch name used at deploy time
#   <environment>   dev | qa | preview | prod
#
# Options (see AWS/scripts/README.md for the full list + defaults — this set
# mirrors deploy.sh's flags so the SAME tfvars get re-rendered for `terraform
# destroy`; a plain `destroy.sh <company> <env>` matches a plain `deploy.sh
# <company> <env>`):
#   --yes                             skip the interactive confirmation
#   --region REGION
#   --vpc-id ID --subnet-ids a,b,c    BYO VPC (must match what deploy.sh used)
#   --jumpbox-sg-id SG
#   --iac-ref REF                     default: feat/ie-carveout-dev2
#   --eks-version / --image-tag / --loadbalancer-type / --registry-api-url /
#   --operator-email                  must match deploy.sh's values
#   --hub-context CTX                 default: current kube context
#   --gitops-repo-path PATH           default: /Users/antoniopm61data/pm61data/gitops-tenants-registry
#   --ecr-account-profile PROFILE     AWS CLI profile for account 734236616923
#                                      (Step 6 best-effort cleanup)
#   --max-attempts N                  terraform destroy retry bound, default 3
#   --workdir DIR                     default: current directory
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
[ -n "$COMPANY_NAME" ] && [ -n "$ENVIRONMENT" ] || { echo "ERROR: company and environment are required" >&2; exit 2; }

ASSUME_YES=false
AWS_REGION="${AWS_REGION:-}"
VPC_ID_OVERRIDE=""; SUBNET_IDS_OVERRIDE=""
JUMPBOX_SG_ID_OVERRIDE=""
IAC_REF="feat/ie-carveout-dev2"
EKS_VERSION="1.35"
PROMETHIUM_IMAGE_TAG="24.6.0"
LOADBALANCER_TYPE="internet-facing"
TENANT_REGISTRY_API_URL=""
OPERATOR_EMAIL="support@promethium.ai"
HUB_CONTEXT=""
GITOPS_REPO_PATH="/Users/antoniopm61data/pm61data/gitops-tenants-registry"
GITOPS_BRANCH="feature/argo-runner-appsets"
ECR_ACCOUNT_PROFILE=""
MAX_ATTEMPTS=3
WORKDIR="$PWD"

while [ $# -gt 0 ]; do
  case "$1" in
    --yes) ASSUME_YES=true; shift ;;
    --region) AWS_REGION="$2"; shift 2 ;;
    --vpc-id) VPC_ID_OVERRIDE="$2"; shift 2 ;;
    --subnet-ids) SUBNET_IDS_OVERRIDE="$2"; shift 2 ;;
    --jumpbox-sg-id) JUMPBOX_SG_ID_OVERRIDE="$2"; shift 2 ;;
    --iac-ref) IAC_REF="$2"; shift 2 ;;
    --eks-version) EKS_VERSION="$2"; shift 2 ;;
    --image-tag) PROMETHIUM_IMAGE_TAG="$2"; shift 2 ;;
    --loadbalancer-type) LOADBALANCER_TYPE="$2"; shift 2 ;;
    --registry-api-url) TENANT_REGISTRY_API_URL="$2"; shift 2 ;;
    --operator-email) OPERATOR_EMAIL="$2"; shift 2 ;;
    --hub-context) HUB_CONTEXT="$2"; shift 2 ;;
    --gitops-repo-path) GITOPS_REPO_PATH="$2"; shift 2 ;;
    --ecr-account-profile) ECR_ACCOUNT_PROFILE="$2"; shift 2 ;;
    --max-attempts) MAX_ATTEMPTS="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

case "$ENVIRONMENT" in dev|qa|preview|prod) ;; *) echo "ERROR: environment must be dev|qa|preview|prod" >&2; exit 2 ;; esac
require_tools

[ -n "$AWS_REGION" ] || AWS_REGION="$(aws configure get region 2>/dev/null || true)"
AWS_REGION="${AWS_REGION:-us-east-1}"
[ -n "$TENANT_REGISTRY_API_URL" ] || TENANT_REGISTRY_API_URL="https://ol77z8v5j2.execute-api.us-east-1.amazonaws.com/${ENVIRONMENT}/onboarding/registry/tenants"

NETWORK_STACK="promethium-network-${COMPANY_NAME}"
FOUNDATION_STACK="promethium-foundation-${COMPANY_NAME}"
REPO_DIR="${WORKDIR}/promethium-internal-ie-aws-${COMPANY_NAME}"
CLUSTER_NAME="promethium-datafabric-${ENVIRONMENT}-${COMPANY_NAME}-eks-cluster"
BYO_VPC=false; [ -n "$VPC_ID_OVERRIDE" ] && BYO_VPC=true
WE_OWN_THE_VPC=false
stack_exists "$NETWORK_STACK" "$AWS_REGION" && WE_OWN_THE_VPC=true

cat <<PLAN

== Promethium IE destroy — plan ==
  company              : ${COMPANY_NAME}
  environment          : ${ENVIRONMENT}
  region               : ${AWS_REGION}
  cluster              : ${CLUSTER_NAME}
  VPC ownership        : $([ "$WE_OWN_THE_VPC" = true ] && echo "we created it (${NETWORK_STACK} exists) -> WILL be torn down" || echo "BYO / not ours -> will NOT be touched")
  hub context          : ${HUB_CONTEXT:-<current kube context>}
  gitops repo          : ${GITOPS_REPO_PATH} @ ${GITOPS_BRANCH}
  working directory     : ${REPO_DIR}

  This is IRREVERSIBLE: EKS cluster, all in-cluster workloads, the hub Argo
  Application + agent registration, the gitops tenant file, the Foundation
  stack's IAM roles, and the tfstate bucket (incl. the agent cert bundle) are
  all deleted. If ${NETWORK_STACK} exists, the VPC it created is deleted too.

PLAN

if [ "$ASSUME_YES" != true ]; then
  read -r -p "Type 'yes' to continue: " CONFIRM
  [ "$CONFIRM" = "yes" ] || { echo "aborted"; exit 1; }
fi

CUSTOMER_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Capture the cluster's OIDC issuer NOW, before terraform destroy removes the
# cluster (and its OIDC provider) — Step 6 needs it and can't get it later.
CLUSTER_OIDC_ISSUER=$(aws eks describe-cluster --name "$CLUSTER_NAME" --region "$AWS_REGION" \
  --query 'cluster.identity.oidc.issuer' --output text 2>/dev/null || true)
[ "$CLUSTER_OIDC_ISSUER" = "None" ] && CLUSTER_OIDC_ISSUER=""

# ---- Step 1: stop the agent re-syncing ---------------------------------------
echo; echo "== Step 1: scale down the spoke agent =="
if aws eks update-kubeconfig --region "$AWS_REGION" --name "$CLUSTER_NAME" >/dev/null 2>&1; then
  kubectl -n argocd scale deploy/argocd-agent-agent --replicas=0 2>/dev/null \
    || echo "  argocd-agent-agent not found / already scaled down"
else
  echo "  cluster ${CLUSTER_NAME} unreachable — already gone? continuing"
fi

# ---- Step 2: strip ExternalSecret finalizers ---------------------------------
echo; echo "== Step 2: strip ExternalSecret finalizers (ns intelligentedge) =="
ES_NAMES=$(kubectl -n intelligentedge get externalsecrets.external-secrets.io -o name 2>/dev/null || true)
if [ -n "$ES_NAMES" ]; then
  while IFS= read -r es; do
    [ -n "$es" ] || continue
    kubectl -n intelligentedge patch "$es" --type merge -p '{"metadata":{"finalizers":null}}' \
      && echo "  cleared finalizers: $es" \
      || echo "  WARN: could not patch $es"
  done <<< "$ES_NAMES"
else
  echo "  no ExternalSecrets found (namespace already gone?) — skipping"
fi

# ---- Step 3: terraform destroy (bounded prune-and-retry) --------------------
echo; echo "== Step 3: terraform destroy =="
clone_or_refresh_tenant_repo "$COMPANY_NAME" "$REPO_DIR"
pin_iac_ref "$IAC_REF" "${REPO_DIR}/main.tf"

# Re-resolve the SAME VPC + Foundation values deploy.sh used, so this destroy
# evaluates an IDENTICAL configuration (same resource graph — same toggles —
# and the same data values) against the real remote state.
if [ "$BYO_VPC" = true ]; then
  VPC_ID="$VPC_ID_OVERRIDE"
  IFS=',' read -r SUBNET1_ID SUBNET2_ID SUBNET3_ID <<< "$SUBNET_IDS_OVERRIDE"
  VPC_CIDR=$(aws ec2 describe-vpcs --vpc-ids "$VPC_ID" --region "$AWS_REGION" --query 'Vpcs[0].CidrBlock' --output text)
elif [ "$WE_OWN_THE_VPC" = true ]; then
  VPC_ID=$(stack_output "$NETWORK_STACK" VpcId "$AWS_REGION")
  VPC_CIDR=$(stack_output "$NETWORK_STACK" VpcCidrBlock "$AWS_REGION")
  SUBNET1_ID=$(stack_output "$NETWORK_STACK" Subnet1Id "$AWS_REGION")
  SUBNET2_ID=$(stack_output "$NETWORK_STACK" Subnet2Id "$AWS_REGION")
  SUBNET3_ID=$(stack_output "$NETWORK_STACK" Subnet3Id "$AWS_REGION")
else
  echo "ERROR: neither ${NETWORK_STACK} nor --vpc-id/--subnet-ids gave a VPC to re-render tfvars with." >&2
  echo "       Pass --vpc-id/--subnet-ids matching what deploy.sh originally used." >&2
  exit 1
fi

stack_exists "$FOUNDATION_STACK" "$AWS_REGION" || { echo "ERROR: stack ${FOUNDATION_STACK} not found — cannot re-render tfvars for destroy" >&2; exit 1; }
DEPLOY_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" DeployRoleArn "$AWS_REGION")
INSTANCE_PROFILE_NAME=$(stack_output "$FOUNDATION_STACK" InstanceProfileName "$AWS_REGION")
TF_STATE_BUCKET=$(stack_output "$FOUNDATION_STACK" TfStateBucket "$AWS_REGION")
EBS_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" EBSCSIDriverRoleArn "$AWS_REGION")
EFS_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" EFSCSIDriverRoleArn "$AWS_REGION")
LB_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" LoadBalancerControllerRoleArn "$AWS_REGION")
CA_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" ClusterAutoscalerRoleArn "$AWS_REGION")
EKS_CLUSTER_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" EKSClusterRoleArn "$AWS_REGION")
EKS_WORKER_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" EKSWorkerNodeRoleArn "$AWS_REGION")
PG_BACKUP_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" PGBackupServiceRoleArn "$AWS_REGION")
TRINO_ROLE_ARN=$(stack_output "$FOUNDATION_STACK" GlueTrinoServiceRoleArn "$AWS_REGION")

if [ -n "$JUMPBOX_SG_ID_OVERRIDE" ]; then
  JUMPBOX_SG_ID="$JUMPBOX_SG_ID_OVERRIDE"
else
  JUMPBOX_SG_ID="$(discover_jumpbox_sg_id "$AWS_REGION")"
fi

export COMPANY_NAME ENVIRONMENT AWS_REGION DEPLOY_ROLE_ARN VPC_ID SUBNET1_ID SUBNET2_ID \
  SUBNET3_ID VPC_CIDR INSTANCE_PROFILE_NAME JUMPBOX_SG_ID EKS_CLUSTER_ROLE_ARN \
  EKS_WORKER_ROLE_ARN LB_ROLE_ARN CA_ROLE_ARN EFS_ROLE_ARN EBS_ROLE_ARN \
  PG_BACKUP_ROLE_ARN TRINO_ROLE_ARN EKS_VERSION PROMETHIUM_IMAGE_TAG LOADBALANCER_TYPE \
  TENANT_REGISTRY_API_URL OPERATOR_EMAIL
render_terraform_tfvars "${REPO_DIR}/terraform.tfvars"
render_register_enable_tfvars "${REPO_DIR}/register-enable.auto.tfvars"
render_backend_tf "${REPO_DIR}/backend.tf"
export TF_VAR_ghcr_token="${TF_VAR_ghcr_token:-unused}"

(
  cd "$REPO_DIR"
  terraform init -input=false \
    -backend-config="bucket=${TF_STATE_BUCKET}" \
    -backend-config="key=${COMPANY_NAME}/terraform.tfstate" \
    -backend-config="region=${AWS_REGION}" \
    -backend-config="use_lockfile=true"

  export TF_VAR_install_spoke_argocd=false TF_VAR_enable_argocd_bootstrap=true TF_VAR_gitops_mode=true
  export TF_VAR_enable_tenant_registration=true

  attempt=1
  until terraform destroy -refresh=false -auto-approve; do
    if [ "$attempt" -ge "$MAX_ATTEMPTS" ]; then
      echo "ERROR: terraform destroy failed after ${MAX_ATTEMPTS} attempts — inspect the state by hand (terraform state list)" >&2
      exit 1
    fi
    echo "  terraform destroy failed (attempt ${attempt}/${MAX_ATTEMPTS}) — the EKS cluster deletion nukes the in-cluster"
    echo "  content out from under helm_release/kubernetes_namespace state; pruning those addresses and retrying."
    STUCK=$(terraform state list 2>/dev/null | grep -E 'helm_release|kubernetes_namespace' || true)
    if [ -n "$STUCK" ]; then
      echo "$STUCK" | while IFS= read -r addr; do
        [ -n "$addr" ] && terraform state rm "$addr" || true
      done
    else
      echo "  nothing matching helm_release|kubernetes_namespace in state — retrying as-is"
    fi
    attempt=$((attempt + 1))
  done
)
echo "  terraform destroy complete."

# ---- Step 4: Hub Application + cluster registration --------------------------
echo; echo "== Step 4: remove the hub Application + agent registration =="
KCTL_HUB=(); [ -n "$HUB_CONTEXT" ] && KCTL_HUB+=(--context "$HUB_CONTEXT")
kubectl "${KCTL_HUB[@]}" -n argocd delete application "${COMPANY_NAME}-${ENVIRONMENT}-ie" --ignore-not-found
kubectl "${KCTL_HUB[@]}" -n argocd delete secret "cluster-${COMPANY_NAME}" --ignore-not-found

# ---- Step 5: gitops tenant file removal ---------------------------------------
echo; echo "== Step 5: remove the gitops tenant file =="
if [ -d "$GITOPS_REPO_PATH/.git" ]; then
  (
    cd "$GITOPS_REPO_PATH"
    git fetch origin "$GITOPS_BRANCH"
    git checkout "$GITOPS_BRANCH"
    git pull --ff-only origin "$GITOPS_BRANCH"
    TENANT_FILE="tenants/${ENVIRONMENT}/${COMPANY_NAME}.yaml"
    if [ -f "$TENANT_FILE" ]; then
      git rm -f "$TENANT_FILE"
      git commit -m "registry: remove ${ENVIRONMENT}/${COMPANY_NAME} (teardown)"
      git push origin "$GITOPS_BRANCH"
    else
      echo "  ${TENANT_FILE} not present in ${GITOPS_REPO_PATH} — already removed, skipping"
    fi
  )
else
  echo "  WARN: ${GITOPS_REPO_PATH} is not a git checkout — pass --gitops-repo-path. Skipping." >&2
fi

# ---- Step 6: cross-account 734 cleanup (best-effort) --------------------------
# In the CURRENT architecture the argocd-ecr-cred-refresher role is same-account
# IRSA in the CUSTOMER's account (promethium-iac-terraform
# aws/infrastructure/modules/iam_oidc/argocd-ecr-refresher-oidc.tf) and Step 3's
# terraform destroy already removed it. This step is a safety net for the
# older hand-rolled pattern (role + a cross-account OIDC provider created
# directly in 734) in case any tenant still has one — see README assumptions.
echo; echo "== Step 6: cross-account 734 cleanup (best-effort) =="
AWS734=(aws); [ -n "$ECR_ACCOUNT_PROFILE" ] && AWS734=(aws --profile "$ECR_ACCOUNT_PROFILE")
REFRESHER_ROLE="promethium-${ENVIRONMENT}-${COMPANY_NAME}-argocd-ecr-refresher"
if "${AWS734[@]}" iam get-role --role-name "$REFRESHER_ROLE" >/dev/null 2>&1; then
  for pol in $("${AWS734[@]}" iam list-role-policies --role-name "$REFRESHER_ROLE" --query 'PolicyNames' --output text); do
    "${AWS734[@]}" iam delete-role-policy --role-name "$REFRESHER_ROLE" --policy-name "$pol"
  done
  for arn in $("${AWS734[@]}" iam list-attached-role-policies --role-name "$REFRESHER_ROLE" --query 'AttachedPolicies[].PolicyArn' --output text); do
    "${AWS734[@]}" iam detach-role-policy --role-name "$REFRESHER_ROLE" --policy-arn "$arn"
  done
  "${AWS734[@]}" iam delete-role --role-name "$REFRESHER_ROLE"
  echo "  deleted 734 IAM role ${REFRESHER_ROLE}"
else
  echo "  ${REFRESHER_ROLE} not found in 734 — nothing to clean up (expected in the current architecture)"
fi

if [ -n "$CLUSTER_OIDC_ISSUER" ]; then
  HOST="${CLUSTER_OIDC_ISSUER#https://}"
  MATCH_ARN=""
  for arn in $("${AWS734[@]}" iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text); do
    url=$("${AWS734[@]}" iam get-open-id-connect-provider --open-id-connect-provider-arn "$arn" --query Url --output text 2>/dev/null || true)
    if [ "$url" = "$HOST" ]; then MATCH_ARN="$arn"; break; fi
  done
  if [ -n "$MATCH_ARN" ]; then
    "${AWS734[@]}" iam delete-open-id-connect-provider --open-id-connect-provider-arn "$MATCH_ARN"
    echo "  deleted 734 OIDC provider ${MATCH_ARN}"
  else
    echo "  no 734 OIDC provider matches ${HOST} — nothing to clean up (expected in the current architecture)"
  fi
else
  echo "  cluster OIDC issuer unknown (cluster already gone before we could read it) — skipping OIDC provider lookup"
fi

# ---- Step 7: VPC chain — ONLY if we created it -------------------------------
echo; echo "== Step 7: VPC chain =="
if [ "$WE_OWN_THE_VPC" = true ]; then
  echo "  ${NETWORK_STACK} exists — we created this VPC, tearing it down"
  EP_IDS=$(aws ec2 describe-vpc-endpoints --region "$AWS_REGION" \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=service-name,Values=*guardduty*" \
    --query 'VpcEndpoints[].VpcEndpointId' --output text)
  if [ -n "$EP_IDS" ]; then
    for ep in $EP_IDS; do
      SG_IDS=$(aws ec2 describe-vpc-endpoints --vpc-endpoint-ids "$ep" --region "$AWS_REGION" \
        --query 'VpcEndpoints[0].Groups[].GroupId' --output text)
      aws ec2 delete-vpc-endpoints --vpc-endpoint-ids "$ep" --region "$AWS_REGION" >/dev/null
      echo "  deleted GuardDuty VPC endpoint ${ep} — waiting for its ENIs to clear"
      for i in $(seq 1 60); do
        remaining=0
        for sg in $SG_IDS; do
          n=$(aws ec2 describe-network-interfaces --region "$AWS_REGION" \
            --filters "Name=vpc-id,Values=${VPC_ID}" "Name=group-id,Values=${sg}" \
            --query 'length(NetworkInterfaces)' --output text 2>/dev/null || echo 0)
          remaining=$((remaining + n))
        done
        [ "$remaining" -eq 0 ] && break
        sleep 10
      done
      for sg in $SG_IDS; do
        aws ec2 delete-security-group --group-id "$sg" --region "$AWS_REGION" 2>/dev/null \
          || echo "  WARN: could not delete SG ${sg} yet (dependents remain — clean up by hand)"
      done
    done
  else
    echo "  no GuardDuty VPC endpoint found in ${VPC_ID} — skipping"
  fi

  # Lenient (|| true) on purpose: if this script is somehow still running on
  # THAT jumpbox despite the warning at the top, the wait call below loses its
  # connection when the instance terminates — don't let that read as a script
  # bug. The network stack delete right after this is NOT lenient: a VPC
  # teardown failure should stop the script rather than silently continuing.
  echo "  deleting stack promethium-jumpbox-${COMPANY_NAME}"
  aws cloudformation delete-stack --stack-name "promethium-jumpbox-${COMPANY_NAME}" --region "$AWS_REGION" 2>/dev/null || true
  aws cloudformation wait stack-delete-complete --stack-name "promethium-jumpbox-${COMPANY_NAME}" --region "$AWS_REGION" 2>/dev/null || true

  echo "  deleting stack ${NETWORK_STACK}"
  aws cloudformation delete-stack --stack-name "$NETWORK_STACK" --region "$AWS_REGION"
  aws cloudformation wait stack-delete-complete --stack-name "$NETWORK_STACK" --region "$AWS_REGION"
else
  echo "  ${NETWORK_STACK} not found — BYO VPC, leaving it untouched (never delete a customer's own VPC)"
fi

# ---- Step 8: Foundation stack + tfstate bucket --------------------------------
echo; echo "== Step 8: Foundation stack + tfstate bucket =="
echo "  deleting stack ${FOUNDATION_STACK} (TfStateBucket has DeletionPolicy: Retain, so it survives this)"
aws cloudformation delete-stack --stack-name "$FOUNDATION_STACK" --region "$AWS_REGION"
aws cloudformation wait stack-delete-complete --stack-name "$FOUNDATION_STACK" --region "$AWS_REGION"

STATE_BUCKET="promethium-tfstate-${CUSTOMER_ACCOUNT_ID}"
empty_versioned_bucket "$STATE_BUCKET" "$AWS_REGION"
aws s3api delete-bucket --bucket "$STATE_BUCKET" --region "$AWS_REGION" 2>/dev/null \
  || echo "  could not delete ${STATE_BUCKET} (already gone, or still has objects — check by hand)"

# ---- Step 9: zero-trace verification ------------------------------------------
echo; echo "== Step 9: zero-trace verification (all of the below should be empty) =="
echo "-- IAM roles matching '${COMPANY_NAME}' --"
aws iam list-roles --query "Roles[?contains(RoleName, '${COMPANY_NAME}')].RoleName" --output text
echo "-- S3 buckets matching '${COMPANY_NAME}' --"
aws s3 ls | grep "${COMPANY_NAME}" || echo "  (none)"
echo "-- CloudFormation stacks matching '${COMPANY_NAME}' --"
aws cloudformation list-stacks --region "$AWS_REGION" \
  --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE ROLLBACK_COMPLETE DELETE_FAILED UPDATE_ROLLBACK_COMPLETE \
  --query "StackSummaries[?contains(StackName, '${COMPANY_NAME}')].StackName" --output text
echo "-- Cognito user pools matching '${COMPANY_NAME}' --"
for pool_id in $(aws cognito-idp list-user-pools --max-results 60 --region "$AWS_REGION" --query 'UserPools[].Id' --output text); do
  name=$(aws cognito-idp describe-user-pool --user-pool-id "$pool_id" --region "$AWS_REGION" --query 'UserPool.Name' --output text 2>/dev/null || true)
  case "$name" in *"$COMPANY_NAME"*) echo "  ${pool_id}  ${name}" ;; esac
done

echo
echo "== DONE. ${COMPANY_NAME}/${ENVIRONMENT} teardown complete. Review Step 9's output above for stragglers. =="
