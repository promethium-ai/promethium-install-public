#!/bin/bash
# Pre-install verification: checks operational roles exist and are correctly configured
# Works whether roles were created via CloudFormation or manually.
#
# Usage:
#
# - company_name:   used to derive expected cluster name and default role names
# - aws_region:     AWS region
# - stack_name:     (optional) CFT stack name to validate CompanyName and OIDCProviderUrl params
# --discover:       scan all IAM roles and identify candidates by managed policy/trust pattern
#                   use this when role names are unknown
#
# Run TWICE:
#   1. Before Phase 1a — validates roles exist and are correctly configured
#   2. After  Phase 1a — additionally validates OIDC URL is updated (not dummy)
#
# Permissions required on the running identity:
#   iam:GetRole, iam:ListRolePolicies, iam:GetRolePolicy, iam:ListAttachedRolePolicies,
#   iam:ListRoles (for --discover), cloudformation:DescribeStacks, eks:DescribeCluster,
#   sts:GetCallerIdentity

COMPANY=${1:-}
REGION=${2:-us-east-1}
DISCOVER=false
STACK_NAME=""

# Parse remaining args — accept stack name as 3rd positional or via --stack flag
shift 2 2>/dev/null
while [ $# -gt 0 ]; do
  case "$1" in
    --stack)    STACK_NAME="$2"; shift 2 ;;
    --discover) DISCOVER=true; shift ;;
    -*)         shift ;;
    *)          [ -z "$STACK_NAME" ] && STACK_NAME="$1"; shift ;;
  esac
done

if [ -z "$COMPANY" ]; then
  echo "Usage: $0 <company_name> [aws_region] [stack_name] [--discover]"
  echo ""
  echo "  company_name  Required. Used to derive expected cluster name and default role names."
  echo "  aws_region    Optional. Defaults to us-east-1."
  echo "  stack_name    Optional. CFT stack name (positional or --stack <name>)."
  echo "  --discover    Optional. Scan all IAM roles and identify candidates by policy pattern."
  echo ""
  echo "Examples:"
  echo "  $0 acme us-east-1"
  echo "  $0 acme us-east-1 promethium-eks-base-roles-acme"
  echo "  $0 acme us-east-1 --stack promethium-eks-base-roles-acme"
  echo "  $0 acme us-east-1 promethium-eks-base-roles-acme --discover"
  exit 1
fi

EXPECTED_CLUSTER="promethium-datafabric-prod-${COMPANY}-eks-cluster"
DUMMY_OIDC="DUMMY1234567890"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
PASS=0; FAIL=0; WARN=0

check_pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
check_fail() { echo "  ❌ $1 — $2"; FAIL=$((FAIL+1)); }
check_warn() { echo "  ⚠️  $1 — $2"; WARN=$((WARN+1)); }

echo ""
echo "============================================================"
echo " Promethium Operational Roles Verification"
echo " Company: ${COMPANY}"
echo " Account: ${ACCOUNT_ID}"
echo " Region:  ${REGION}"
[ -n "$STACK_NAME" ] && echo " Stack:   ${STACK_NAME}" || echo " Stack:   (not provided — checking roles directly)"
echo "============================================================"

# ── 1. CFT stack checks (only if stack name provided) ─────────────────────────
if [ -n "$STACK_NAME" ]; then
  echo ""
  echo "── 1. CFT stack validation"
  STACK_STATUS=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].StackStatus" \
    --output text --region "$REGION" 2>/dev/null)

  if [ -z "$STACK_STATUS" ]; then
    check_warn "Stack ${STACK_NAME}" "NOT FOUND — skipping stack parameter checks, will verify roles directly"
    STACK_NAME=""
  else
    [ "$STACK_STATUS" = "CREATE_COMPLETE" ] || [ "$STACK_STATUS" = "UPDATE_COMPLETE" ] \
      && check_pass "Stack status: ${STACK_STATUS}" \
      || check_fail "Stack status" "${STACK_STATUS} — expected CREATE_COMPLETE or UPDATE_COMPLETE"

    COMPANY_PARAM=$(aws cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --query "Stacks[0].Parameters[?ParameterKey=='CompanyName'].ParameterValue" \
      --output text --region "$REGION" 2>/dev/null)

    OIDC_PARAM=$(aws cloudformation describe-stacks \
      --stack-name "$STACK_NAME" \
      --query "Stacks[0].Parameters[?ParameterKey=='OIDCProviderUrl'].ParameterValue" \
      --output text --region "$REGION" 2>/dev/null)

    echo "     CompanyName:     ${COMPANY_PARAM}"
    echo "     OIDCProviderUrl: ${OIDC_PARAM}"

    [ "$COMPANY_PARAM" = "$COMPANY" ] \
      && check_pass "CompanyName matches: ${COMPANY}" \
      || check_fail "CompanyName mismatch" "Got '${COMPANY_PARAM}', expected '${COMPANY}'"

    if echo "$OIDC_PARAM" | grep -q "$DUMMY_OIDC"; then
      check_pass "OIDCProviderUrl is dummy placeholder (expected before Phase 1a)"
      echo "     After EKS cluster is created, update with:"
      echo "       OIDC_URL=\$(aws eks describe-cluster \\"
      echo "         --name ${EXPECTED_CLUSTER} \\"
      echo "         --query 'cluster.identity.oidc.issuer' \\"
      echo "         --output text --region ${REGION} | sed 's|https://||')"
      echo "       aws cloudformation update-stack \\"
      echo "         --stack-name ${STACK_NAME} \\"
      echo "         --use-previous-template \\"
      echo "         --parameters \\"
      echo "           ParameterKey=CompanyName,ParameterValue=${COMPANY} \\"
      echo "           ParameterKey=OIDCProviderUrl,ParameterValue=\$OIDC_URL \\"
      echo "         --capabilities CAPABILITY_NAMED_IAM \\"
      echo "         --region ${REGION}"
    else
      check_pass "OIDCProviderUrl is real value: ${OIDC_PARAM}"
    fi
  fi
fi

# ── 2. Role existence ─────────────────────────────────────────────────────────
echo ""
echo "── 2. Role existence"
echo "     Checking roles by ARN (from stack outputs) or by default naming convention."
echo ""
echo "     Copy these into terraform.tfvars:"
echo "     ──────────────────────────────────────────────────────"

get_role_arn_from_stack() {
  local output_key=$1
  aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='${output_key}'].OutputValue" \
    --output text --region "$REGION" 2>/dev/null
}

get_role_arn_by_name() {
  local role_name=$1
  aws iam get-role --role-name "$role_name" \
    --query 'Role.Arn' --output text 2>/dev/null
}

check_role() {
  local tfvar_key=$1
  local output_key=$2
  local default_role_name=$3

  local role_arn=""

  if [ -n "$STACK_NAME" ]; then
    role_arn=$(get_role_arn_from_stack "$output_key")
  fi

  # Fall back to default naming convention if no stack or stack output empty
  if [ -z "$role_arn" ] || [ "$role_arn" = "None" ]; then
    role_arn=$(get_role_arn_by_name "$default_role_name")
  fi

  if [ -z "$role_arn" ] || [ "$role_arn" = "None" ]; then
    check_fail "$tfvar_key" "Role not found — tried stack output '${output_key}' and default name '${default_role_name}'"
  else
    check_pass "$tfvar_key"
    echo "     ${tfvar_key} = \"${role_arn}\""
  fi
}

check_role "cluster_role_arn"                "EKSClusterRoleArn"             "promethium-prod-eks-cluster-role-${COMPANY}"
check_role "worker_role_arn"                 "EKSWorkerNodeRoleArn"          "promethium-prod-eks-worker-role-${COMPANY}"
check_role "aws_ebs_driver_role_arn"         "EBSCSIDriverRoleArn"           "promethium-prod-ebs-csi-driver-role-${COMPANY}"
check_role "aws_efs_driver_role_arn"         "EFSCSIDriverRoleArn"           "promethium-prod-efs-csi-driver-role-${COMPANY}"
check_role "aws_lb_controller_role_arn"      "LoadBalancerControllerRoleArn" "promethium-prod-lb-controller-role-${COMPANY}"
check_role "aws_eks_autoscaler_role_arn"     "ClusterAutoscalerRoleArn"      "promethium-prod-cluster-autoscaler-role-${COMPANY}"
check_role "pg_backup_cronjob_oidc_role_arn" "PGBackupServiceRoleArn"        "promethium-prod-pg-backup-role-${COMPANY}"
check_role "trino_oidc_role_arn"             "GlueTrinoServiceRoleArn"       "promethium-prod-glue-trino-role-${COMPANY}"

# ── 3. OIDC URL validation ────────────────────────────────────────────────────
echo ""
echo "── 3. OIDC URL validation"

# Check if the EKS cluster exists yet
REAL_OIDC=$(aws eks describe-cluster \
  --name "$EXPECTED_CLUSTER" \
  --query 'cluster.identity.oidc.issuer' \
  --output text --region "$REGION" 2>/dev/null | sed 's|https://||')

if [ -z "$REAL_OIDC" ] || [ "$REAL_OIDC" = "None" ]; then
  echo "     EKS cluster '${EXPECTED_CLUSTER}' does not exist yet."
  check_pass "OIDC URL check skipped — cluster not yet created (expected before Phase 1a)"
else
  echo "     Cluster exists. Real OIDC URL: ${REAL_OIDC}"

  # Check each OIDC role's trust policy
  OIDC_ROLE_NAMES=()
  if [ -n "$STACK_NAME" ]; then
    for KEY in EBSCSIDriverRoleArn EFSCSIDriverRoleArn LoadBalancerControllerRoleArn ClusterAutoscalerRoleArn PGBackupServiceRoleArn GlueTrinoServiceRoleArn; do
      ARN=$(get_role_arn_from_stack "$KEY")
      [ -n "$ARN" ] && OIDC_ROLE_NAMES+=("$(echo $ARN | cut -d'/' -f2)")
    done
  fi
  # Fallback to default names if stack not used or empty
  if [ ${#OIDC_ROLE_NAMES[@]} -eq 0 ]; then
    OIDC_ROLE_NAMES=(
      "promethium-prod-ebs-csi-driver-role-${COMPANY}"
      "promethium-prod-efs-csi-driver-role-${COMPANY}"
      "promethium-prod-lb-controller-role-${COMPANY}"
      "promethium-prod-cluster-autoscaler-role-${COMPANY}"
      "promethium-prod-pg-backup-role-${COMPANY}"
      "promethium-prod-glue-trino-role-${COMPANY}"
    )
  fi

  OIDC_MISMATCH=false
  for ROLE in "${OIDC_ROLE_NAMES[@]}"; do
    TRUST=$(aws iam get-role --role-name "$ROLE" \
      --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
    if echo "$TRUST" | grep -q "DUMMY"; then
      check_fail "OIDC trust policy on ${ROLE}" "Still has DUMMY URL — update operational_roles stack now:
      OIDC_URL=$(aws eks describe-cluster --name ${EXPECTED_CLUSTER} --query 'cluster.identity.oidc.issuer' --output text --region ${REGION} | sed 's|https://||')
      aws cloudformation update-stack --stack-name ${STACK_NAME:-<stack_name>} --use-previous-template \\
        --parameters ParameterKey=CompanyName,ParameterValue=${COMPANY} \\
                     ParameterKey=OIDCProviderUrl,ParameterValue=\$OIDC_URL \\
        --capabilities CAPABILITY_NAMED_IAM --region ${REGION}"
      OIDC_MISMATCH=true
    elif echo "$TRUST" | grep -q "$REAL_OIDC"; then
      check_pass "OIDC trust policy on ${ROLE} matches cluster"
    else
      check_fail "OIDC trust policy on ${ROLE}" "References a different OIDC provider — not the ${EXPECTED_CLUSTER} cluster. Update the operational_roles stack with the real OIDC URL."
      OIDC_MISMATCH=true
    fi
  done
fi

# ── 4. EKS cluster role trust ─────────────────────────────────────────────────
echo ""
echo "── 4. EKS cluster role trust"
CLUSTER_ROLE_NAME=""
if [ -n "$STACK_NAME" ]; then
  CLUSTER_ROLE_ARN=$(get_role_arn_from_stack "EKSClusterRoleArn")
  [ -n "$CLUSTER_ROLE_ARN" ] && CLUSTER_ROLE_NAME=$(echo "$CLUSTER_ROLE_ARN" | cut -d'/' -f2)
fi
[ -z "$CLUSTER_ROLE_NAME" ] && CLUSTER_ROLE_NAME="promethium-prod-eks-cluster-role-${COMPANY}"

TRUST=$(aws iam get-role --role-name "$CLUSTER_ROLE_NAME" \
  --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
echo "$TRUST" | grep -q "eks.amazonaws.com" \
  && check_pass "EKS cluster role trusts eks.amazonaws.com" \
  || check_fail "EKS cluster role trust" "Missing eks.amazonaws.com trust — cluster creation will fail"

# ── 5. Worker role trust ──────────────────────────────────────────────────────
echo ""
echo "── 5. EKS worker role trust"
WORKER_ROLE_NAME=""
if [ -n "$STACK_NAME" ]; then
  WORKER_ROLE_ARN=$(get_role_arn_from_stack "EKSWorkerNodeRoleArn")
  [ -n "$WORKER_ROLE_ARN" ] && WORKER_ROLE_NAME=$(echo "$WORKER_ROLE_ARN" | cut -d'/' -f2)
fi
[ -z "$WORKER_ROLE_NAME" ] && WORKER_ROLE_NAME="promethium-prod-eks-worker-role-${COMPANY}"

TRUST=$(aws iam get-role --role-name "$WORKER_ROLE_NAME" \
  --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
echo "$TRUST" | grep -q "ec2.amazonaws.com" \
  && check_pass "Worker role trusts ec2.amazonaws.com" \
  || check_fail "Worker role trust" "Missing ec2.amazonaws.com trust — node group creation will fail"

# ── Discover mode ────────────────────────────────────────────────────────────
if [ "$DISCOVER" = true ]; then
  echo ""
  echo "── DISCOVER MODE — scanning IAM roles by policy pattern"
  echo "    Use this to identify roles when names are unknown."
  echo "    Confirm each candidate and paste ARNs into terraform.tfvars."
  echo ""

  find_role_by_managed_policy() {
    local label=$1
    local policy_name=$2
    echo "  Scanning for ${label} (has ${policy_name} attached)..."
    aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text 2>/dev/null | \
    while read ROLE_NAME ROLE_ARN; do
      ATTACHED=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
        --query "AttachedPolicies[?contains(PolicyName,'${policy_name}')].PolicyName" \
        --output text 2>/dev/null)
      if [ -n "$ATTACHED" ]; then
        echo "    → CANDIDATE: $ROLE_NAME ($ROLE_ARN)"
      fi
    done
  }

  find_role_by_trust() {
    local label=$1
    local trust_pattern=$2
    echo "  Scanning for ${label} (trusts ${trust_pattern})..."
    aws iam list-roles --query 'Roles[*].[RoleName,Arn]' --output text 2>/dev/null | \
    while read ROLE_NAME ROLE_ARN; do
      TRUST=$(aws iam get-role --role-name "$ROLE_NAME" \
        --query 'Role.AssumeRolePolicyDocument' --output json 2>/dev/null)
      if echo "$TRUST" | grep -q "$trust_pattern"; then
        echo "    → CANDIDATE: $ROLE_NAME ($ROLE_ARN)"
      fi
    done
  }

  find_role_by_managed_policy "EKS cluster role" "AmazonEKSClusterPolicy"
  find_role_by_managed_policy "EKS worker node role" "AmazonEKSWorkerNodePolicy"
  find_role_by_managed_policy "EBS CSI driver role" "AmazonEBSCSIDriverPolicy"
  find_role_by_trust "EFS CSI driver role" "efs-csi-controller-sa"
  find_role_by_trust "LB controller role" "aws-load-balancer-controller"
  find_role_by_trust "Cluster autoscaler role" "cluster-autoscaler"
  find_role_by_trust "PG backup role" "s3-backup-sa"
  find_role_by_trust "Glue/Trino role" "trino-sa"

  echo ""
  echo "  Once you identify the correct roles, re-run without --discover"
  echo "  and provide the stack name, or set role names in tfvars manually."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Summary: ✅ $PASS passed | ❌ $FAIL failed | ⚠️  $WARN warnings"
echo "============================================================"
if [ $FAIL -gt 0 ]; then
  echo " ACTION REQUIRED: Fix failures above before running terraform."
elif [ $WARN -gt 0 ]; then
  echo " Review warnings — if EKS cluster exists, update the OIDC URL now."
else
  echo " Operational roles look good. Proceed with terraform."
fi
echo ""
