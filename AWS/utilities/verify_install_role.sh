#!/bin/bash
# Pre-install verification: checks install role permissions
# Usage: ./verify_install_role.sh <role_name> [aws_region]

ROLE_NAME=${1:-}
REGION=${2:-us-east-1}

if [ -z "$ROLE_NAME" ]; then
  echo "Usage: $0 <role_name> [aws_region]"
  echo "Example: $0 PromethiumDeploymentRole-acme us-east-1"
  exit 1
fi

COMPANY=$(echo "$ROLE_NAME" | sed 's/PromethiumDeploymentRole-//')
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
PASS=0; FAIL=0; WARN=0

check_pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
check_fail() { echo "  ❌ $1 — $2"; FAIL=$((FAIL+1)); }
check_warn() { echo "  ⚠️  $1 — $2"; WARN=$((WARN+1)); }

echo ""
echo "============================================================"
echo " Promethium Pre-Install Role Verification"
echo " Role:    ${ROLE_NAME}"
echo " Account: ${ACCOUNT_ID}"
echo " Region:  ${REGION}"
echo "============================================================"

# ── 1. Role existence ─────────────────────────────────────────────────────────
echo ""
echo "── 1. Role existence"
ROLE_JSON=$(aws iam get-role --role-name "$ROLE_NAME" --output json 2>/dev/null)
if [ -z "$ROLE_JSON" ]; then
  check_fail "Role exists" "ROLE NOT FOUND — cannot continue"
  echo ""
  echo "  FATAL: Role ${ROLE_NAME} does not exist in account ${ACCOUNT_ID}."
  exit 1
fi
ROLE_ARN=$(echo "$ROLE_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['Role']['Arn'])")
check_pass "Role exists: ${ROLE_ARN}"

# ── 2. Instance profile ───────────────────────────────────────────────────────
echo ""
echo "── 2. Instance profile"
PROFILE=$(aws iam list-instance-profiles-for-role --role-name "$ROLE_NAME" \
  --query 'InstanceProfiles[0].InstanceProfileName' --output text 2>/dev/null)
if [ -z "$PROFILE" ] || [ "$PROFILE" = "None" ]; then
  check_fail "Instance profile" "MISSING — jumpbox instance won't have role credentials"
else
  check_pass "Instance profile exists: ${PROFILE}"
fi

# ── 3. Managed policies ────────────────────────────────────────────────────────
echo ""
echo "── 3. Managed policies"
POLICIES=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null)

for EXPECTED in \
  "${ROLE_NAME}-eks" \
  "${ROLE_NAME}-sts" \
  "${ROLE_NAME}-s3-kms" \
  "${ROLE_NAME}-efs" \
  "${ROLE_NAME}-acm" \
  "${ROLE_NAME}-vpc" \
  "${ROLE_NAME}-ec2" \
  "${ROLE_NAME}-glue" \
  "${ROLE_NAME}-iam"; do
  echo "$POLICIES" | grep -q "$EXPECTED" \
    && check_pass "$EXPECTED" \
    || check_warn "$EXPECTED" "not found — may cause failures during apply"
done

# ── 4. STS cross-account targets ──────────────────────────────────────────────
echo ""
echo "── 4. STS cross-account permissions"

# Build combined policy document text from all attached managed policies (reused in section 7)
COMBINED_ALL=""
while IFS=$'\t' read -r PARN PNAME; do
  [ -z "$PARN" ] && continue
  VERSION=$(aws iam get-policy --policy-arn "$PARN" --query 'Policy.DefaultVersionId' --output text 2>/dev/null)
  DOC=$(aws iam get-policy-version --policy-arn "$PARN" --version-id "$VERSION" \
    --query 'PolicyVersion.Document' --output json 2>/dev/null)
  COMBINED_ALL="${COMBINED_ALL}${DOC}"
done < <(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].[PolicyArn,PolicyName]' --output text 2>/dev/null)

COMBINED_STS="$COMBINED_ALL"

echo "$COMBINED_STS" | grep -q "734236616923" \
  && check_pass "STS policy allows assume-role on 734236616923 (S3 state backend)" \
  || check_fail "734236616923 in STS policy" "MISSING — terraform init will fail"

echo "$COMBINED_STS" | grep -q "308611924187" \
  && check_pass "STS policy allows assume-role on 308611924187 (DynamoDB tenant)" \
  || check_fail "308611924187 in STS policy" "MISSING — terraform apply will fail"

echo "$COMBINED_STS" | grep -q "sts:GetServiceBearerToken" \
  && check_pass "sts:GetServiceBearerToken present (ECR token fetch)" \
  || { check_fail "sts:GetServiceBearerToken" "MISSING — ECR image pulls may fail. Fix:
      aws iam put-role-policy \\
        --role-name ${ROLE_NAME} \\
        --policy-name promethium-terraform-sts-patch \\
        --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"sts:GetServiceBearerToken\"],\"Resource\":\"*\"}]}'"; }

# ── 5. Managed policies ───────────────────────────────────────────────────────
echo ""
echo "── 5. Managed policies"
MANAGED=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null)

echo "$MANAGED" | grep -q "AmazonSSMManagedInstanceCore" \
  && check_pass "AmazonSSMManagedInstanceCore" \
  || check_warn "AmazonSSMManagedInstanceCore" "MISSING — SSM session access won't work"

# ── 6. IAM permissions ────────────────────────────────────────────────────────
echo ""
echo "── 6. IAM permissions"
COMBINED_IAM="$COMBINED_ALL"

# Check iam:PassRole and iam:GetRole scoped to IAM role resources (not just EKS ARNs)
# Common bug: these actions present but scoped to arn:aws:eks:* instead of arn:aws:iam:*
IAM_POLICY_FIX="aws iam put-role-policy --role-name ${ROLE_NAME} --policy-name promethium-terraform-iam-policy --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"IAMRoleActionsForEKS\",\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\",\"iam:GetRole\",\"iam:ListAttachedRolePolicies\",\"iam:ListRolePolicies\"],\"Resource\":[\"arn:aws:iam::${ACCOUNT_ID}:role/promethium-*\"]}]}'"

check_iam_action_on_iam_resource() {
  local action=$1
  echo "$COMBINED_ALL" | python3 -c "
import sys, json
text = sys.stdin.read()
# COMBINED_ALL is multiple JSON objects concatenated — split on '}{' boundaries
import re
docs = re.split(r'(?<=\})\s*(?=\{)', text)
for raw in docs:
    try:
        d = json.loads(raw)
    except Exception:
        continue
    for s in d.get('Statement', []):
        actions = s.get('Action', [])
        if isinstance(actions, str): actions = [actions]
        resources = s.get('Resource', [])
        if isinstance(resources, str): resources = [resources]
        if any('${action}' in a for a in actions):
            if any('iam' in r for r in resources) or resources == ['*']:
                print('ok')
                exit(0)
" 2>/dev/null
}

# iam:PassRole check
if [ "$(check_iam_action_on_iam_resource PassRole)" = "ok" ]; then
  check_pass "iam:PassRole scoped to IAM role resources (required for EKS cluster/nodegroup creation)"
elif echo "$COMBINED_IAM" | grep -q "iam:PassRole"; then
  check_fail "iam:PassRole" "Scoped to wrong resource (likely arn:aws:eks:*) — EKS creation will fail. Fix:
      ${IAM_POLICY_FIX}"
else
  check_fail "iam:PassRole" "MISSING — EKS creation will fail. Fix:
      ${IAM_POLICY_FIX}"
fi

# iam:GetRole check
if [ "$(check_iam_action_on_iam_resource GetRole)" = "ok" ]; then
  check_pass "iam:GetRole scoped to IAM role resources (required for EKS nodegroup creation)"
elif echo "$COMBINED_IAM" | grep -q "iam:GetRole"; then
  check_fail "iam:GetRole" "Scoped to wrong resource (likely arn:aws:eks:*) — EKS nodegroup creation will fail. Fix:
      ${IAM_POLICY_FIX}"
else
  check_fail "iam:GetRole" "MISSING — EKS nodegroup creation will fail. Fix:
      ${IAM_POLICY_FIX}"
fi

# iam:UpdateAssumeRolePolicy check (required for OIDC trust policy updates on IRSA roles)
if [ "$(check_iam_action_on_iam_resource UpdateAssumeRolePolicy)" = "ok" ]; then
  check_pass "iam:UpdateAssumeRolePolicy scoped to IAM role resources (required for OIDC trust policy updates)"
elif echo "$COMBINED_IAM" | grep -q "iam:UpdateAssumeRolePolicy"; then
  check_fail "iam:UpdateAssumeRolePolicy" "Scoped to wrong resource — OIDC trust policy updates will fail. Fix:
      ${IAM_POLICY_FIX}"
else
  check_fail "iam:UpdateAssumeRolePolicy" "MISSING — OIDC trust policy updates on IRSA roles will fail during Phase 1c. Fix:
      ${IAM_POLICY_FIX}"
fi

# iam:GetRole on service-linked roles (required for EKS nodegroup SLR validation)
SLR_FIX="aws iam put-role-policy --role-name ${ROLE_NAME} --policy-name promethium-terraform-iam-slr-policy --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"IAMServiceLinkedRoleCheck\",\"Effect\":\"Allow\",\"Action\":[\"iam:GetRole\",\"iam:CreateServiceLinkedRole\"],\"Resource\":[\"arn:aws:iam::${ACCOUNT_ID}:role/aws-service-role/*\"]}]}'"

HAS_SLR_GETROLE=$(echo "$COMBINED_ALL" | python3 -c "
import sys, json, re
text = sys.stdin.read()
docs = re.split(r'(?<=\})\s*(?=\{)', text)
for raw in docs:
    try:
        d = json.loads(raw)
    except Exception:
        continue
    for s in d.get('Statement', []):
        actions = s.get('Action', [])
        if isinstance(actions, str): actions = [actions]
        resources = s.get('Resource', [])
        if isinstance(resources, str): resources = [resources]
        if any('GetRole' in a for a in actions):
            if any('aws-service-role' in r or r == '*' for r in resources):
                print('true')
                exit(0)
print('false')
" 2>/dev/null)

$HAS_SLR_GETROLE \
  && check_pass "iam:GetRole on aws-service-role/* (required for EKS nodegroup SLR validation)" \
  || check_fail "iam:GetRole on aws-service-role/*" "MISSING — EKS nodegroup creation will fail validating AWSServiceRoleForAmazonEKSNodegroup. Fix:
      ${SLR_FIX}"

# iam:CreateOpenIDConnectProvider (required even with aws_iam_oidc_enabled=false — module creates OIDC provider)
OIDC_FIX="aws iam put-role-policy --role-name ${ROLE_NAME} --policy-name promethium-terraform-oidc-policy --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"OIDCProviderManagement\",\"Effect\":\"Allow\",\"Action\":[\"iam:CreateOpenIDConnectProvider\",\"iam:DeleteOpenIDConnectProvider\",\"iam:GetOpenIDConnectProvider\",\"iam:UpdateOpenIDConnectProviderThumbprint\",\"iam:TagOpenIDConnectProvider\"],\"Resource\":\"arn:aws:iam::${ACCOUNT_ID}:oidc-provider/*\"}]}'"

echo "$COMBINED_IAM" | grep -q "iam:CreateOpenIDConnectProvider" \
  && check_pass "iam:CreateOpenIDConnectProvider present (required for EKS OIDC provider creation)" \
  || check_fail "iam:CreateOpenIDConnectProvider" "MISSING — EKS OIDC provider creation will fail. Fix:
      ${OIDC_FIX}"

# iam:CreateRole — Mode 1 only
echo ""
echo "    ── iam:CreateRole (Mode 1 only)"
echo "       Skip if customer pre-created all roles via operational_roles.yaml (Mode 2/BYO)."
echo "$COMBINED_IAM" | grep -q "iam:CreateRole" \
  && check_pass "iam:CreateRole present (Mode 1 — Terraform creates all IAM roles)" \
  || check_warn "iam:CreateRole NOT FOUND" "OK if Mode 2/BYO (customer pre-created all roles). REQUIRED for Mode 1."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Summary: ✅ $PASS passed | ❌ $FAIL failed | ⚠️  $WARN warnings"
echo "============================================================"
if [ $FAIL -gt 0 ]; then
  echo " ACTION REQUIRED: Fix failures above before running terraform."
elif [ $WARN -gt 0 ]; then
  echo " Review warnings — some may cause failures depending on deployment mode."
else
  echo " Role looks good. Proceed to cross-account trust check."
fi
echo ""
