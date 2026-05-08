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

# ── 3. Trust policy ───────────────────────────────────────────────────────────
# NOTE: commented out for now since trust policy is updated by promethium associate, it won't be there when the customer finishes their steps

# echo ""
# echo "── 3. Trust policy"
# TRUST=$(echo "$ROLE_JSON" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin)['Role']['AssumeRolePolicyDocument']))")
# 
# echo "$TRUST" | grep -q "ec2.amazonaws.com" \
#   && check_pass "Trusts ec2.amazonaws.com (required for instance profile)" \
#   || check_fail "Trusts ec2.amazonaws.com" "MISSING — instance profile won't work"
# 
# echo "$TRUST" | grep -q "$ROLE_NAME" \
#   && check_pass "Self-trust present (role can assume itself)" \
#   || check_fail "Self-trust" "MISSING — terraform init will fail; must add before deploy"

# ── 4. Inline policies ────────────────────────────────────────────────────────
echo ""
echo "── 4. Inline policies"
POLICIES=$(aws iam list-role-policies --role-name "$ROLE_NAME" \
  --query 'PolicyNames' --output text 2>/dev/null)

for EXPECTED in \
  promethium-terraform-eks-policy \
  promethium-terraform-sts-policy \
  promethium-terraform-s3-kms-policy \
  promethium-terraform-efs-policy \
  promethium-terraform-acm-policy \
  promethium-terraform-vpc-policy \
  promethium-terraform-ec2-policy \
  promethium-terraform-elb-policy \
  promethium-terraform-glue-policy; do
  echo "$POLICIES" | grep -q "$EXPECTED" \
    && check_pass "$EXPECTED" \
    || check_warn "$EXPECTED" "not found — may cause failures during apply"
done

# ── 5. STS cross-account targets ──────────────────────────────────────────────
echo ""
echo "── 5. STS cross-account permissions"

# Search ALL inline policies for STS permissions (old JSON templates embed STS in ec2 policy)
ALL_INLINE=$(aws iam list-role-policies --role-name "$ROLE_NAME" \
  --query 'PolicyNames' --output json 2>/dev/null)
COMBINED_STS=""
for PNAME in $(echo "$ALL_INLINE" | python3 -c "import sys,json; [print(p) for p in json.load(sys.stdin)]" 2>/dev/null); do
  DOC=$(aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$PNAME" \
    --query 'PolicyDocument' --output json 2>/dev/null)
  COMBINED_STS="${COMBINED_STS}${DOC}"
done

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

# ── 5b. Cross-account trust (live test) ───────────────────────────────────────
echo ""
echo "── 5b. Cross-account trust — live assume-role test"
echo "    (First assumes ${ROLE_NAME}, then tests cross-account trust from that identity)"

# First assume the deployment role itself to get its credentials
DEPLOY_CREDS=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "verify-${COMPANY}-crossaccount" \
  --duration-seconds 900 \
  --output json 2>&1)

if ! echo "$DEPLOY_CREDS" | python3 -c "import sys,json; json.load(sys.stdin)['Credentials']" 2>/dev/null; then
  check_warn "Cross-account trust test" "Cannot assume ${ROLE_NAME} from current caller — run this script from the jumpbox instance profile for accurate results. Verify trust policy manually in each Promethium account."
else
  DEPLOY_KEY=$(echo "$DEPLOY_CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['Credentials']['AccessKeyId'])")
  DEPLOY_SECRET=$(echo "$DEPLOY_CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['Credentials']['SecretAccessKey'])")
  DEPLOY_TOKEN=$(echo "$DEPLOY_CREDS" | python3 -c "import sys,json; print(json.load(sys.stdin)['Credentials']['SessionToken'])")

  for ACCT in 734236616923 308611924187; do
    RESULT=$(AWS_ACCESS_KEY_ID="$DEPLOY_KEY" \
      AWS_SECRET_ACCESS_KEY="$DEPLOY_SECRET" \
      AWS_SESSION_TOKEN="$DEPLOY_TOKEN" \
      aws sts assume-role \
        --role-arn "arn:aws:iam::${ACCT}:role/promethium-terraform-saas-assume-role" \
        --role-session-name "verify-${COMPANY}" \
        --duration-seconds 900 \
        --query 'Credentials.AccessKeyId' \
        --output text 2>&1)
    if echo "$RESULT" | grep -q "^ASIA\|^AKIA"; then
      check_pass "Cross-account trust OK — ${ACCT} trusts ${ROLE_NAME}"
    else
      check_fail "Cross-account trust — ${ACCT}" "MISSING — Promethium must add ${ROLE_NAME} to promethium-terraform-saas-assume-role trust policy in ${ACCT}"
    fi
  done
fi

# ── 6. Managed policies ───────────────────────────────────────────────────────
echo ""
echo "── 6. Managed policies"
MANAGED=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
  --query 'AttachedPolicies[*].PolicyName' --output text 2>/dev/null)

echo "$MANAGED" | grep -q "AmazonSSMManagedInstanceCore" \
  && check_pass "AmazonSSMManagedInstanceCore" \
  || check_warn "AmazonSSMManagedInstanceCore" "MISSING — SSM session access won't work"

# ── 7. IAM permissions ────────────────────────────────────────────────────────
echo ""
echo "── 7. IAM permissions"
ALL_POLICIES=$(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames' --output json 2>/dev/null)
COMBINED_IAM=""
for PNAME in $(echo "$ALL_POLICIES" | python3 -c "import sys,json; [print(p) for p in json.load(sys.stdin)]" 2>/dev/null); do
  DOC=$(aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$PNAME" \
    --query 'PolicyDocument' --output json 2>/dev/null)
  COMBINED_IAM="${COMBINED_IAM}${DOC}"
done

# Check iam:PassRole and iam:GetRole scoped to IAM role resources (not just EKS ARNs)
# Common bug: these actions present but scoped to arn:aws:eks:* instead of arn:aws:iam:*
IAM_POLICY_FIX="aws iam put-role-policy --role-name ${ROLE_NAME} --policy-name promethium-terraform-iam-policy --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"IAMRoleActionsForEKS\",\"Effect\":\"Allow\",\"Action\":[\"iam:PassRole\",\"iam:GetRole\",\"iam:ListAttachedRolePolicies\",\"iam:ListRolePolicies\"],\"Resource\":[\"arn:aws:iam::${ACCOUNT_ID}:role/promethium-*\"]}]}'"

check_iam_action_on_iam_resource() {
  local action=$1
  for PNAME in $(echo "$ALL_POLICIES" | python3 -c "import sys,json; [print(p) for p in json.load(sys.stdin)]" 2>/dev/null); do
    DOC=$(aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$PNAME" \
      --query 'PolicyDocument' --output json 2>/dev/null)
    if echo "$DOC" | grep -q "iam:${action}"; then
      FOUND=$(echo "$DOC" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for s in d.get('Statement', []):
    actions = s.get('Action', [])
    if isinstance(actions, str): actions = [actions]
    resources = s.get('Resource', [])
    if isinstance(resources, str): resources = [resources]
    if any('${action}' in a for a in actions):
        if any('iam' in r for r in resources) or resources == ['*']:
            print('ok')
            break
" 2>/dev/null)
      [ "$FOUND" = "ok" ] && echo "ok" && return
    fi
  done
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

HAS_SLR_GETROLE=false
for PNAME in $(echo "$ALL_POLICIES" | python3 -c "import sys,json; [print(p) for p in json.load(sys.stdin)]" 2>/dev/null); do
  DOC=$(aws iam get-role-policy --role-name "$ROLE_NAME" --policy-name "$PNAME" \
    --query 'PolicyDocument' --output json 2>/dev/null)
  FOUND=$(echo "$DOC" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for s in d.get('Statement', []):
    actions = s.get('Action', [])
    if isinstance(actions, str): actions = [actions]
    resources = s.get('Resource', [])
    if isinstance(resources, str): resources = [resources]
    if any('GetRole' in a for a in actions):
        if any('aws-service-role' in r or r == '*' for r in resources):
            print('ok')
            break
" 2>/dev/null)
  [ "$FOUND" = "ok" ] && HAS_SLR_GETROLE=true && break
done

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
