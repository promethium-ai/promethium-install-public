#!/bin/bash
# Cross-account trust verification — run from the jumpbox ONLY.
#
# Tests that Promethium's two internal accounts trust the install role,
# allowing Terraform to access the S3 state backend and DynamoDB tenant lookup.
#
# Run this from the jumpbox after attaching the PromethiumDeploymentRole
# instance profile. No additional permissions are needed — the install role
# already has sts:AssumeRole on both Promethium accounts.
#
# Usage: ./verify_cross_account_trust.sh <role_name> [aws_region]
#
# Example:
#   ./verify_cross_account_trust.sh PromethiumDeploymentRole us-east-1

ROLE_NAME=${1:-}
REGION=${2:-us-east-1}

if [ -z "$ROLE_NAME" ]; then
  echo "Usage: $0 <role_name> [aws_region]"
  echo "Example: $0 PromethiumDeploymentRole us-east-1"
  exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
CALLER=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)
PASS=0; FAIL=0

check_pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
check_fail() { echo "  ❌ $1 — $2"; FAIL=$((FAIL+1)); }

echo ""
echo "============================================================"
echo " Promethium Cross-Account Trust Verification"
echo " Role:    ${ROLE_NAME}"
echo " Account: ${ACCOUNT_ID}"
echo " Caller:  ${CALLER}"
echo "============================================================"
echo ""

# ── 1. Confirm running as the install role ────────────────────────────────────
echo "── 1. Caller identity"
if echo "$CALLER" | grep -q "$ROLE_NAME"; then
  check_pass "Running as ${ROLE_NAME} (instance profile confirmed)"
else
  echo "  ⚠️  WARNING: Current caller does not appear to be ${ROLE_NAME}."
  echo "       Caller: ${CALLER}"
  echo "       This script must be run from the jumpbox with the install role"
  echo "       instance profile attached. Results may not be accurate."
  echo ""
fi

# ── 2. Cross-account trust test ───────────────────────────────────────────────
echo ""
echo "── 2. Cross-account trust — live assume-role test"
echo "     Testing that each Promethium account trusts ${ROLE_NAME}..."
echo ""

for ACCT in 734236616923 308611924187; do
  case "$ACCT" in
    734236616923) PURPOSE="S3 Terraform state backend" ;;
    308611924187) PURPOSE="DynamoDB tenant lookup" ;;
  esac

  RESULT=$(aws sts assume-role \
    --role-arn "arn:aws:iam::${ACCT}:role/promethium-terraform-saas-assume-role" \
    --role-session-name "verify-crossaccount" \
    --duration-seconds 900 \
    --query 'Credentials.AccessKeyId' \
    --output text 2>&1)

  if echo "$RESULT" | grep -q "^ASIA\|^AKIA"; then
    check_pass "Account ${ACCT} (${PURPOSE}) trusts ${ROLE_NAME}"
  else
    check_fail "Account ${ACCT} (${PURPOSE})" "MISSING — Promethium must add ${ROLE_NAME} to the trust policy of promethium-terraform-saas-assume-role in account ${ACCT}. Error: ${RESULT}"
  fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Summary: ✅ $PASS passed | ❌ $FAIL failed"
echo "============================================================"
if [ $FAIL -gt 0 ]; then
  echo " ACTION REQUIRED: Promethium must update cross-account trust before terraform init."
else
  echo " Cross-account trust confirmed. Proceed with terraform init."
fi
echo ""
