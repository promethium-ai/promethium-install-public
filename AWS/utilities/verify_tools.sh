#!/bin/bash
# Pre-install verification: checks tool versions on the install VM
# Run this from the jumpbox before starting the terraform deployment.
#
# Usage: ./verify_tools.sh

REQUIRED_TERRAFORM="1.10"   # 1.10+ required for use_lockfile in S3 backend
REQUIRED_KUBECTL="1.29"
REQUIRED_HELM="3.12"
REQUIRED_AWSCLI="2"

PASS=0; FAIL=0; WARN=0

check_pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
check_fail() { echo "  ❌ $1 — $2"; FAIL=$((FAIL+1)); }
check_warn() { echo "  ⚠️  $1 — $2"; WARN=$((WARN+1)); }

# Compare semantic versions: returns 0 if $1 >= $2
version_gte() {
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

echo ""
echo "============================================================"
echo " Promethium IE — Tool Version Verification"
echo " Run from the install VM (jumpbox) before terraform deploy"
echo "============================================================"

# ── Terraform ─────────────────────────────────────────────────────────────────
echo ""
echo "── Terraform (minimum ${REQUIRED_TERRAFORM}.x)"
if command -v terraform &> /dev/null; then
  TF_VER=$(terraform -v 2>/dev/null | head -1 | sed 's/Terraform v//')
  if version_gte "$TF_VER" "$REQUIRED_TERRAFORM"; then
    check_pass "Terraform ${TF_VER}"
    # Warn if below our recommended version
    if ! version_gte "$TF_VER" "1.14"; then
      check_warn "Terraform ${TF_VER} meets minimum but recommended is 1.14+" "Upgrade when possible"
    fi
  else
    check_fail "Terraform ${TF_VER}" "Below minimum ${REQUIRED_TERRAFORM} — versions below 1.10 do not support 'use_lockfile' in the S3 backend and will fail on terraform init. Upgrade:
      sudo yum install -y terraform-1.14.8   # Amazon Linux
      sudo apt-get install terraform=1.14.8-* # Ubuntu"
  fi
else
  check_fail "Terraform not found" "Install:
      sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
      sudo yum install -y terraform-1.14.8"
fi

# ── kubectl ───────────────────────────────────────────────────────────────────
echo ""
echo "── kubectl (minimum ${REQUIRED_KUBECTL}.x)"
if command -v kubectl &> /dev/null; then
  KUBECTL_VER=$(kubectl version --client 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/v//')
  if version_gte "$KUBECTL_VER" "$REQUIRED_KUBECTL"; then
    check_pass "kubectl v${KUBECTL_VER}"
    # Warn if significantly behind recommended
    if ! version_gte "$KUBECTL_VER" "1.33"; then
      check_warn "kubectl v${KUBECTL_VER} is behind recommended v1.35.3" "Upgrade for best compatibility with EKS 1.33+:
      curl -sLO https://dl.k8s.io/release/v1.35.3/bin/linux/amd64/kubectl
      sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl"
    fi
  else
    check_fail "kubectl v${KUBECTL_VER}" "Below minimum ${REQUIRED_KUBECTL}. Upgrade:
      curl -sLO https://dl.k8s.io/release/v1.35.3/bin/linux/amd64/kubectl
      sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl"
  fi
else
  check_fail "kubectl not found" "Install:
      curl -sLO https://dl.k8s.io/release/v1.35.3/bin/linux/amd64/kubectl
      sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl"
fi

# ── Helm ──────────────────────────────────────────────────────────────────────
echo ""
echo "── Helm (minimum ${REQUIRED_HELM}.x)"
if command -v helm &> /dev/null; then
  HELM_VER=$(helm version --short 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | sed 's/v//')
  if version_gte "$HELM_VER" "$REQUIRED_HELM"; then
    check_pass "Helm v${HELM_VER}"
  else
    check_fail "Helm v${HELM_VER}" "Below minimum ${REQUIRED_HELM} — Promethium Helm charts require 3.12+. Upgrade:
      curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash -s -- --version v3.20.1"
  fi
else
  check_fail "Helm not found" "Install:
      curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash -s -- --version v3.20.1"
fi

# ── AWS CLI ───────────────────────────────────────────────────────────────────
echo ""
echo "── AWS CLI (minimum v${REQUIRED_AWSCLI})"
if command -v aws &> /dev/null; then
  AWSCLI_VER=$(aws --version 2>/dev/null | grep -oE 'aws-cli/[0-9]+' | sed 's/aws-cli\///')
  if version_gte "$AWSCLI_VER" "$REQUIRED_AWSCLI"; then
    AWSCLI_FULL=$(aws --version 2>/dev/null | awk '{print $1}' | sed 's/aws-cli\///')
    check_pass "AWS CLI ${AWSCLI_FULL}"
  else
    check_fail "AWS CLI v${AWSCLI_VER}" "v1 detected — must use v2. Install:
      curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip
      unzip awscliv2.zip && sudo ./aws/install --update"
  fi
else
  check_fail "AWS CLI not found" "Install:
      curl https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o awscliv2.zip
      unzip awscliv2.zip && sudo ./aws/install"
fi

# ── Python ────────────────────────────────────────────────────────────────────
echo ""
echo "── Python (minimum 3.9)"
if command -v python3 &> /dev/null; then
  PY_VER=$(python3 --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  if version_gte "$PY_VER" "3.9"; then
    check_pass "Python ${PY_VER}"
  else
    check_fail "Python ${PY_VER}" "Below minimum 3.9. Upgrade via package manager."
  fi
else
  check_fail "python3 not found" "Install: sudo yum install -y python3"
fi

# ── Git ───────────────────────────────────────────────────────────────────────
echo ""
echo "── Git"
if command -v git &> /dev/null; then
  GIT_VER=$(git --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  check_pass "Git ${GIT_VER}"
else
  check_fail "Git not found" "Install: sudo yum install -y git"
fi

# ── AWS identity check ────────────────────────────────────────────────────────
echo ""
echo "── AWS identity (confirms instance profile is attached)"
CALLER=$(aws sts get-caller-identity --output json 2>/dev/null)
if [ -n "$CALLER" ]; then
  CALLER_ARN=$(echo "$CALLER" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])" 2>/dev/null)
  ACCOUNT=$(echo "$CALLER" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])" 2>/dev/null)
  check_pass "Running as: ${CALLER_ARN}"
  echo "     Account: ${ACCOUNT}"
  echo ""
  echo "     Verify this is the correct deployment role before proceeding."
else
  check_fail "AWS identity" "Cannot get caller identity — instance profile may not be attached or role has no permissions"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Summary: ✅ $PASS passed | ❌ $FAIL failed | ⚠️  $WARN warnings"
echo "============================================================"
if [ $FAIL -gt 0 ]; then
  echo " ACTION REQUIRED: Fix failures above before running terraform."
  echo " Run the upgrade commands shown, then re-run this script."
elif [ $WARN -gt 0 ]; then
  echo " Warnings present — upgrades recommended but not blocking."
else
  echo " All tools verified. Ready to proceed with terraform deploy."
fi
echo ""
