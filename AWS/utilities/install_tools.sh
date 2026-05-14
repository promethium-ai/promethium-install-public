#!/bin/bash
# Promethium Intelligent Edge — Install VM tool setup
# Installs pinned versions of all tools required for the Promethium AWS deployment.
# Supports Amazon Linux 2023, Amazon Linux 2, Ubuntu 22.04, Ubuntu 24.04.
#
# Usage: bash install_tools.sh

set -e

TERRAFORM_VERSION="1.14.8"
KUBECTL_VERSION="v1.35.3"
HELM_VERSION="v3.20.1"

echo ""
echo "============================================================"
echo " Promethium IE — Tool Installation"
echo " Terraform: ${TERRAFORM_VERSION}"
echo " kubectl:   ${KUBECTL_VERSION}"
echo " Helm:      ${HELM_VERSION}"
echo " AWS CLI:   v2 (latest)"
echo "============================================================"
echo ""

# ── Detect package manager ────────────────────────────────────────────────────
if command -v dnf &> /dev/null; then
    PKG_MGR="dnf"
elif command -v yum &> /dev/null; then
    PKG_MGR="yum"
elif command -v apt-get &> /dev/null; then
    PKG_MGR="apt"
else
    echo "ERROR: Unsupported package manager. Install tools manually."
    exit 1
fi
echo "Package manager: ${PKG_MGR}"

# ── Terraform ─────────────────────────────────────────────────────────────────
echo ""
echo "── Installing Terraform ${TERRAFORM_VERSION}..."
if command -v terraform &> /dev/null && terraform -v | grep -q "$TERRAFORM_VERSION"; then
    echo "   Already installed."
else
    if [ "$PKG_MGR" = "apt" ]; then
        sudo apt-get update -q
        sudo apt-get install -y gnupg software-properties-common curl
        curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
        sudo apt-get update -q && sudo apt-get install -y terraform=${TERRAFORM_VERSION}-*
    else
        sudo ${PKG_MGR} install -y yum-utils
        sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
        sudo ${PKG_MGR} install -y terraform-${TERRAFORM_VERSION}
    fi
fi
terraform -v

# ── kubectl ───────────────────────────────────────────────────────────────────
echo ""
echo "── Installing kubectl ${KUBECTL_VERSION}..."
if command -v kubectl &> /dev/null && kubectl version --client 2>/dev/null | grep -q "${KUBECTL_VERSION#v}"; then
    echo "   Already installed."
else
    curl -sLO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
    sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
    rm -f kubectl
fi
kubectl version --client

# ── Helm ──────────────────────────────────────────────────────────────────────
echo ""
echo "── Installing Helm ${HELM_VERSION}..."
if command -v helm &> /dev/null && helm version --short 2>/dev/null | grep -q "${HELM_VERSION#v}"; then
    echo "   Already installed."
else
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash -s -- --version ${HELM_VERSION}
fi
helm version --short

# ── AWS CLI v2 ────────────────────────────────────────────────────────────────
echo ""
echo "── Installing AWS CLI v2..."
if command -v aws &> /dev/null; then
    echo "   Already installed: $(aws --version)"
else
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip -q awscliv2.zip
    sudo ./aws/install
    rm -rf aws awscliv2.zip
fi
aws --version

# ── Git ───────────────────────────────────────────────────────────────────────
echo ""
echo "── Installing Git..."
if command -v git &> /dev/null; then
    echo "   Already installed: $(git --version)"
else
    if [ "$PKG_MGR" = "apt" ]; then
        sudo apt-get install -y git
    else
        sudo ${PKG_MGR} install -y git
    fi
fi
git --version

# ── Python ────────────────────────────────────────────────────────────────────
echo ""
echo "── Installing Python..."
if command -v python3 &> /dev/null; then
    echo "   Already installed: $(python3 --version)"
else
    if [ "$PKG_MGR" = "apt" ]; then
        sudo apt-get install -y python3 python3-pip python3-venv
    else
        sudo ${PKG_MGR} install -y python3 python3-pip
    fi
fi
python3 --version

# ── Python venv + boto3 ───────────────────────────────────────────────────────
echo ""
echo "── Setting up Python venv with boto3..."
mkdir -p /tmp/venv
python3 -m venv /tmp/venv/.venv 2>/dev/null || true
/tmp/venv/.venv/bin/pip install --quiet boto3 2>/dev/null || pip3 install --quiet boto3 2>/dev/null || true
echo "   boto3 ready."

# ── SSM Agent ─────────────────────────────────────────────────────────────────
echo ""
echo "── Checking SSM Agent..."
if systemctl is-active --quiet amazon-ssm-agent 2>/dev/null; then
    echo "   SSM Agent is running."
elif command -v amazon-ssm-agent &> /dev/null; then
    sudo systemctl start amazon-ssm-agent
    sudo systemctl enable amazon-ssm-agent
    echo "   SSM Agent started."
else
    if [ "$PKG_MGR" != "apt" ]; then
        sudo ${PKG_MGR} install -y amazon-ssm-agent
        sudo systemctl start amazon-ssm-agent
        sudo systemctl enable amazon-ssm-agent
        echo "   SSM Agent installed and started."
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Installation complete. Installed versions:"
echo "   Terraform: $(terraform -v | head -1)"
echo "   kubectl:   $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"
echo "   Helm:      $(helm version --short)"
echo "   AWS CLI:   $(aws --version)"
echo "   Python:    $(python3 --version)"
echo "   Git:       $(git --version)"
echo "============================================================"
echo ""
