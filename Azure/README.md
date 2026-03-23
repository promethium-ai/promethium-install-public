# Promethium Intelligent Edge Installation (Azure)

The following steps describe how to deploy a secure Promethium Intelligent Edge on Azure. It will deploy an Azure Kubernetes Service (AKS) cluster within which the Promethium application services are deployed, fronted by an Azure Application Gateway.

---

## 1. Environment Prerequisites

| Item | Description |
|------|-------------|
| Azure Subscription | The Azure subscription where the Promethium Intelligent Edge will be deployed |
| Region | Azure region for deployment (e.g., `eastus`, `centralus`) |
| VNet | An existing VNet of at least /22, or allow Terraform to create one |
| 3 Subnets | Three dedicated subnets — see subnet requirements below |
| Outbound Internet Access | AKS nodes require HTTPS access to the Promethium Control Plane and image registry |
| Company Name | A `<company_name>` variable used throughout the deployment. Agree on this value with your Promethium technical representative before starting |
| GitHub PAT | A GitHub Personal Access Token with `read:packages` scope to pull private Terraform modules and Helm charts |
| AWS Credentials | Access key and secret for the IAM user permitted to assume the Promethium ECR role (provided by Promethium) |

### Subnet Requirements

Three subnets are required, each in your VNet:

| Subnet Key | Purpose | Minimum Size |
|------------|---------|--------------|
| `aks_subnet` | AKS node pool | /24 |
| `appgw_subnet` | Azure Application Gateway (dedicated — Azure platform requirement) | /27 |
| `bastion_subnet` | Jumpbox / Bastion Host | /27 |

If you are not deploying a Jumpbox (`install_jumpbox = false`), the `bastion_subnet` still needs to exist but will remain unused.

> **Note:** If you allow Terraform to create the VNet (`install_vnet = true`), all three subnets are created automatically.

---

## 2. Azure Roles & Privileges

A Service Principal (SP) is used to run the Terraform deployment. It requires:

| Role | Scope | Purpose |
|------|-------|---------|
| Contributor | Resource Group | Create and manage all Azure resources |
| User Access Administrator | Resource Group | Create the 7 RBAC role assignments that allow AKS to manage the App Gateway, Key Vault, and Storage |

### Creating the Service Principal

```bash
az ad sp create-for-rbac \
  --name "<company_name>-promethium-sp" \
  --role Contributor \
  --scopes /subscriptions/<subscription_id>/resourceGroups/<resource_group_name>
```

### Granting User Access Administrator

This must be run by an Azure Owner whose role assignment has no ABAC conditions:

```bash
az role assignment create \
  --assignee <sp_client_id> \
  --role "User Access Administrator" \
  --scope /subscriptions/<subscription_id>/resourceGroups/<resource_group_name>
```

> **Note:** This step is blocked if the Owner role has ABAC conditions attached. In that case, ask another Owner without ABAC restrictions to run the command.

---

## 3. Terraform State Backend

Terraform state should be stored in an Azure Storage Account. This can be in the Promethium subscription (managed by Promethium) or in the customer subscription. Create the backend resources:

```bash
# Create resource group for Terraform state
az group create --name <tf_state_rg> --location <region>

# Create storage account
az storage account create \
  --name <tf_state_storage_account> \
  --resource-group <tf_state_rg> \
  --location <region> \
  --sku Standard_LRS

# Create container
az storage container create \
  --name terraform-backend \
  --account-name <tf_state_storage_account>
```

---

## 4. Installation VM

Terraform must be run from a VM inside the customer VNet. The VM requires:

- Ubuntu 22.04 LTS
- Public IP with NSG rule allowing SSH from your IP only
- The following tools installed: `terraform`, `kubectl`, `helm`, `az`, `aws`, `git`

### Tool Installation

```bash
# Terraform
sudo apt-get install -y gnupg software-properties-common
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install -y terraform

# kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# Python venv (required by Terraform module scripts)
sudo apt-get install -y python3-venv python3-pip
mkdir -p /tmp/venv
python3 -m venv /tmp/venv/.venv
source /tmp/venv/.venv/bin/activate
pip install boto3
deactivate
```

---

## 5. Configuration

### Clone the wrapper repository

```bash
git clone https://github.com/promethium-ai/promethium-internal-ie-azure.git
cd promethium-internal-ie-azure
```

### Configure git for private module access

```bash
git config --global url."https://${GH_TOKEN}@github.com/".insteadOf "https://github.com/"
```

### Update `backend.tf`

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "<tf_state_rg>"
    storage_account_name = "<tf_state_storage_account>"
    container_name       = "terraform-backend"
    key                  = "<company_name>/terraform.tfstate"
  }
}
```

### Create `terraform.tfvars`

**For existing VNet (customer brings their own):**

```hcl
env                  = "<env>"           # e.g. qa, prod
location             = "<region>"        # e.g. eastus
resource_group_name  = "<rg_name>"
company_name         = "<company_name>"
subscription_id      = "<subscription_id>"
promethium_image_tag = "<image_tag>"     # provided by Promethium

# Existing VNet
install_vnet             = false
create_resource_group    = false
vnet_name                = "<vnet_name>"
vnet_resource_group_name = "<vnet_rg_name>"

subnet_names = {
  aks_subnet     = "<aks_subnet_name>"
  appgw_subnet   = "<appgw_subnet_name>"
  bastion_subnet = "<bastion_subnet_name>"
}

# App Gateway
appgw_private_ip = "<ip_within_appgw_subnet>"

# AKS networking (must be outside VNet CIDR)
aks_service_cidr   = "<service_cidr>"   # e.g. 10.x.x.0/24
aks_service_dns_ip = "<dns_ip>"         # first usable IP in service_cidr
```

**For new VNet (Terraform creates everything):**

```hcl
env                  = "<env>"
location             = "<region>"
resource_group_name  = "<rg_name>"
company_name         = "<company_name>"
subscription_id      = "<subscription_id>"
promethium_image_tag = "<image_tag>"

install_vnet            = true
create_resource_group   = true
vnet_address_space      = "10.x.x.0/22"
aks_subnet_cidr         = "10.x.1.0/24"
application_subnet_cidr = "10.x.2.0/24"
appgw_subnet_cidr       = "10.x.3.0/24"

appgw_private_ip   = "10.x.3.10"
aks_service_cidr   = "10.x.4.0/24"
aks_service_dns_ip = "10.x.4.10"
```

---

## 6. Deployment

### Set environment variables

```bash
# Azure Service Principal
export ARM_CLIENT_ID="<sp_client_id>"
export ARM_CLIENT_SECRET="<sp_client_secret>"
export ARM_SUBSCRIPTION_ID="<subscription_id>"
export ARM_TENANT_ID="<tenant_id>"

# AWS credentials (for ECR image pulls — provided by Promethium)
export AWS_ACCESS_KEY_ID="<aws_access_key>"
export AWS_SECRET_ACCESS_KEY="<aws_secret_key>"

# GitHub tokens
export GH_TOKEN="<github_pat>"
export GHCR_TOKEN="<ghcr_token>"
```

### Login to Helm OCI registry

```bash
helm registry login ghcr.io -u promethium-ai --password-stdin <<< "$GHCR_TOKEN"
```

### Initialise Terraform

```bash
terraform init -upgrade
```

### Phase 1 — Azure Infrastructure

Deploys AKS, App Gateway, Key Vault, Storage Accounts, and RBAC role assignments. The `skip_k8s_config=true` flag is required on first run because the Kubernetes provider cannot initialise until AKS exists.

```bash
terraform apply \
  -target=module.azure \
  -var="ghcr_token=$GHCR_TOKEN" \
  -var="skip_k8s_config=true"
```

### Phase 2 — Certificate Manager

```bash
terraform apply \
  -target=module.promethium.module.cert_manager \
  -var="ghcr_token=$GHCR_TOKEN"
```

### Phase 3 — Full Deployment

```bash
terraform apply -var="ghcr_token=$GHCR_TOKEN"
```

---

## 7. Verification

```bash
# Get AKS credentials
az aks get-credentials \
  --resource-group <rg_name> \
  --name <company_name>-ie-cluster \
  --overwrite-existing

# Check all pods are running
kubectl get pods -n intelligentedge

# Check ingress
kubectl get ingress -n intelligentedge
```

---

## 8. Teardown

```bash
# Destroy Postgres first
terraform destroy \
  -target=module.promethium.module.postgres \
  -var="ghcr_token=$GHCR_TOKEN"

# Destroy everything else
terraform destroy -var="ghcr_token=$GHCR_TOKEN"
```
