# Promethium Installation Public Repository

This repository contains tools and documentation for Promethium deployment verification and setup.

## IAM Setup Verification

Before deploying Promethium, customers must set up the required IAM roles and policies. Use the verification script to ensure your IAM setup is correct.

### Prerequisites

1. **AWS CLI configured** with credentials that have permissions to read IAM roles and policies
   ```
      {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "IAMVerificationScriptPermissions",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity",
                "iam:GetRole",
                "iam:ListAttachedRolePolicies", 
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:ListRolePolicies",
                "iam:GetRolePolicy",
                "iam:SimulatePrincipalPolicy"
            ],
            "Resource": "*"
        }
    ]
    }
```
3. **Python 3.6+** with boto3 installed: `pip install boto3`
4. **Required IAM roles created** according to your deployment configuration

### Quick Start

```bash
# Basic verification for Terraform-managed deployment
python verify_iam_setup.py --account-id 123456789012 --region us-east-1 --company-name acme \
  --iam-role-create true --aws-iam-oidc-enabled true

# Verification when you're providing your own IAM roles (iam_role_create=false)
python verify_iam_setup.py --account-id 123456789012 --region us-east-1 --company-name acme \
  --iam-role-create false --aws-iam-oidc-enabled true

# Verification when you're providing your own OIDC roles (aws_iam_oidc_enabled=false)
python verify_iam_setup.py --account-id 123456789012 --region us-east-1 --company-name acme \
  --iam-role-create true --aws-iam-oidc-enabled false

# Full verification for customer-managed deployment with simulation
python verify_iam_setup.py --account-id 123456789012 --region us-east-1 --company-name acme \
  --iam-role-create false --aws-iam-oidc-enabled false --simulate-installer true

# Verification with custom role ARNs (recommended for production deployments)
python verify_iam_setup.py --account-id 646322277713 --region us-east-1 --company-name promethium \
  --installer-role "arn:aws:iam::646322277713:role/PromethiumInstall" \
  --cluster-role "arn:aws:iam::646322277713:role/promethium-eks-cluster-role" \
  --iam-role-create false --aws-iam-oidc-enabled false --output json
```

### Required IAM Roles

The verification script checks for the following roles based on your deployment configuration:

#### 1. Installer Role (Always Required)
- **Default Name**: `PromethiumInstall`
- **Purpose**: Used by Terraform to deploy infrastructure
- **Trust Policy**: Must allow your deployment user/role to assume it
- **Required Permissions**: See `policy.json` for the installer user policy
- **Conditional Policy**: When Terraform creates roles, also requires `promethium-terraform-iam-policy`

#### 2. Core EKS Roles (Required when `iam_role_create=false`)
- **EKS Cluster Role**: `{company_name}-eks-cluster`
  - Trust Policy: `eks.amazonaws.com`
  - Managed Policy: `AmazonEKSClusterPolicy`
- **EKS Worker Role**: `{company_name}-eks-worker`
  - Trust Policy: `ec2.amazonaws.com`
  - Managed Policies: `AmazonEKSWorkerNodePolicy`, `AmazonEKS_CNI_Policy`, `AmazonEC2ContainerRegistryReadOnly`
- **Jumpbox Role**: `{company_name}-jumpbox-role` (if jumpbox enabled)
  - Trust Policy: `ec2.amazonaws.com`

#### 3. OIDC Roles (Required when `aws_iam_oidc_enabled=false`)
- **AWS Load Balancer Controller**: `{company_name}-lbcontroller-role`
- **AWS EFS CSI Driver**: `{company_name}-efscsi-role`
- **AWS EBS CSI Driver**: `{company_name}-ebscsi-role`
- **Cluster Autoscaler**: `{company_name}-eks-autoscaler-role`
- **PostgreSQL Backup**: `{company_name}-s3-access-role`
- **Trino**: `{company_name}-trino-oidc-role`

All OIDC roles must have trust policies configured for the EKS OIDC provider with appropriate service account conditions.

### Installer User Policy

Create an AWS IAM user with the permissions defined in `policy.json`. This user will be used to run Terraform and deploy the infrastructure.

### Command Line Options

```
--account-id          AWS Account ID (required)
--region             AWS Region (required)
--company-name       Company name for role naming (required)
--spec               Path to IAM requirements YAML file (default: specs/iam_requirements.yaml)

--installer-role     Installer role ARN or name
--cluster-role       EKS cluster role ARN or name
--worker-role        EKS worker role ARN or name
--jumpbox-role       Jumpbox role ARN or name

--aws-lb-controller-role    AWS LB Controller role ARN or name
--aws-efs-driver-role      AWS EFS CSI Driver role ARN or name
--aws-ebs-driver-role      AWS EBS CSI Driver role ARN or name
--aws-eks-autoscaler-role  Cluster Autoscaler role ARN or name
--pgbackup-role           PG Backup role ARN or name
--trino-role             Trino role ARN or name

--iam-role-create        Whether Terraform creates IAM roles (true/false, required)
--aws-iam-oidc-enabled   Whether Terraform manages OIDC roles (true/false, required)
--jumpbox-enabled        Whether jumpbox is enabled (true/false, default: true)

--simulate-installer     Enable/disable installer permission simulation (true/false)
--output-json           JSON output file (default: verify_iam_report.json)
--strict                Exit with non-zero code on any failures
--output                Output format: text (default) or json
--verbose               Enable verbose logging
--analyze-policies      Analyze attached policies for hardcoded values and unnecessary permissions
```

**Note**: All role parameters accept either role names (e.g., `PromethiumInstall`) or full ARNs (e.g., `arn:aws:iam::646322277713:role/PromethiumInstall`). Using ARNs is recommended for production deployments to avoid ambiguity.

### Troubleshooting

#### Common Issues

1. **Role not found**: Ensure the role exists and the naming matches the expected pattern
2. **Trust policy incorrect**: Verify the trust policy allows the correct principals
3. **Missing policies**: Check that all required managed policies are attached
4. **OIDC provider not configured**: Ensure the EKS OIDC provider is set up for OIDC roles

#### Getting Help

If the verification script reports errors:

1. Review the specific error messages
2. Check the AWS IAM console to verify role configuration
3. Ensure your AWS credentials have sufficient permissions to read IAM resources
4. Contact Promethium support with the verification output

### Example Output

**Text Format:**
```
[PASS] auth.identity: Using AWS identity
[PASS] installer.exists: Installer role found
[PASS] installer.simulate: Installer has required permissions
[PASS] eks.cluster.exists: EKS cluster role found
[PASS] eks.cluster.trust: Trust policy valid
[PASS] eks.cluster.policies: Required policies attached
[PASS] oidc.lbcontroller.exists: OIDC role for AWS Load Balancer Controller found
[PASS] oidc.lbcontroller.trust: OIDC trust policy valid for AWS Load Balancer Controller

Summary: 7 passed, 0 warnings, 0 failed (total 7)
```

**JSON Format (with --output json):**
```json
{
  "checks": [
    {
      "id": "auth.identity",
      "status": "PASS",
      "details": "Using AWS identity",
      "meta": {
        "account": "646322277713",
        "arn": "arn:aws:iam::646322277713:user/terraform-user"
      }
    },
    {
      "id": "installer.simulate",
      "status": "PASS", 
      "details": "Installer has required permissions",
      "meta": {
        "tested_actions": 23,
        "mode": "customer-managed manage-only"
      }
    }
  ]
}
```

### New Features

#### Enhanced Failure Analysis
The script now distinguishes between expected service-context failures and real permission issues:
- **Expected failures**: Actions requiring `iam:AWSServiceName` context (normal for policies with service conditions)
- **Real failures**: Actual missing permissions that need to be addressed

When simulation failures occur due to missing service context (like `iam:AWSServiceName`), these are now marked as "INFO" or "EXPECTED" rather than "FAIL", providing clearer guidance on what actually needs to be fixed.

#### Policy Analysis
Use `--analyze-policies` to review attached policies for:
- Hardcoded account IDs and regions that should be parameterized
- Unnecessary permissions that could be removed
- Generic policy templates are provided in `policy-templates/` directory

The policy analysis helps identify region-specific and account-specific hardcoding that prevents policies from being reusable across different AWS environments.

#### IAM Permission Simulation
The enhanced script now uses AWS IAM's `simulate_principal_policy` API to test actual permissions rather than just checking policy attachments. This provides more accurate validation of whether roles have the required permissions.

#### YAML-Based Specifications
Role requirements are now defined in `specs/iam_requirements.yaml`, making it easier to maintain and update requirements without modifying the script code.

#### Structured JSON Output
The script provides detailed JSON output with specific failure reasons, metadata, and structured reporting for integration with CI/CD pipelines.

#### Generic Policy Templates
The `policy-templates/` directory contains parameterized versions of common IAM policies with `${AWS_ACCOUNT_ID}` and `${AWS_REGION}` placeholders that can be customized for any AWS environment.
