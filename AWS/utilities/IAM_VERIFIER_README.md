# promethium-install-public

IAM Verification

This repo now includes a read-only verification script that checks whether the required AWS IAM roles, policies, trust policies, and instance profiles are correctly configured for Promethium IE deployments.

Prerequisites
- Python 3.9+
- AWS credentials configured on the install box (environment or profile) with at least:
  - iam:Get*, iam:List*
  - sts:GetCallerIdentity
  - iam:SimulatePrincipalPolicy (optional but recommended)

Setup
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Usage
Additional flags
- --aws-iam-oidc-enabled:
  - true: Terraform-managed OIDC roles (skip validating customer-supplied OIDC role ARNs; logs a note that OIDC roles are Terraform-managed)
  - false: Customer-managed OIDC roles (expects OIDC role ARNs via flags and validates trust/policies; optionally match provider with --oidc-issuer-url)
- Terraform-created IAM mode (Terraform manages the IAM roles; script validates the installer role and modes). By default, installer permission simulation runs in this mode unless you explicitly disable it with --simulate-installer false:
```
python scripts/verify_iam.py \
  --account-id 111122223333 --region us-east-1 \
  --iam-role-create true --aws-iam-oidc-enabled true --jumpbox-enabled false \
  --terraform-assume-role-arn arn:aws:iam::111122223333:role/promethium-terraform-aws-provider-ie-role \
  --simulate-installer true
```

- Customer-managed IAM mode default: installer simulation is skipped unless you explicitly enable it with --simulate-installer true.
- Customer-supplied IAM mode (provide ARNs for roles you created). By default, installer simulation is OFF in this mode; enable it with --simulate-installer true if desired:
```
python scripts/verify_iam.py \
  --account-id 111122223333 --region us-east-1 --profile default \
  --iam-role-create false --aws-iam-oidc-enabled false --jumpbox-enabled true \
  --terraform-assume-role-arn arn:aws:iam::111122223333:role/InstallerRole \
  --cluster-role-arn arn:aws:iam::111122223333:role/MyEKSClusterRole \
  --worker-role-arn arn:aws:iam::111122223333:role/MyEKSWorkerRole \
  --jumpbox-instance-profile-name MyJumpboxRole \
  --aws-lb-controller-role-arn arn:aws:iam::111122223333:role/MyAWSLBControllerRole \
  --aws-eks-autoscaler-role-arn arn:aws:iam::111122223333:role/MyAWSEKSAutoScalerRole \
  --aws-efs-driver-role-arn arn:aws:iam::111122223333:role/MyAWSEFSCSIDriverRole \
  --aws-ebs-driver-role-arn arn:aws:iam::111122223333:role/MyAWSEBSCSIDriverRole \
  --pgbackup-cronjob-role-arn arn:aws:iam::111122223333:role/MyPGBackupCronJobRole \
  --trino-oidc-role-arn arn:aws:iam::111122223333:role/MyTrinoRole \
  --oidc-issuer-url https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE \
  --simulate-installer false
```

Outputs
- Human-readable summary to stdout
- Machine-readable JSON written to verify_iam_report.json
- Non-zero exit code when --strict is used and any required check fails
- Failure messages specify the exact policy or action where possible. For simulation failures, the output lists each failed action and any matched statements (including SourcePolicyId) that contributed to the decision.
Spec
Note on worker KMS policy
- The EKS worker KMS requirement can be satisfied by either:
  - an inline role policy whose name contains "eks-kms-access-policy", or
  - an attached managed policy whose name contains "eks-kms-access-policy".
- The verifier reads the policy document and checks for these actions:
  - kms:Encrypt, kms:Decrypt, kms:ReEncrypt*, kms:GenerateDataKey*, kms:DescribeKey
Spec shapes supported for worker KMS
- Preferred shape (suffix + actions at worker level):
  eks:
    worker:
      required_attached_suffixes:
        - eks-kms-access-policy
      actions:
        - kms:Encrypt
        - kms:Decrypt
        - kms:ReEncrypt*
        - kms:GenerateDataKey*
        - kms:DescribeKey
- Backward compatible shape (inline entries with name_contains and actions, optional accept_managed):
  eks:
    worker:
      required_inline:
        - name_contains: eks-kms-access-policy
          actions:
            - kms:Encrypt
            - kms:Decrypt
            - kms:ReEncrypt*
            - kms:GenerateDataKey*
            - kms:DescribeKey
In both cases, the verifier accepts either an inline policy or an attached managed policy whose name contains the given suffix and validates the actions.
- If the check fails, either attach the managed policy (e.g., promethium-eks-kms-access-policy) to the worker role or add an inline policy with the required actions.
Customer-managed simulation behavior
- When --iam-role-create false, the verifier skips installer permission simulation by default.
- If you explicitly enable simulation with --simulate-installer true in this mode, the verifier simulates a manage-only subset:
  - It excludes IAM creation/attachment/inline policy/instance profile creation actions (e.g., iam:CreateRole, iam:AttachRolePolicy, iam:PutRolePolicy, iam:CreateInstanceProfile, iam:AddRoleToInstanceProfile).
  - All other actions in the installer.simulate_actions spec are still tested.
- This lets you validate operational permissions without requiring IAM creation rights when roles are pre-created.

- The script reads specs/iam_requirements.yaml for expected principals and policy suffixes. You can point to a custom file with --spec.
Forbidden actions (optional)
- You can guide least-privilege without blocking installs by declaring forbidden_actions under the worker spec. When present, the verifier will emit WARN if any of those actions appear in the matched inline or attached managed policy for the worker KMS requirement. This does not affect PASS/FAIL for required actions.

Example:
eks:
  worker:
    required_attached_suffixes:
      - promethium-eks-kms-access-policy
    actions:
      - kms:Encrypt
      - kms:Decrypt
      - kms:ReEncrypt*
      - kms:GenerateDataKey*
      - kms:DescribeKey
    forbidden_actions:
      - kms:CreateGrant
      - kms:ListGrants
      - kms:RevokeGrant

Typical output when forbidden actions are present:
[WARN] eks.worker.forbidden.managed.promethium-eks-kms-access-policy: Policy includes forbidden actions
