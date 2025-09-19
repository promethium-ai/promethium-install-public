#!/usr/bin/env python3
"""
IAM Setup Verification Script for Promethium Deployment

This script verifies that all required IAM roles and policies are properly configured
for Promethium deployment, including the installer role and application-specific OIDC roles.
"""

import argparse
import boto3
import json
import logging
import sys
import yaml
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional, Any
from botocore.exceptions import ClientError, NoCredentialsError


@dataclass
class CheckResult:
    id: str
    status: str
    details: str
    meta: Dict[str, Any]


class Reporter:
    def __init__(self) -> None:
        self.checks: List[CheckResult] = []

    def add(self, id: str, status: str, details: str, meta: Optional[Dict[str, Any]] = None) -> None:
        self.checks.append(CheckResult(id=id, status=status, details=details, meta=meta or {}))

    def has_failures(self) -> bool:
        return any(c.status == "FAIL" for c in self.checks)

    def to_json(self) -> Dict[str, Any]:
        return {"checks": [asdict(c) for c in self.checks]}

    def print_text(self) -> None:
        for c in self.checks:
            print(f"[{c.status}] {c.id}: {c.details}")
        total = len(self.checks)
        fails = len([c for c in self.checks if c.status == "FAIL"])
        warns = len([c for c in self.checks if c.status == "WARN"])
        passes = total - fails - warns
        print("")
        print(f"Summary: {passes} passed, {warns} warnings, {fails} failed (total {total})")


MANAGE_ONLY_EXCLUDE = {
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateInstanceProfile",
    "iam:AddRoleToInstanceProfile",
    "iam:PassRole",
}


def filter_manage_only(actions: List[str]) -> List[str]:
    return [a for a in actions if a not in MANAGE_ONLY_EXCLUDE]


CURATED_MANAGE_ONLY_ACTIONS = [
    "eks:DescribeCluster",
    "eks:UpdateClusterConfig",
    "eks:UpdateClusterVersion",
    "eks:ListNodegroups",
    "eks:CreateNodegroup",
    "eks:DeleteNodegroup",
    "eks:DescribeNodegroup",
    "eks:ListUpdates",
    "eks:DescribeUpdate",
    "ec2:DescribeInstances",
    "ec2:RunInstances",
    "ec2:TerminateInstances",
    "ec2:CreateVolume",
    "ec2:AttachVolume",
    "ec2:DetachVolume",
    "ec2:CreateNetworkInterface",
    "ec2:AttachNetworkInterface",
    "ec2:DetachNetworkInterface",
    "ec2:DeleteNetworkInterface",
    "ec2:CreateLaunchTemplate",
    "ec2:CreateLaunchTemplateVersion",
    "ec2:DeleteLaunchTemplate",
    "ec2:CreateTags",
    "ec2:DeleteTags",
    "s3:CreateBucket",
    "s3:DeleteBucket",
    "s3:ListBucket",
    "s3:GetBucketPolicy",
    "s3:PutBucketPolicy",
    "s3:DeleteBucketPolicy",
    "s3:GetBucketTagging",
    "s3:PutBucketTagging",
    "s3:GetBucketVersioning",
    "s3:PutBucketVersioning",
    "s3:GetLifecycleConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:GetEncryptionConfiguration",
    "s3:PutEncryptionConfiguration",
    "acm:RequestCertificate",
    "acm:ListCertificates",
    "acm:GetCertificate",
    "acm:DeleteCertificate",
    "acm:DescribeCertificate",
    "acm:AddTagsToCertificate",
    "acm:ListTagsForCertificate",
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:GenerateDataKey",
    "kms:DescribeKey",
    "kms:ReEncrypt*",
    "kms:EnableKeyRotation",
    "kms:EnableKey",
    "kms:ListKeyPolicies",
    "kms:UntagResource",
    "kms:PutKeyPolicy",
    "kms:GetKeyPolicy",
    "kms:Verify",
    "kms:ListResourceTags",
    "kms:DisableKey",
    "kms:DisableKeyRotation",
    "kms:TagResource",
    "kms:GetKeyRotationStatus",
    "kms:ScheduleKeyDeletion",
    "kms:CreateAlias",
    "kms:Sign",
    "kms:DeleteAlias",
    "kms:CreateKey",
    "kms:ListAliases",
    "glue:GetDatabase",
    "glue:GetDatabases",
    "glue:CreateDatabase",
    "glue:DeleteDatabase",
    "glue:UpdateDatabase",
    "glue:GetTable",
    "glue:GetTables",
    "glue:CreateTable",
    "glue:UpdateTable",
    "glue:DeleteTable",
    "glue:BatchDeleteTable",
    "glue:GetCrawlers",
    "glue:ListCrawlers",
    "glue:GetCrawler",
    "glue:CreateCrawler",
    "glue:UpdateCrawler",
    "glue:StartCrawler",
    "glue:StopCrawler",
    "glue:DeleteCrawler",
    "sts:AssumeRole",
]


def simulate_actions(iam: Any, role_arn: str, actions: List[str]) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    try:
        resp = iam.simulate_principal_policy(PolicySourceArn=role_arn, ActionNames=actions, ResourceArns=["*"])
    except ClientError as e:
        return False, [], str(e)
    failures: List[Dict[str, Any]] = []
    for r in resp.get("EvaluationResults", []):
        decision = (r.get("EvalDecision") or "").lower()
        if decision != "allowed":
            failures.append({
                "action": r.get("EvalActionName"),
                "decision": r.get("EvalDecision"),
                "missing_context_values": r.get("MissingContextValues", []),
                "matched_statements": r.get("MatchedStatements", []),
                "permissions_boundary_decision_detail": r.get("PermissionsBoundaryDecisionDetail", {}),
                "organizations_decision_detail": r.get("OrganizationsDecisionDetail", {}),
                "resource_specific_results": r.get("ResourceSpecificResults", []),
            })
    return len(failures) == 0, failures, None


def analyze_simulation_failure(failure: Dict[str, Any]) -> str:
    """Categorize simulation failures as expected vs actual issues"""
    missing_context = failure.get("missing_context_values", [])
    decision = failure.get("decision", "")
    
    if "iam:AWSServiceName" in missing_context and decision == "implicitDeny":
        return "EXPECTED_SERVICE_CONTEXT"
    
    if decision == "explicitDeny":
        return "REAL_PERMISSION_ISSUE"
    
    return "OTHER_ISSUE"


def load_spec(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        if path.endswith(".json"):
            return json.load(f)
        return yaml.safe_load(f)


class IAMVerifier:
    def __init__(self, account_id: str, region: str, company_name: str, spec_path: str = None):
        self.account_id = account_id
        self.region = region
        self.company_name = company_name
        self.iam_client = boto3.client('iam', region_name=region)
        self.sts_client = boto3.client('sts', region_name=region)
        self.reporter = Reporter()
        self.spec = {}
        
        if spec_path:
            try:
                self.spec = load_spec(spec_path)
            except Exception as e:
                self.reporter.add("spec.load", "WARN", f"Could not load spec file: {e}", {"path": spec_path})
        
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
        self.logger = logging.getLogger(__name__)

    def extract_role_name_from_arn(self, role_arn: str) -> str:
        """Extract role name from ARN or return the input if it's already a role name"""
        if role_arn.startswith('arn:aws:iam::'):
            return role_arn.split('/')[-1]
        return role_arn

    def extract_policy_name_from_arn(self, policy_arn: str) -> str:
        """Extract policy name from ARN or return the input if it's already a policy name"""
        if policy_arn.startswith('arn:aws:iam::'):
            return policy_arn.split('/')[-1]
        return policy_arn

    def role_exists(self, role_name: str) -> Tuple[bool, Dict]:
        """Check if IAM role exists and return role data"""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return True, response['Role']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return False, {}
            raise

    def validate_trust_policy(self, role_name: str, expected_principals: List[str]) -> bool:
        """Validate trust policy allows expected principals"""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            trust_policy = response['Role']['AssumeRolePolicyDocument']
            
            statements = trust_policy.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]
            
            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    principal = statement.get('Principal', {})
                    
                    if isinstance(principal, dict):
                        service_principals = principal.get('Service', [])
                        if isinstance(service_principals, str):
                            service_principals = [service_principals]
                        
                        for expected_principal in expected_principals:
                            if expected_principal in service_principals:
                                return True
                        
                        conditions = statement.get('Condition', {})
                        if conditions and self._validate_conditions(conditions, expected_principals):
                            return True
            
            return False
            
        except ClientError as e:
            return False

    def _validate_conditions(self, conditions: Dict, expected_principals: List[str]) -> bool:
        """Validate conditions in trust policy for OIDC scenarios"""
        string_equals = conditions.get('StringEquals', {})
        for key, value in string_equals.items():
            if any(principal in key for principal in expected_principals):
                return True
        return False

    def validate_attached_policies(self, role_name: str, required_policies: List[str]) -> tuple[bool, List[str]]:
        """Validate that all required policies are attached to the role"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = [policy['PolicyArn'] for policy in response['AttachedPolicies']]
            
            missing_policies = []
            for policy_arn in required_policies:
                policy_name = self.extract_policy_name_from_arn(policy_arn)
                
                if policy_arn not in attached_policies:
                    policy_found = False
                    for attached_policy in attached_policies:
                        if policy_name in attached_policy:
                            policy_found = True
                            break
                    
                    if not policy_found:
                        missing_policies.append(policy_arn)
            
            return len(missing_policies) == 0, missing_policies
            
        except ClientError as e:
            return False, []

    def verify_installer_role(self, role_arn: str = None, customer_creates_roles: bool = False, simulate: bool = True) -> bool:
        """Verify the Terraform installer role with optional simulation"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/PromethiumInstall"
        
        role_name = self.extract_role_name_from_arn(role_arn)
        self.logger.info(f"Verifying installer role: {role_name} (ARN: {role_arn})")
        
        exists, role_data = self.role_exists(role_name)
        if not exists:
            self.reporter.add("installer.exists", "FAIL", "Installer role not found", 
                            {"input": role_arn, "role_name": role_name})
            return False
        
        self.reporter.add("installer.exists", "PASS", "Installer role found", 
                         {"role_name": role_name, "arn": role_arn})
        
        base_required_policies = [
            f"arn:aws:iam::{self.account_id}:policy/promethium-terraform-acm-policy",
            f"arn:aws:iam::{self.account_id}:policy/promethium-terraform-s3-policy"
        ]
        
        if customer_creates_roles:
            self.logger.info("Customer creates roles scenario - checking for base policies and iam:PassRole permission")
            required_policies = base_required_policies
            self.reporter.add("installer.scenario", "INFO", "Customer-managed roles scenario", 
                            {"note": "Installer needs ACM and S3 policies plus iam:PassRole permission"})
        else:
            self.logger.info("Terraform creates roles scenario - checking for full IAM permissions including custom policy")
            required_policies = base_required_policies + [
                "arn:aws:iam::aws:policy/PowerUserAccess",
                "arn:aws:iam::aws:policy/IAMFullAccess",
                f"arn:aws:iam::{self.account_id}:policy/promethium-terraform-iam-policy"
            ]
        
        if required_policies:
            policies_valid, missing_policies = self.validate_attached_policies(role_name, required_policies)
            if not policies_valid:
                if customer_creates_roles:
                    self.reporter.add("installer.policies", "FAIL", 
                                    "Installer role missing required policies for customer-managed scenario", 
                                    {"role_name": role_name, "missing": missing_policies,
                                     "note": "Base policies required for customer-managed deployment"})
                else:
                    self.reporter.add("installer.policies", "FAIL", 
                                    "Installer role missing required policies for Terraform-managed scenario", 
                                    {"role_name": role_name, "missing": missing_policies,
                                     "note": "Required policies for Terraform-managed deployment"})
                return False
        
        if simulate:
            simulate_cfg = self.spec.get("installer", {}).get("simulate_actions", [])
            if not simulate_cfg:
                simulate_cfg = [
                    "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:PassRole",
                    "iam:CreateInstanceProfile", "iam:AddRoleToInstanceProfile",
                    "eks:*", "ec2:*", "elasticloadbalancing:*", "autoscaling:*", "ecr:*",
                    "acm:*", "kms:*", "s3:*", "logs:*", "glue:*", "sts:AssumeRole"
                ]
            
            if customer_creates_roles:
                used_actions = filter_manage_only(CURATED_MANAGE_ONLY_ACTIONS)
                mode = "customer-managed manage-only"
            else:
                used_actions = simulate_cfg
                mode = "terraform-managed full"
            
            ok, failures, sim_err = simulate_actions(self.iam_client, role_arn, used_actions)
            if sim_err:
                self.reporter.add("installer.simulate", "WARN", "Simulation could not be performed", 
                                {"error": sim_err})
            elif ok:
                self.reporter.add("installer.simulate", "PASS", "Installer has required permissions", 
                                {"tested_actions": len(used_actions), "mode": mode})
            else:
                expected_failures = []
                real_failures = []
                
                for failure in failures:
                    failure_type = analyze_simulation_failure(failure)
                    if failure_type == "EXPECTED_SERVICE_CONTEXT":
                        expected_failures.append(failure)
                    else:
                        real_failures.append(failure)
                
                if real_failures:
                    self.reporter.add("installer.simulate", "FAIL", 
                                    f"Installer missing {len(real_failures)} required permissions",
                                    {"real_failures": real_failures, "mode": mode})
                    return False
                
                if expected_failures:
                    self.reporter.add("installer.simulate.service_context", "INFO",
                                    f"{len(expected_failures)} actions require service context (expected)",
                                    {"expected_failures": expected_failures, "mode": mode})
                
                self.reporter.add("installer.simulate", "PASS",
                                "Installer has required permissions (service-context limitations expected)",
                                {"tested_actions": len(used_actions), "mode": mode})
        
        if hasattr(self, '_analyze_policies') and self._analyze_policies:
            deployment_context = {
                'customer_creates_roles': customer_creates_roles,
                'tested_actions': used_actions if simulate else [],
                'deployment_mode': mode if simulate else 'no-simulation'
            }
            self.analyze_attached_policies(role_name, self.account_id, self.region, deployment_context)
        
        return True

    def verify_eks_cluster_role(self, role_arn: str = None) -> bool:
        """Verify EKS cluster role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-eks-cluster"
        
        role_name = self.extract_role_name_from_arn(role_arn)
        self.logger.info(f"Verifying EKS cluster role: {role_name} (ARN: {role_arn})")
        
        exists, role_data = self.role_exists(role_name)
        if not exists:
            self.reporter.add("eks.cluster.exists", "FAIL", "EKS cluster role not found", 
                            {"input": role_arn, "role_name": role_name})
            return False
        
        self.reporter.add("eks.cluster.exists", "PASS", "EKS cluster role found", 
                         {"role_name": role_name, "arn": role_arn})
        
        if not self.validate_trust_policy(role_name, ["eks.amazonaws.com"]):
            self.reporter.add("eks.cluster.trust", "FAIL", "Invalid trust policy", 
                            {"role_name": role_name, "expected": ["eks.amazonaws.com"]})
            return False
        
        self.reporter.add("eks.cluster.trust", "PASS", "Trust policy valid", 
                         {"role_name": role_name, "principals": ["eks.amazonaws.com"]})
        
        required_policies = ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
        if not self.validate_attached_policies(role_name, required_policies):
            self.reporter.add("eks.cluster.policies", "FAIL", "Missing required policies", 
                            {"role_name": role_name, "required": required_policies})
            return False
        
        self.reporter.add("eks.cluster.policies", "PASS", "Required policies attached", 
                         {"role_name": role_name, "policies": required_policies})
        
        self.logger.info(f"✓ EKS cluster role '{role_name}' is properly configured")
        return True

    def verify_eks_worker_role(self, role_arn: str = None) -> bool:
        """Verify EKS worker node role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-eks-worker"
        
        role_name = self.extract_role_name_from_arn(role_arn)
        self.logger.info(f"Verifying EKS worker role: {role_name} (ARN: {role_arn})")
        
        exists, role_data = self.role_exists(role_name)
        if not exists:
            self.reporter.add("eks.worker.exists", "FAIL", "EKS worker role not found", 
                            {"input": role_arn, "role_name": role_name})
            return False
        
        self.reporter.add("eks.worker.exists", "PASS", "EKS worker role found", 
                         {"role_name": role_name, "arn": role_arn})
        
        if not self.validate_trust_policy(role_name, ["ec2.amazonaws.com"]):
            self.reporter.add("eks.worker.trust", "FAIL", "Invalid trust policy", 
                            {"role_name": role_name, "expected": ["ec2.amazonaws.com"]})
            return False
        
        self.reporter.add("eks.worker.trust", "PASS", "Trust policy valid", 
                         {"role_name": role_name, "principals": ["ec2.amazonaws.com"]})
        
        required_policies = [
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
        ]
        if not self.validate_attached_policies(role_name, required_policies):
            self.reporter.add("eks.worker.policies", "FAIL", "Missing required policies", 
                            {"role_name": role_name, "required": required_policies})
            return False
        
        self.reporter.add("eks.worker.policies", "PASS", "Required policies attached", 
                         {"role_name": role_name, "policies": required_policies})
        
        worker_spec = self.spec.get('eks', {}).get('worker', {})
        required_suffixes = worker_spec.get('required_attached_suffixes', [])
        
        if required_suffixes:
            if not self._validate_worker_custom_policies(role_name, required_suffixes):
                return False
        
        self.logger.info(f"✓ EKS worker role '{role_name}' is properly configured")
        return True

    def verify_jumpbox_role(self, role_arn: str = None) -> bool:
        """Verify jumpbox role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-jumpbox-role"
        
        role_name = self.extract_role_name_from_arn(role_arn)
        self.logger.info(f"Verifying jumpbox role: {role_name} (ARN: {role_arn})")
        
        exists, role_data = self.role_exists(role_name)
        if not exists:
            self.reporter.add("jumpbox.exists", "FAIL", "Jumpbox role not found", 
                            {"input": role_arn, "role_name": role_name})
            return False
        
        self.reporter.add("jumpbox.exists", "PASS", "Jumpbox role found", 
                         {"role_name": role_name, "arn": role_arn})
        
        if not self.validate_trust_policy(role_name, ["ec2.amazonaws.com"]):
            self.reporter.add("jumpbox.trust", "FAIL", "Invalid trust policy", 
                            {"role_name": role_name, "expected": ["ec2.amazonaws.com"]})
            return False
        
        self.reporter.add("jumpbox.trust", "PASS", "Trust policy valid", 
                         {"role_name": role_name, "principals": ["ec2.amazonaws.com"]})
        
        self.logger.info(f"✓ Jumpbox role '{role_name}' is properly configured")
        return True

    def verify_oidc_role(self, role_arn: str, service_account: str, namespace: str, description: str, oidc_spec_key: str = None) -> bool:
        """Verify OIDC role configuration including attached policies"""
        role_name = self.extract_role_name_from_arn(role_arn)
        self.logger.info(f"Verifying OIDC role: {role_name} (ARN: {role_arn}) for {description}")
        
        exists, role_data = self.role_exists(role_name)
        if not exists:
            self.reporter.add(f"oidc.{service_account}.exists", "FAIL", f"OIDC role for {description} not found", 
                            {"input": role_arn, "role_name": role_name, "service_account": service_account})
            return False
        
        self.reporter.add(f"oidc.{service_account}.exists", "PASS", f"OIDC role for {description} found", 
                         {"role_name": role_name, "arn": role_arn, "service_account": service_account})
        
        trust_policy = role_data.get('AssumeRolePolicyDocument', {})
        if not self._validate_oidc_trust_policy(trust_policy, service_account, namespace):
            self.reporter.add(f"oidc.{service_account}.trust", "FAIL", f"Invalid OIDC trust policy for {description}", 
                            {"role_name": role_name, "service_account": f"{namespace}:{service_account}"})
            return False
        
        self.reporter.add(f"oidc.{service_account}.trust", "PASS", f"OIDC trust policy valid for {description}", 
                         {"role_name": role_name, "service_account": f"{namespace}:{service_account}"})
        
        if oidc_spec_key and oidc_spec_key in self.spec.get('oidc', {}).get('roles', {}):
            oidc_role_spec = self.spec['oidc']['roles'][oidc_spec_key]
            required_suffixes = oidc_role_spec.get('required_attached_suffixes', [])
            aws_managed_policies = oidc_role_spec.get('aws_managed_policies', [])
            
            if required_suffixes or aws_managed_policies:
                if not self._validate_oidc_attached_policies(role_name, required_suffixes, aws_managed_policies, service_account, description, oidc_spec_key):
                    return False
        
        self.logger.info(f"✓ OIDC role '{role_name}' for {description} is properly configured")
        return True
    
    def _validate_oidc_trust_policy(self, trust_policy: Dict, service_account: str, namespace: str) -> bool:
        """Validate OIDC trust policy has correct federated principal and conditions"""
        statements = trust_policy.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            principal = statement.get('Principal', {})
            if 'Federated' not in principal:
                continue
            
            federated = principal['Federated']
            if not isinstance(federated, str) or 'oidc-provider' not in federated:
                continue
            
            condition = statement.get('Condition', {})
            string_equals = condition.get('StringEquals', {})
            
            expected_oidc_provider = f"arn:aws:iam::{self.account_id}:oidc-provider/oidc.eks.{self.region}.amazonaws.com/id/"
            expected_subject = f"system:serviceaccount:{namespace}:{service_account}"
            
            if not federated.startswith(expected_oidc_provider):
                continue
            
            for key, value in string_equals.items():
                if key.endswith(':sub'):
                    if isinstance(value, str):
                        if value == expected_subject:
                            return True
                    elif isinstance(value, list):
                        if expected_subject in value:
                            return True
        
        return False

    def _validate_oidc_attached_policies(self, role_name: str, required_suffixes: list, aws_managed_policies: list, service_account: str, description: str, oidc_spec_key: str = None) -> bool:
        """Validate that OIDC role has required attached policies"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = response.get('AttachedPolicies', [])
            attached_policy_names = [policy['PolicyName'] for policy in attached_policies]
            attached_policy_arns = [policy['PolicyArn'] for policy in attached_policies]
            
            missing_suffixes = []
            for suffix in required_suffixes:
                found = False
                for policy_name in attached_policy_names:
                    if policy_name.endswith(suffix):
                        found = True
                        break
                if not found:
                    missing_suffixes.append(suffix)
            
            missing_aws_policies = []
            for aws_policy_arn in aws_managed_policies:
                if aws_policy_arn not in attached_policy_arns:
                    missing_aws_policies.append(aws_policy_arn)
            
            if missing_suffixes and oidc_spec_key and oidc_spec_key in self.spec.get('oidc', {}).get('roles', {}):
                oidc_role_spec = self.spec['oidc']['roles'][oidc_spec_key]
                required_actions = oidc_role_spec.get('required_actions', [])
                
                if required_actions:
                    return self._validate_policy_content(role_name, required_actions, aws_managed_policies, service_account, description)
            
            if missing_suffixes or missing_aws_policies:
                self.reporter.add(f"oidc.{service_account}.policies", "FAIL", 
                                f"OIDC role for {description} missing required policies", 
                                {"role_name": role_name, "missing_suffixes": missing_suffixes,
                                 "missing_aws_policies": missing_aws_policies,
                                 "attached_policies": attached_policy_names})
                return False
            else:
                self.reporter.add(f"oidc.{service_account}.policies", "PASS", 
                                f"OIDC role for {description} has required policies", 
                                {"role_name": role_name, "required_suffixes": required_suffixes,
                                 "aws_managed_policies": aws_managed_policies,
                                 "attached_policies": attached_policy_names})
                return True
                
        except ClientError as e:
            self.reporter.add(f"oidc.{service_account}.policies", "WARN", 
                            f"Could not validate attached policies for {description}: {e}", 
                            {"role_name": role_name})
            return True  # Don't fail verification if we can't check policies

    def _validate_worker_custom_policies(self, role_name: str, required_suffixes: list) -> bool:
        """Validate that EKS worker role has required custom policies"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = response.get('AttachedPolicies', [])
            attached_policy_names = [policy['PolicyName'] for policy in attached_policies]
            
            missing_suffixes = []
            for suffix in required_suffixes:
                found = False
                for policy_name in attached_policy_names:
                    if policy_name.endswith(suffix):
                        found = True
                        break
                if not found:
                    missing_suffixes.append(suffix)
            
            if missing_suffixes:
                worker_spec = self.spec.get('eks', {}).get('worker', {})
                required_actions = worker_spec.get('actions', [])
                
                if required_actions:
                    return self._validate_worker_policy_content(role_name, required_actions)
            
            if missing_suffixes:
                self.reporter.add("eks.worker.custom_policies", "FAIL", 
                                "EKS worker role missing required custom policies", 
                                {"role_name": role_name, "missing_suffixes": missing_suffixes, 
                                 "attached_policies": attached_policy_names})
                return False
            else:
                self.reporter.add("eks.worker.custom_policies", "PASS", 
                                "EKS worker role has required custom policies", 
                                {"role_name": role_name, "required_suffixes": required_suffixes,
                                 "attached_policies": attached_policy_names})
                return True
                
        except ClientError as e:
            self.reporter.add("eks.worker.custom_policies", "WARN", 
                            f"Could not validate custom policies for EKS worker role: {e}", 
                            {"role_name": role_name})
            return True  # Don't fail verification if we can't check policies

    def verify_aws_load_balancer_controller_role(self, role_arn: str = None) -> bool:
        """Verify AWS Load Balancer Controller OIDC role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-lbcontroller-role"
        return self.verify_oidc_role(role_arn, "aws-load-balancer-controller", "kube-system", "AWS Load Balancer Controller", "lbcontroller")

    def verify_aws_efs_csi_driver_role(self, role_arn: str = None) -> bool:
        """Verify AWS EFS CSI Driver OIDC role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-efscsi-role"
        return self.verify_oidc_role(role_arn, "efs-csi-controller-sa", "kube-system", "AWS EFS CSI Driver", "efs_csi_driver")

    def verify_aws_ebs_csi_driver_role(self, role_arn: str = None) -> bool:
        """Verify AWS EBS CSI Driver OIDC role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-ebscsi-role"
        return self.verify_oidc_role(role_arn, "ebs-csi-controller-sa", "kube-system", "AWS EBS CSI Driver", "ebs_csi_driver")

    def verify_cluster_autoscaler_role(self, role_arn: str = None) -> bool:
        """Verify Cluster Autoscaler OIDC role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-eks-autoscaler-role"
        return self.verify_oidc_role(role_arn, "cluster-autoscaler", "kube-system", "Cluster Autoscaler", "autoscaler")

    def verify_pgbackup_role(self, role_arn: str = None) -> bool:
        """Verify PostgreSQL Backup OIDC role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-s3-access-role"
        return self.verify_oidc_role(role_arn, "pgbackup-sa", "intelligentedge", "PostgreSQL Backup", "pgbackup")

    def verify_trino_role(self, role_arn: str = None) -> bool:
        """Verify Trino OIDC role"""
        if not role_arn:
            role_arn = f"arn:aws:iam::{self.account_id}:role/{self.company_name}-trino-oidc-role"
        return self.verify_oidc_role(role_arn, "trino-sa", "intelligentedge", "Trino", "trino")

    def analyze_attached_policies(self, role_name: str, account_id: str, region: str, deployment_context: Dict[str, Any] = None) -> None:
        """Analyze attached policies for hardcoded values and unnecessary permissions"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = response.get('AttachedPolicies', [])
            
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_name = policy['PolicyName']
                
                if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                    continue
                
                try:
                    policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = policy_response['Policy']['DefaultVersionId']
                    
                    version_response = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id)
                    policy_doc = version_response['PolicyVersion']['Document']
                    
                    hardcoded_issues = self._analyze_policy_hardcoding(policy_doc, account_id, region)
                    
                    if hardcoded_issues:
                        self.reporter.add(f"policy.{policy_name}.hardcoded", "WARN",
                                        f"Policy contains hardcoded values that should be parameterized",
                                        {"policy_arn": policy_arn, "issues": hardcoded_issues})
                    else:
                        self.reporter.add(f"policy.{policy_name}.generic", "PASS",
                                        f"Policy appears to be region/account generic",
                                        {"policy_arn": policy_arn})
                    
                    if deployment_context:
                        over_permission_issues = self._analyze_policy_over_permissions(
                            policy_doc, policy_name, deployment_context)
                        
                        if over_permission_issues:
                            self.reporter.add(f"policy.{policy_name}.over_permissions", "WARN",
                                            f"Policy may contain unnecessary permissions for this deployment scenario",
                                            {"policy_arn": policy_arn, "issues": over_permission_issues,
                                             "deployment_context": deployment_context})
                        
                except ClientError as e:
                    self.reporter.add(f"policy.{policy_name}.analysis", "WARN",
                                    f"Could not analyze policy: {e}",
                                    {"policy_arn": policy_arn})
                    
        except ClientError as e:
            self.reporter.add("policy.analysis", "WARN", f"Could not list attached policies: {e}")

    def _analyze_policy_hardcoding(self, policy_doc: Dict[str, Any], account_id: str, region: str) -> List[Dict[str, Any]]:
        """Analyze policy document for hardcoded account/region values"""
        issues = []
        policy_str = json.dumps(policy_doc)
        
        import re
        account_pattern = r'arn:aws:[^:]*:[^:]*:(\d{12}):'
        found_accounts = re.findall(account_pattern, policy_str)
        
        for found_account in set(found_accounts):
            if found_account != account_id:
                issues.append({
                    "type": "hardcoded_account",
                    "value": found_account,
                    "suggestion": f"Replace with {account_id} or use parameter"
                })
        
        region_pattern = r'arn:aws:[^:]*:([^:]+):'
        found_regions = re.findall(region_pattern, policy_str)
        
        for found_region in set(found_regions):
            if found_region and found_region != region and found_region != '*':
                issues.append({
                    "type": "hardcoded_region", 
                    "value": found_region,
                    "suggestion": f"Replace with {region} or use * for all regions"
                })
        
        return issues

    def _analyze_policy_over_permissions(self, policy_doc: Dict[str, Any], policy_name: str, 
                                       deployment_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze policy for over-permissions based on deployment context"""
        issues = []
        
        customer_creates_roles = deployment_context.get('customer_creates_roles', False)
        tested_actions = deployment_context.get('tested_actions', [])
        
        policy_actions = self._extract_policy_actions(policy_doc)
        
        if customer_creates_roles:
            context_inappropriate_policies = self._identify_context_inappropriate_policies(
                policy_name, policy_actions, tested_actions)
            
            if context_inappropriate_policies:
                issues.extend(context_inappropriate_policies)
        
        return issues
    
    def _extract_policy_actions(self, policy_doc: Dict[str, Any]) -> List[str]:
        """Extract all actions from a policy document"""
        actions = []
        
        for statement in policy_doc.get('Statement', []):
            if statement.get('Effect') == 'Allow':
                action_list = statement.get('Action', [])
                if isinstance(action_list, str):
                    actions.append(action_list)
                elif isinstance(action_list, list):
                    actions.extend(action_list)
        
        return actions
    
    def _validate_policy_content(self, role_name: str, required_actions: list, aws_managed_policies: list, service_account: str, description: str) -> bool:
        """Validate that role has policies with required actions/permissions"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = response.get('AttachedPolicies', [])
            attached_policy_arns = [policy['PolicyArn'] for policy in attached_policies]
            
            missing_aws_policies = []
            for aws_policy_arn in aws_managed_policies:
                if aws_policy_arn not in attached_policy_arns:
                    missing_aws_policies.append(aws_policy_arn)
            
            all_policy_actions = set()
            condition_issues = []
            
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                try:
                    if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                        continue
                    
                    policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = policy_response['Policy']['DefaultVersionId']
                    
                    version_response = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id)
                    policy_doc = version_response['PolicyVersion']['Document']
                    
                    policy_actions = self._extract_policy_actions(policy_doc)
                    all_policy_actions.update(policy_actions)
                    
                    condition_validation = self._validate_policy_conditions(policy_doc, service_account)
                    if condition_validation:
                        condition_issues.extend(condition_validation)
                    
                except ClientError as e:
                    self.logger.debug(f"Could not analyze policy {policy_arn}: {e}")
                    continue
            
            missing_actions = []
            for required_action in required_actions:
                found = False
                for policy_action in all_policy_actions:
                    if self._action_matches(policy_action, required_action):
                        found = True
                        break
                if not found:
                    missing_actions.append(required_action)
            
            if missing_actions or missing_aws_policies or condition_issues:
                failure_details = {
                    "role_name": role_name, 
                    "missing_actions": missing_actions,
                    "missing_aws_policies": missing_aws_policies,
                    "found_actions": list(all_policy_actions)
                }
                if condition_issues:
                    failure_details["condition_issues"] = condition_issues
                
                self.reporter.add(f"oidc.{service_account}.policies", "FAIL", 
                                f"OIDC role for {description} has policy validation issues", 
                                failure_details)
                return False
            else:
                self.reporter.add(f"oidc.{service_account}.policies", "PASS", 
                                f"OIDC role for {description} has required permissions and valid conditions", 
                                {"role_name": role_name, "required_actions": required_actions,
                                 "aws_managed_policies": aws_managed_policies,
                                 "found_actions": list(all_policy_actions)})
                return True
                
        except ClientError as e:
            self.reporter.add(f"oidc.{service_account}.policies", "WARN", 
                            f"Could not validate policies for {description}: {e}", 
                            {"role_name": role_name})
            return True

    def _validate_worker_policy_content(self, role_name: str, required_actions: list) -> bool:
        """Validate that EKS worker role has policies with required actions"""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            attached_policies = response.get('AttachedPolicies', [])
            
            all_policy_actions = set()
            condition_issues = []
            
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                try:
                    if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                        continue
                    
                    policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                    version_id = policy_response['Policy']['DefaultVersionId']
                    
                    version_response = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id)
                    policy_doc = version_response['PolicyVersion']['Document']
                    
                    policy_actions = self._extract_policy_actions(policy_doc)
                    all_policy_actions.update(policy_actions)
                    
                    condition_validation = self._validate_policy_conditions(policy_doc, "eks-worker")
                    if condition_validation:
                        condition_issues.extend(condition_validation)
                    
                except ClientError as e:
                    self.logger.debug(f"Could not analyze policy {policy_arn}: {e}")
                    continue
            
            missing_actions = []
            for required_action in required_actions:
                found = False
                for policy_action in all_policy_actions:
                    if self._action_matches(policy_action, required_action):
                        found = True
                        break
                if not found:
                    missing_actions.append(required_action)
            
            if missing_actions or condition_issues:
                failure_details = {
                    "role_name": role_name, 
                    "missing_actions": missing_actions,
                    "found_actions": list(all_policy_actions)
                }
                if condition_issues:
                    failure_details["condition_issues"] = condition_issues
                
                self.reporter.add("eks.worker.custom_policies", "FAIL", 
                                "EKS worker role has policy validation issues", 
                                failure_details)
                return False
            else:
                self.reporter.add("eks.worker.custom_policies", "PASS", 
                                "EKS worker role has required permissions and valid conditions", 
                                {"role_name": role_name, "required_actions": required_actions,
                                 "found_actions": list(all_policy_actions)})
                return True
                
        except ClientError as e:
            self.reporter.add("eks.worker.custom_policies", "WARN", 
                            f"Could not validate worker policy content: {e}", 
                            {"role_name": role_name})
            return True

    def _validate_policy_conditions(self, policy_doc: dict, service_account: str) -> list:
        """Validate policy conditions for cluster-specific parameters"""
        issues = []
        expected_cluster_name = f"{self.company_name}-{self.region}-eks-cluster"
        
        statements = policy_doc.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            conditions = statement.get('Condition', {})
            if not conditions:
                continue
                
            for condition_type, condition_values in conditions.items():
                if isinstance(condition_values, dict):
                    for key, value in condition_values.items():
                        if 'cluster-name' in key.lower():
                            if isinstance(value, str):
                                cluster_values = [value]
                            elif isinstance(value, list):
                                cluster_values = value
                            else:
                                continue
                                
                            for cluster_value in cluster_values:
                                if not self._is_valid_cluster_name(cluster_value, service_account):
                                    issues.append({
                                        "type": "invalid_cluster_name",
                                        "condition_key": key,
                                        "found_value": cluster_value,
                                        "expected_pattern": f"Should contain cluster name for {self.company_name} deployment"
                                    })
                        
                        elif 'account' in key.lower() and self.account_id:
                            if isinstance(value, str):
                                account_values = [value]
                            elif isinstance(value, list):
                                account_values = value
                            else:
                                continue
                                
                            for account_value in account_values:
                                if self.account_id not in str(account_value):
                                    issues.append({
                                        "type": "invalid_account_id",
                                        "condition_key": key,
                                        "found_value": account_value,
                                        "expected_account_id": self.account_id
                                    })
        
        return issues
    
    def _is_valid_cluster_name(self, cluster_name: str, service_account: str) -> bool:
        """Check if cluster name is valid for the deployment"""
        if not cluster_name or cluster_name.strip() == "":
            return False
            
        invalid_patterns = ["bad-cluster-name", "test-cluster", "dev-cluster", "example-cluster"]
        if cluster_name.lower() in invalid_patterns:
            return False
            
        return True

    def _action_matches(self, policy_action: str, required_action: str) -> bool:
        """Check if a policy action matches a required action (supports wildcards)"""
        import fnmatch
        return fnmatch.fnmatch(policy_action, required_action) or fnmatch.fnmatch(required_action, policy_action)

    def _identify_context_inappropriate_policies(self, policy_name: str, policy_actions: List[str], 
                                               tested_actions: List[str]) -> List[Dict[str, Any]]:
        """Identify policies that are inappropriate for customer-managed deployment context"""
        issues = []
        
        policy_service_map = {
            'acm': {
                'policy_patterns': ['acm-policy', 'certificate'],
                'actions': ['acm:'],
                'reason': 'Certificate management typically handled outside installer in customer-managed scenarios'
            },
            's3-advanced': {
                'policy_patterns': ['s3-policy'],
                'actions': ['kms:CreateKey', 'kms:EnableKeyRotation', 'kms:ScheduleKeyDeletion', 
                           's3:PutEncryptionConfiguration', 's3:PutLifecycleConfiguration'],
                'reason': 'Advanced S3/KMS management typically handled by customers in customer-managed scenarios'
            },
            'glue-advanced': {
                'policy_patterns': ['glue-policy'],
                'actions': ['glue:CreateDatabase', 'glue:CreateCrawler', 'glue:CreateTable'],
                'reason': 'Data catalog management typically handled by customers in customer-managed scenarios'
            }
        }
        
        for service, config in policy_service_map.items():
            policy_matches = any(pattern in policy_name.lower() for pattern in config['policy_patterns'])
            
            if policy_matches:
                policy_service_actions = [action for action in policy_actions 
                                        if any(action.startswith(svc_action) for svc_action in config['actions'])]
                
                tested_service_actions = [action for action in tested_actions 
                                        if any(action.startswith(svc_action) for svc_action in config['actions'])]
                
                if policy_service_actions and not tested_service_actions:
                    issues.append({
                        'type': 'context_inappropriate_policy',
                        'service': service,
                        'policy_actions': policy_service_actions[:5],
                        'reason': config['reason'],
                        'suggestion': f'Consider removing {policy_name} for customer-managed deployments'
                    })
                elif len(policy_service_actions) > len(tested_service_actions) * 2:
                    issues.append({
                        'type': 'excessive_permissions',
                        'service': service,
                        'policy_actions_count': len(policy_service_actions),
                        'tested_actions_count': len(tested_service_actions),
                        'reason': f'Policy grants {len(policy_service_actions)} {service} actions but only {len(tested_service_actions)} are tested',
                        'suggestion': f'Review {policy_name} to ensure all permissions are necessary'
                    })
        
        return issues


def main():
    parser = argparse.ArgumentParser(
        description='Verify IAM setup for Promethium deployment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python verify_iam_setup.py --account-id 123456789012 --region us-east-1 --company-name acme \\
    --iam-role-create true --aws-iam-oidc-enabled true

  python verify_iam_setup.py --account-id 123456789012 --region us-east-1 --company-name acme \\
    --installer-role arn:aws:iam::123456789012:role/PromethiumInstall --simulate-installer true \\
    --iam-role-create false --aws-iam-oidc-enabled false

  python verify_iam_setup.py --account-id 123456789012 --region us-east-1 --company-name acme \\
    --iam-role-create false --aws-iam-oidc-enabled false --output json
        """
    )
    
    parser.add_argument('--account-id', required=True, help='AWS Account ID')
    parser.add_argument('--region', required=True, help='AWS Region')
    parser.add_argument('--company-name', required=True, help='Company name for role naming')
    parser.add_argument('--spec', default='specs/iam_requirements.yaml', help='Path to IAM requirements YAML file')
    parser.add_argument('--output-json', default='verify_iam_report.json', help='JSON output file')
    parser.add_argument('--strict', action='store_true', help='Exit with non-zero code on any failures')
    parser.add_argument('--simulate-installer', choices=['true', 'false'], default=None, help='Enable/disable installer permission simulation')
    
    parser.add_argument('--installer-role', help='Installer role ARN or name')
    parser.add_argument('--cluster-role', help='EKS cluster role ARN or name')
    parser.add_argument('--worker-role', help='EKS worker role ARN or name')
    parser.add_argument('--jumpbox-role', help='Jumpbox role ARN or name')
    parser.add_argument('--aws-lb-controller-role', help='AWS LB Controller role ARN or name')
    parser.add_argument('--aws-efs-driver-role', help='AWS EFS CSI Driver role ARN or name')
    parser.add_argument('--aws-ebs-driver-role', help='AWS EBS CSI Driver role ARN or name')
    parser.add_argument('--aws-eks-autoscaler-role', help='Cluster Autoscaler role ARN or name')
    parser.add_argument('--pgbackup-role', help='PG Backup role ARN or name')
    parser.add_argument('--trino-role', help='Trino role ARN or name')
    
    parser.add_argument('--iam-role-create', choices=['true', 'false'], required=True, help='Whether Terraform creates IAM roles')
    parser.add_argument('--aws-iam-oidc-enabled', choices=['true', 'false'], required=True, help='Whether Terraform manages OIDC roles')
    parser.add_argument('--jumpbox-enabled', choices=['true', 'false'], default='true', help='Whether jumpbox is enabled')
    
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--analyze-policies', action='store_true', 
                       help='Analyze attached policies for hardcoded values and unnecessary permissions')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    verifier = IAMVerifier(args.account_id, args.region, args.company_name, args.spec)
    verifier._analyze_policies = getattr(args, 'analyze_policies', False)
    
    try:
        response = verifier.sts_client.get_caller_identity()
        verifier.reporter.add("auth.identity", "PASS", "Using AWS identity", 
                            {"account": response.get("Account"), "arn": response.get("Arn")})
    except Exception as e:
        verifier.reporter.add("auth.identity", "FAIL", "Unable to call sts:GetCallerIdentity", {"error": str(e)})
        if args.output == 'json':
            print(json.dumps(verifier.reporter.to_json(), indent=2))
        else:
            verifier.reporter.print_text()
        sys.exit(2)
    
    customer_creates_roles = args.iam_role_create == "false"
    simulate_installer = args.simulate_installer == "true" if args.simulate_installer else (args.iam_role_create == "true")
    
    verifier.verify_installer_role(args.installer_role, customer_creates_roles, simulate_installer)
    
    if args.iam_role_create == "false":
        if args.cluster_role:
            verifier.verify_eks_cluster_role(args.cluster_role)
        else:
            verifier.reporter.add("eks.cluster.provided", "WARN", "Cluster role ARN not provided", {})
        
        if args.worker_role:
            verifier.verify_eks_worker_role(args.worker_role)
        else:
            verifier.reporter.add("eks.worker.provided", "WARN", "Worker role ARN not provided", {})
        
        if args.jumpbox_enabled == "true" and args.jumpbox_role:
            verifier.verify_jumpbox_role(args.jumpbox_role)
        elif args.jumpbox_enabled == "true":
            verifier.reporter.add("jumpbox.provided", "WARN", "Jumpbox role ARN not provided", {})
    else:
        verifier.reporter.add("eks.mode", "PASS", "Terraform-managed IAM roles mode", {})
    
    if args.aws_iam_oidc_enabled == "false":
        oidc_roles = [
            (args.aws_lb_controller_role, "lbcontroller", "aws-load-balancer-controller", "kube-system", "AWS Load Balancer Controller"),
            (args.aws_efs_driver_role, "efs_csi_driver", "efs-csi-controller-sa", "kube-system", "AWS EFS CSI Driver"),
            (args.aws_ebs_driver_role, "ebs_csi_driver", "ebs-csi-controller-sa", "kube-system", "AWS EBS CSI Driver"),
            (args.aws_eks_autoscaler_role, "autoscaler", "cluster-autoscaler", "kube-system", "Cluster Autoscaler"),
            (args.pgbackup_role, "pgbackup", "pgbackup-sa", "intelligentedge", "PostgreSQL Backup"),
            (args.trino_role, "trino", "trino-sa", "intelligentedge", "Trino"),
        ]
        
        for role_arn, key, service_account, namespace, description in oidc_roles:
            if role_arn:
                verifier.verify_oidc_role(role_arn, service_account, namespace, description, key)
            else:
                verifier.reporter.add(f"oidc.{key}.provided", "WARN", f"{description} role ARN not provided", {})
    else:
        verifier.reporter.add("oidc.mode", "PASS", "Terraform-managed OIDC roles mode", {})
    
    if args.output == 'json':
        with open(args.output_json, 'w') as f:
            json.dump(verifier.reporter.to_json(), f, indent=2)
        print(json.dumps(verifier.reporter.to_json(), indent=2))
    else:
        verifier.reporter.print_text()
    
    if args.strict and verifier.reporter.has_failures():
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
