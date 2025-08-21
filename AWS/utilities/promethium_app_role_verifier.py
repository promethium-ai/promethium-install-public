#!/usr/bin/env python3
"""
AWS IAM Role Verification Script for Promethium IE Roles

This script verifies seven roles:
1. promethium-ebscsi-role with trust policy, AWS managed policy AmazonEBSCSIDriverPolicy, 
   and customer policy Promethium-eks-kms-access-policy
2. promethium-eks-autoscaler-role with trust policy and custom promethium-eks-autoscaler-policy
3. promethium-efscsi-role with trust policy and custom promethium-efscsi-policy
4. promethium-lbcontroller-role with trust policy and custom promethium-lbcontroller-policy
5. promethium-s3-access-role with trust policy and custom promethium-s3-access-policy
6. promethium-eks-cluster-role with trust policy and AWS managed policies AmazonEKSClusterPolicy and AmazonEKSVPCResourceController
7. promethium-trino-oidc-role with trust policy and custom promethium-trino-glue-policy

All roles are verified for proper account ID, region, EKS OIDC ID, and placeholder replacement in policies.
"""

import boto3
import json
import sys
import argparse
from botocore.exceptions import ClientError, NoCredentialsError


class RoleVerifier:
    def __init__(self, account_id, region, eks_oidc_id, eks_cluster_name=None, company_name=None, trust_policy_file=None, customer_policy_file=None):
        self.account_id = account_id
        self.region = region
        self.eks_oidc_id = eks_oidc_id
        self.eks_cluster_name = eks_cluster_name
        self.company_name = company_name
        self.role_name = "promethium-ebscsi-role"
        self.aws_managed_policy = "AmazonEBSCSIDriverPolicy"
        self.customer_policy = "promethium-eks-kms-access-policy.json"
        self.trust_policy_file = trust_policy_file or "promethium-ebscsi-role-trust-policy.json"
        self.customer_policy_file = customer_policy_file or "promethium-eks-kms-access-policy.json"
        self.iam_client = None
        
        self.expected_trust_policy = self.load_policy_template(self.trust_policy_file)
        self.expected_customer_policy = self.load_policy_template(self.customer_policy_file)
    
    def load_policy_template(self, file_path):
        """Load policy template from file and replace placeholders"""
        try:
            with open(file_path, 'r') as f:
                policy_content = f.read()
            
            policy_content = policy_content.replace('<ACCOUNT_ID>', self.account_id)
            policy_content = policy_content.replace('<account_id>', self.account_id)
            policy_content = policy_content.replace('<REGION>', self.region)
            policy_content = policy_content.replace('<region>', self.region)
            policy_content = policy_content.replace('<EKS_OIDC_ID>', self.eks_oidc_id)
            
            if self.eks_cluster_name:
                policy_content = policy_content.replace('<eks_cluster_name>', self.eks_cluster_name)
            
            if hasattr(self, 'company_name') and self.company_name:
                policy_content = policy_content.replace('<COMPANY NAME>', self.company_name)
            
            return json.loads(policy_content)
        except FileNotFoundError:
            print(f"ERROR: Policy template file '{file_path}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in policy template file '{file_path}': {e}")
            sys.exit(1)
    
    def check_aws_credentials(self):
        """Check if AWS credentials are configured"""
        try:
            self.iam_client = boto3.client('iam', region_name=self.region)
            self.iam_client.get_account_summary()
            return True
        except NoCredentialsError:
            print("ERROR: AWS credentials not configured. Please run 'aws configure' first.")
            return False
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print("ERROR: AWS credentials don't have sufficient IAM permissions.")
                return False
            else:
                print(f"ERROR: AWS credential check failed: {e}")
                return False
    
    def verify_role_exists(self):
        """Verify that the IAM role exists"""
        try:
            response = self.iam_client.get_role(RoleName=self.role_name)
            print(f"Role '{self.role_name}' exists")
            return response['Role']
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                print(f"Role '{self.role_name}' does not exist")
                return None
            else:
                print(f"Error checking role: {e}")
                return None
    
    def verify_trust_policy(self, role):
        """Verify the trust policy matches the expected template"""
        actual_trust_policy = role['AssumeRolePolicyDocument']
        expected_trust_policy = self.expected_trust_policy
        
        print("Verifying Trust Policy:")
        print(f"Expected trust policy loaded from: {self.trust_policy_file}")
        
        if self.policies_match(actual_trust_policy, expected_trust_policy):
            print("Trust policy matches expected template")
            
            expected_federated_arn = f"arn:aws:iam::{self.account_id}:oidc-provider/oidc.eks.{self.region}.amazonaws.com/id/{self.eks_oidc_id}"
            expected_condition_key = f"oidc.eks.{self.region}.amazonaws.com/id/{self.eks_oidc_id}:sub"
            
            policy_str = json.dumps(actual_trust_policy)
            if self.eks_oidc_id in policy_str:
                print(f"EKS OIDC ID '{self.eks_oidc_id}' found in trust policy")
            else:
                print(f"EKS OIDC ID '{self.eks_oidc_id}' NOT found in trust policy")
                return False
            
            if self.account_id in policy_str and self.region in policy_str:
                print(f"Account ID '{self.account_id}' and region '{self.region}' found in trust policy")
            else:
                print(f"Account ID or region missing in trust policy")
                return False
            
            return True
        else:
            print("Trust policy does not match expected template")
            print(f"Expected: {json.dumps(expected_trust_policy, indent=2)}")
            print(f"Actual: {json.dumps(actual_trust_policy, indent=2)}")
            return False
    
    def verify_attached_policies(self):
        """Verify that both AWS managed and customer policies are attached"""
        try:
            managed_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)
            attached_managed_policies = [p['PolicyName'] for p in managed_policies['AttachedPolicies']]
            
            inline_policies = self.iam_client.list_role_policies(RoleName=self.role_name)
            attached_inline_policies = inline_policies['PolicyNames']
            
            print(f"Verifying Attached Policies:")
            print(f"Attached managed policies: {attached_managed_policies}")
            print(f"Attached inline policies: {attached_inline_policies}")
            
            aws_policy_found = self.aws_managed_policy in attached_managed_policies
            if aws_policy_found:
                print(f"AWS managed policy '{self.aws_managed_policy}' is attached")
            else:
                print(f"AWS managed policy '{self.aws_managed_policy}' is NOT attached")
            
            customer_policy_found = (self.customer_policy in attached_managed_policies or 
                                   self.customer_policy in attached_inline_policies)
            
            if customer_policy_found:
                print(f"Customer policy '{self.customer_policy}' is attached")
                self.verify_customer_policy_content()
            else:
                print(f"Customer policy '{self.customer_policy}' is NOT attached")
            
            return aws_policy_found and customer_policy_found
            
        except ClientError as e:
            print(f"Error checking attached policies: {e}")
            return False
    
    def policies_match(self, actual_policy, expected_policy):
        """Compare two policies for structural equality"""
        def normalize_policy(policy):
            if isinstance(policy, dict):
                return {k: normalize_policy(v) for k, v in sorted(policy.items())}
            elif isinstance(policy, list):
                return sorted([normalize_policy(item) for item in policy])
            else:
                return policy
        
        return normalize_policy(actual_policy) == normalize_policy(expected_policy)
    
    def verify_customer_policy_content(self):
        """Verify the customer policy matches the expected template"""
        try:
            try:
                policy_arn = f"arn:aws:iam::{self.account_id}:policy/{self.customer_policy}"
                policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_response['Policy']['DefaultVersionId']
                )
                actual_policy_document = version_response['PolicyVersion']['Document']
                policy_type = "managed"
            except ClientError:
                policy_response = self.iam_client.get_role_policy(
                    RoleName=self.role_name,
                    PolicyName=self.customer_policy
                )
                actual_policy_document = policy_response['PolicyDocument']
                policy_type = "inline"
            
            print(f"\nVerifying Customer Policy Content ({policy_type}):")
            print(f"Expected customer policy loaded from: {self.customer_policy_file}")
            
            expected_policy_document = self.expected_customer_policy
            
            if self.policies_match(actual_policy_document, expected_policy_document):
                print("Customer policy matches expected template")
                
                policy_str = json.dumps(actual_policy_document)
                account_id_found = self.account_id in policy_str
                region_found = self.region in policy_str
                
                if account_id_found:
                    print(f"Account ID '{self.account_id}' found in policy")
                else:
                    print(f"Account ID '{self.account_id}' NOT found in policy")
                
                if region_found:
                    print(f"Region '{self.region}' found in policy")
                else:
                    print(f"Region '{self.region}' NOT found in policy")
                
                return account_id_found and region_found
            else:
                print("Customer policy does not match expected template")
                print(f"Expected: {json.dumps(expected_policy_document, indent=2)}")
                print(f"Actual: {json.dumps(actual_policy_document, indent=2)}")
                return False
            
        except ClientError as e:
            print(f"Error checking customer policy content: {e}")
            return False
    
    def run_verification(self):
        """Run complete verification of the role"""
        print(f"Starting verification for role: {self.role_name}")
        print(f"Account ID: {self.account_id}")
        print(f"Region: {self.region}")
        print(f"EKS OIDC ID: {self.eks_oidc_id}")
        if self.eks_cluster_name:
            print(f"EKS Cluster Name: {self.eks_cluster_name}")
        print("=" * 60)
        
        if not self.check_aws_credentials():
            print("\nVERIFICATION FAILED: AWS credentials not configured or insufficient permissions")
            return False
        
        role = self.verify_role_exists()
        if not role:
            print("\nVERIFICATION FAILED: Role does not exist")
            return False
        
        trust_policy_ok = self.verify_trust_policy(role)
        
        policies_ok = self.verify_attached_policies()
        
        print("\n" + "=" * 60)
        if trust_policy_ok and policies_ok:
            print("VERIFICATION PASSED: All checks successful!")
            return True
        else:
            print("VERIFICATION FAILED: Some checks failed")
            return False


class AutoscalerRoleVerifier(RoleVerifier):
    def __init__(self, account_id, region, eks_oidc_id, eks_cluster_name, company_name=None, trust_policy_file=None, customer_policy_file=None):
        self.account_id = account_id
        self.region = region
        self.eks_oidc_id = eks_oidc_id
        self.eks_cluster_name = eks_cluster_name
        self.company_name = company_name
        self.role_name = "promethium-eks-autoscaler-role"
        self.aws_managed_policy = None
        self.customer_policy = "promethium-eks-autoscaler-policy"
        self.trust_policy_file = trust_policy_file or "promethium-eks-autoscaler-role-trust-policy.json"
        self.customer_policy_file = customer_policy_file or "promethium-eks-autoscaler-policy.json"
        self.iam_client = None
        
        self.expected_trust_policy = self.load_policy_template(self.trust_policy_file)
        self.expected_customer_policy = self.load_policy_template(self.customer_policy_file)
    
    def verify_attached_policies(self):
        """Verify that the customer policy is attached (no AWS managed policy for autoscaler)"""
        try:
            managed_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)
            attached_managed_policies = [p['PolicyName'] for p in managed_policies['AttachedPolicies']]
            
            inline_policies = self.iam_client.list_role_policies(RoleName=self.role_name)
            attached_inline_policies = inline_policies['PolicyNames']
            
            print(f"\nVerifying Attached Policies:")
            print(f"Attached managed policies: {attached_managed_policies}")
            print(f"Attached inline policies: {attached_inline_policies}")
            
            customer_policy_found = (self.customer_policy in attached_managed_policies or 
                                   self.customer_policy in attached_inline_policies)
            
            if customer_policy_found:
                print(f"Customer policy '{self.customer_policy}' is attached")
                return self.verify_customer_policy_content()
            else:
                print(f"Customer policy '{self.customer_policy}' is NOT attached")
                return False
            
        except ClientError as e:
            print(f"Error checking attached policies: {e}")
            return False


class EfscsiRoleVerifier(RoleVerifier):
    def __init__(self, account_id, region, eks_oidc_id, company_name, trust_policy_file=None, customer_policy_file=None):
        self.account_id = account_id
        self.region = region
        self.eks_oidc_id = eks_oidc_id
        self.eks_cluster_name = None
        self.company_name = company_name
        self.role_name = "promethium-efscsi-role"
        self.aws_managed_policy = None
        self.customer_policy = "promethium-efscsi-policy"
        self.trust_policy_file = trust_policy_file or "promethium-efscsi-role-trust-policy.json"
        self.customer_policy_file = customer_policy_file or "promethium-efscsi-policy.json"
        self.iam_client = None
        
        self.expected_trust_policy = self.load_policy_template(self.trust_policy_file)
        self.expected_customer_policy = self.load_policy_template(self.customer_policy_file)
    
    def verify_attached_policies(self):
        """Verify that the customer policy is attached (no AWS managed policy for EFS CSI)"""
        try:
            managed_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)
            attached_managed_policies = [p['PolicyName'] for p in managed_policies['AttachedPolicies']]
            
            inline_policies = self.iam_client.list_role_policies(RoleName=self.role_name)
            attached_inline_policies = inline_policies['PolicyNames']
            
            print(f"\nVerifying Attached Policies:")
            print(f"Attached managed policies: {attached_managed_policies}")
            print(f"Attached inline policies: {attached_inline_policies}")
            
            customer_policy_found = (self.customer_policy in attached_managed_policies or 
                                   self.customer_policy in attached_inline_policies)
            
            if customer_policy_found:
                print(f"Customer policy '{self.customer_policy}' is attached")
                return self.verify_customer_policy_content()
            else:
                print(f"Customer policy '{self.customer_policy}' is NOT attached")
                return False
            
        except ClientError as e:
            print(f"Error checking attached policies: {e}")
            return False
    
    def verify_customer_policy_content(self):
        """Verify the EFS CSI customer policy matches the expected template"""
        try:
            try:
                policy_arn = f"arn:aws:iam::{self.account_id}:policy/{self.customer_policy}"
                policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_response['Policy']['DefaultVersionId']
                )
                actual_policy_document = version_response['PolicyVersion']['Document']
                policy_type = "managed"
            except ClientError:
                policy_response = self.iam_client.get_role_policy(
                    RoleName=self.role_name,
                    PolicyName=self.customer_policy
                )
                actual_policy_document = policy_response['PolicyDocument']
                policy_type = "inline"
            
            print(f"\nVerifying Customer Policy Content ({policy_type}):")
            print(f"Expected customer policy loaded from: {self.customer_policy_file}")
            
            expected_policy_document = self.expected_customer_policy
            
            if self.policies_match(actual_policy_document, expected_policy_document):
                print("Customer policy matches expected template")
                
                policy_str = json.dumps(actual_policy_document)
                company_name_found = self.company_name in policy_str
                
                if company_name_found:
                    print(f"Company name '{self.company_name}' found in policy")
                else:
                    print(f"Company name '{self.company_name}' NOT found in policy")
                
                return company_name_found
            else:
                print("Customer policy does not match expected template")
                print(f"Expected: {json.dumps(expected_policy_document, indent=2)}")
                print(f"Actual: {json.dumps(actual_policy_document, indent=2)}")
                return False
            
        except ClientError as e:
            print(f"Error checking customer policy content: {e}")
            return False


class LbcontrollerRoleVerifier(RoleVerifier):
    def __init__(self, account_id, region, eks_oidc_id, trust_policy_file=None, customer_policy_file=None):
        self.account_id = account_id
        self.region = region
        self.eks_oidc_id = eks_oidc_id
        self.eks_cluster_name = None
        self.company_name = None
        self.role_name = "promethium-lbcontroller-role"
        self.aws_managed_policy = None
        self.customer_policy = "promethium-lbcontroller-policy"
        self.trust_policy_file = trust_policy_file or "promethium-lbcontroller-role-trust-policy.json"
        self.customer_policy_file = customer_policy_file or "promethium-lbcontroller-policy.json"
        self.iam_client = None
        
        self.expected_trust_policy = self.load_policy_template(self.trust_policy_file)
        self.expected_customer_policy = self.load_policy_template(self.customer_policy_file)
    
    def verify_attached_policies(self):
        """Verify that the customer policy is attached (no AWS managed policy for Load Balancer Controller)"""
        try:
            managed_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)
            attached_managed_policies = [p['PolicyName'] for p in managed_policies['AttachedPolicies']]
            
            inline_policies = self.iam_client.list_role_policies(RoleName=self.role_name)
            attached_inline_policies = inline_policies['PolicyNames']
            
            print(f"\nVerifying Attached Policies:")
            print(f"Attached managed policies: {attached_managed_policies}")
            print(f"Attached inline policies: {attached_inline_policies}")
            
            customer_policy_found = (self.customer_policy in attached_managed_policies or 
                                   self.customer_policy in attached_inline_policies)
            
            if customer_policy_found:
                print(f"Customer policy '{self.customer_policy}' is attached")
                return self.verify_customer_policy_content()
            else:
                print(f"Customer policy '{self.customer_policy}' is NOT attached")
                return False
            
        except ClientError as e:
            print(f"Error checking attached policies: {e}")
            return False
    
    def verify_customer_policy_content(self):
        """Verify the Load Balancer Controller customer policy matches the expected template"""
        try:
            try:
                policy_arn = f"arn:aws:iam::{self.account_id}:policy/{self.customer_policy}"
                policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_response['Policy']['DefaultVersionId']
                )
                actual_policy_document = version_response['PolicyVersion']['Document']
                policy_type = "managed"
            except ClientError:
                policy_response = self.iam_client.get_role_policy(
                    RoleName=self.role_name,
                    PolicyName=self.customer_policy
                )
                actual_policy_document = policy_response['PolicyDocument']
                policy_type = "inline"
            
            print(f"\nVerifying Customer Policy Content ({policy_type}):")
            print(f"Expected customer policy loaded from: {self.customer_policy_file}")
            
            expected_policy_document = self.expected_customer_policy
            
            if self.policies_match(actual_policy_document, expected_policy_document):
                print("Customer policy matches expected template")
                return True
            else:
                print("Customer policy does not match expected template")
                print(f"Expected: {json.dumps(expected_policy_document, indent=2)}")
                print(f"Actual: {json.dumps(actual_policy_document, indent=2)}")
                return False
            
        except ClientError as e:
            print(f"Error checking customer policy content: {e}")
            return False


class S3AccessRoleVerifier(RoleVerifier):
    """Verifier for promethium-s3-access-role"""
    
    def __init__(self, account_id, region, eks_oidc_id, trust_policy_file, policy_file):
        super().__init__(account_id, region, eks_oidc_id, None, None, trust_policy_file, policy_file)
        self.role_name = "promethium-s3-access-role"
        self.customer_policy_name = "promethium-s3-access-policy"
        self.aws_managed_policies = []
        self.eks_cluster_name = None
        self.company_name = None
    
    def verify_attached_policies(self):
        """Verify that the required customer policy is attached"""
        print("Verifying Attached Policies:")
        
        attached_managed_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)['AttachedPolicies']
        attached_inline_policies = self.iam_client.list_role_policies(RoleName=self.role_name)['PolicyNames']
        
        managed_policy_names = [policy['PolicyName'] for policy in attached_managed_policies]
        
        print(f"Attached managed policies: {managed_policy_names}")
        print(f"Attached inline policies: {attached_inline_policies}")
        
        if self.customer_policy_name in managed_policy_names:
            print(f"Customer policy '{self.customer_policy_name}' is attached")
            return True
        elif self.customer_policy_name in attached_inline_policies:
            print(f"Customer policy '{self.customer_policy_name}' is attached")
            return True
        else:
            print(f"Customer policy '{self.customer_policy_name}' is NOT attached (neither managed nor inline)")
            return False
    
    def verify_customer_policy_content(self):
        """Verify customer policy content matches expected template"""
        print("Verifying Customer Policy Content:")
        
        try:
            expected_policy = self.load_policy_template(self.customer_policy_file)
        except Exception as e:
            print(f"Failed to load expected customer policy: {e}")
            return False
        
        print(f"Expected customer policy loaded from: {self.customer_policy_file}")
        
        attached_managed_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)['AttachedPolicies']
        managed_policy_names = [policy['PolicyName'] for policy in attached_managed_policies]
        
        if self.customer_policy_name in managed_policy_names:
            print("Verifying Customer Policy Content (managed):")
            policy_arn = f"arn:aws:iam::{self.account_id}:policy/{self.customer_policy_name}"
            try:
                policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                policy_version = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_response['Policy']['DefaultVersionId']
                )
                actual_policy = policy_version['PolicyVersion']['Document']
            except Exception as e:
                print(f"Failed to retrieve managed policy: {e}")
                return False
        else:
            print("Verifying Customer Policy Content (inline):")
            try:
                policy_response = self.iam_client.get_role_policy(RoleName=self.role_name, PolicyName=self.customer_policy_name)
                actual_policy = policy_response['PolicyDocument']
            except Exception as e:
                print(f"Failed to retrieve inline policy: {e}")
                return False
        
        if self.policies_match(expected_policy, actual_policy):
            print("Customer policy matches expected template")
            return True
        else:
            print("Customer policy does NOT match expected template")
            return False


class EksClusterRoleVerifier(RoleVerifier):
    """Verifier for promethium-eks-cluster-role"""
    
    def __init__(self, account_id, region, eks_oidc_id, trust_policy_file):
        super().__init__(account_id, region, eks_oidc_id, None, None, trust_policy_file, None)
        self.role_name = "promethium-eks-cluster-role"
        self.aws_managed_policies = ["AmazonEKSClusterPolicy", "AmazonEKSVPCResourceController"]
        self.customer_policy = None
        self.eks_cluster_name = None
        self.company_name = None
    
    def verify_attached_policies(self):
        """Verify that the required AWS managed policies are attached"""
        print("Verifying Attached Policies:")
        
        attached_managed_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)['AttachedPolicies']
        attached_inline_policies = self.iam_client.list_role_policies(RoleName=self.role_name)['PolicyNames']
        
        managed_policy_names = [policy['PolicyName'] for policy in attached_managed_policies]
        
        print(f"Attached managed policies: {managed_policy_names}")
        print(f"Attached inline policies: {attached_inline_policies}")
        
        all_policies_attached = True
        
        for aws_policy in self.aws_managed_policies:
            if aws_policy in managed_policy_names:
                print(f"AWS managed policy '{aws_policy}' is attached")
            else:
                print(f"AWS managed policy '{aws_policy}' is NOT attached")
                all_policies_attached = False
        
        return all_policies_attached
    
    def verify_customer_policy_content(self):
        """EKS cluster role doesn't have custom policy, so this always returns True"""
        print("No custom policy verification needed for EKS cluster role")
        return True
    
    def verify_trust_policy(self):
        """Verify trust policy matches expected template (eks.amazonaws.com service principal)"""
        print("Verifying Trust Policy:")
        
        try:
            expected_policy = self.load_policy_template(self.trust_policy_file)
        except Exception as e:
            print(f"Failed to load expected trust policy: {e}")
            return False
        
        print(f"Expected trust policy loaded from: {self.trust_policy_file}")
        
        try:
            role_response = self.iam_client.get_role(RoleName=self.role_name)
            actual_policy = role_response['Role']['AssumeRolePolicyDocument']
        except Exception as e:
            print(f"Failed to retrieve role trust policy: {e}")
            return False
        
        if self.policies_match(expected_policy, actual_policy):
            print("Trust policy matches expected template")
            
            policy_str = json.dumps(actual_policy)
            if "eks.amazonaws.com" in policy_str:
                print("EKS service principal 'eks.amazonaws.com' found in trust policy")
            else:
                print("EKS service principal 'eks.amazonaws.com' NOT found in trust policy")
                return False
            
            return True
        else:
            print("Trust policy does NOT match expected template")
            return False


class TrinoOidcRoleVerifier(RoleVerifier):
    """Verifier for promethium-trino-oidc-role"""
    
    def __init__(self, account_id, region, eks_oidc_id, company_name=None, trust_policy_file=None, customer_policy_file=None):
        self.role_name = "promethium-trino-oidc-role"
        self.customer_policy = "promethium-trino-glue-policy"
        self.trust_policy_file = trust_policy_file or "promethium-trino-oidc-role-trust-policy.json"
        self.customer_policy_file = customer_policy_file or "promethium-trino-glue-policy.json"
        super().__init__(account_id, region, eks_oidc_id, company_name=company_name, 
                         trust_policy_file=self.trust_policy_file, customer_policy_file=self.customer_policy_file)
        self.role_name = "promethium-trino-oidc-role"
    
    def verify_attached_policies(self):
        """Verify that the customer policy is attached"""
        print("Verifying Attached Policies:")
        
        try:
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=self.role_name)
            attached_managed_policies = [policy['PolicyName'] for policy in attached_policies['AttachedPolicies']]
            
            inline_policies = self.iam_client.list_role_policies(RoleName=self.role_name)
            attached_inline_policies = inline_policies['PolicyNames']
            
            print(f"Attached managed policies: {attached_managed_policies}")
            print(f"Attached inline policies: {attached_inline_policies}")
            
            if self.customer_policy in attached_managed_policies:
                print(f"Customer policy '{self.customer_policy}' is attached")
                return True
            elif self.customer_policy in attached_inline_policies:
                print(f"Customer policy '{self.customer_policy}' is attached as inline policy")
                return True
            else:
                print(f"Customer policy '{self.customer_policy}' is NOT attached (neither managed nor inline)")
                return False
                
        except ClientError as e:
            print(f"Error checking attached policies: {e}")
            return False
    
    def verify_customer_policy_content(self):
        """Verify the content of the customer policy matches expected template"""
        print("Verifying Customer Policy Content:")
        print(f"Expected customer policy loaded from: {self.customer_policy_file}")
        
        try:
            try:
                policy_arn = f"arn:aws:iam::{self.account_id}:policy/{self.customer_policy}"
                policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
                policy_version_response = self.iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=policy_response['Policy']['DefaultVersionId']
                )
                actual_policy = policy_version_response['PolicyVersion']['Document']
                print("Customer policy found as managed policy")
            except ClientError:
                policy_response = self.iam_client.get_role_policy(
                    RoleName=self.role_name,
                    PolicyName=self.customer_policy
                )
                actual_policy = policy_response['PolicyDocument']
                print("Customer policy found as inline policy")
            
            if self.policies_match(actual_policy, self.expected_customer_policy):
                print("Customer policy matches expected template")
            else:
                print("Customer policy does NOT match expected template")
                return False
            
            actual_policy_str = json.dumps(actual_policy, sort_keys=True)
            if self.company_name and self.company_name in actual_policy_str:
                print(f"Company name '{self.company_name}' found in policy")
            elif self.company_name:
                print(f"Company name '{self.company_name}' NOT found in policy")
                return False
            
            return True
            
        except ClientError as e:
            print(f"Error verifying customer policy content: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description='Verify Promethium EKS IAM roles configuration')
    parser.add_argument('--account-id', required=True, help='AWS Account ID')
    parser.add_argument('--region', required=True, help='AWS Region')
    parser.add_argument('--eks-oidc-id', required=True, help='EKS OIDC Provider ID')
    parser.add_argument('--eks-cluster-name', help='EKS Cluster Name (required for autoscaler role)')
    parser.add_argument('--company-name', help='Company Name (required for EFS CSI role)')
    
    parser.add_argument('--ebscsi-trust-policy-file', help='Path to EBS CSI trust policy template file (default: promethium-ebscsi-role-trust-policy.json)')
    parser.add_argument('--ebscsi-customer-policy-file', help='Path to EBS CSI customer policy template file (default: promethium-eks-kms-access-policy.json)')
    
    parser.add_argument('--autoscaler-trust-policy-file', help='Path to autoscaler trust policy template file (default: promethium-eks-autoscaler-role-trust-policy.json)')
    parser.add_argument('--autoscaler-policy-file', help='Path to autoscaler policy template file (default: promethium-eks-autoscaler-policy.json)')
    
    parser.add_argument('--efscsi-trust-policy-file', help='Path to EFS CSI trust policy template file (default: promethium-efscsi-role-trust-policy.json)')
    parser.add_argument('--efscsi-policy-file', help='Path to EFS CSI policy template file (default: promethium-efscsi-policy.json)')
    
    parser.add_argument('--lbcontroller-trust-policy-file', help='Path to Load Balancer Controller trust policy template file (default: promethium-lbcontroller-role-trust-policy.json)')
    parser.add_argument('--lbcontroller-policy-file', help='Path to Load Balancer Controller policy template file (default: promethium-lbcontroller-policy.json)')
    
    parser.add_argument('--s3access-trust-policy-file', help='Path to S3 access trust policy template file (default: promethium-s3-access-role-trust-policy.json)')
    parser.add_argument('--s3access-policy-file', help='Path to S3 access policy template file (default: promethium-s3-access-policy.json)')
    
    parser.add_argument('--ekscluster-trust-policy-file', help='Path to EKS cluster trust policy template file (default: promethium-eks-cluster-role-trust-policy.json)')
    
    parser.add_argument('--trinooidc-trust-policy-file', help='Path to Trino OIDC trust policy template file (default: promethium-trino-oidc-role-trust-policy.json)')
    parser.add_argument('--trinooidc-policy-file', help='Path to Trino OIDC policy template file (default: promethium-trino-glue-policy.json)')
    
    parser.add_argument('--verify-ebscsi-only', action='store_true', help='Verify only the EBS CSI role')
    parser.add_argument('--verify-autoscaler-only', action='store_true', help='Verify only the autoscaler role (requires --eks-cluster-name)')
    parser.add_argument('--verify-efscsi-only', action='store_true', help='Verify only the EFS CSI role (requires --company-name)')
    parser.add_argument('--verify-lbcontroller-only', action='store_true', help='Verify only the Load Balancer Controller role')
    parser.add_argument('--verify-s3access-only', action='store_true', help='Verify only the S3 access role')
    parser.add_argument('--verify-ekscluster-only', action='store_true', help='Verify only the EKS cluster role')
    parser.add_argument('--verify-trinooidc-only', action='store_true', help='Verify only the Trino OIDC role (requires --company-name)')
    
    args = parser.parse_args()
    
    if args.verify_autoscaler_only and not args.eks_cluster_name:
        print("ERROR: --eks-cluster-name is required when verifying autoscaler role")
        sys.exit(1)
    
    if args.verify_efscsi_only and not args.company_name:
        print("ERROR: --company-name is required when verifying EFS CSI role")
        sys.exit(1)
    
    if args.verify_trinooidc_only and not args.company_name:
        print("ERROR: --company-name is required when verifying Trino OIDC role")
        sys.exit(1)
    
    verification_modes = [args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]
    if sum(verification_modes) > 1:
        print("ERROR: Only one verification mode can be specified")
        sys.exit(1)
    
    success_count = 0
    total_count = 0
    
    if not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]):
        print("=" * 80)
        print("VERIFYING EBS CSI ROLE")
        print("=" * 80)
        
        ebscsi_verifier = RoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.eks_cluster_name,
            args.company_name,
            args.ebscsi_trust_policy_file,
            args.ebscsi_customer_policy_file
        )
        if ebscsi_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]) and args.eks_cluster_name:
        print("\n" + "=" * 80)
        print("VERIFYING AUTOSCALER ROLE")
        print("=" * 80)
        
        autoscaler_verifier = AutoscalerRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.eks_cluster_name,
            args.company_name,
            args.autoscaler_trust_policy_file,
            args.autoscaler_policy_file
        )
        if autoscaler_verifier.run_verification():
            success_count += 1
        total_count += 1
    elif not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]) and not args.eks_cluster_name:
        print("\nWARNING: Skipping autoscaler role verification - --eks-cluster-name not provided")
    
    if not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]) and args.company_name:
        print("\n" + "=" * 80)
        print("VERIFYING EFS CSI ROLE")
        print("=" * 80)
        
        efscsi_verifier = EfscsiRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.company_name,
            args.efscsi_trust_policy_file,
            args.efscsi_policy_file
        )
        if efscsi_verifier.run_verification():
            success_count += 1
        total_count += 1
    elif not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]) and not args.company_name:
        print("\nWARNING: Skipping EFS CSI role verification - --company-name not provided")
    
    if not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]):
        print("\n" + "=" * 80)
        print("VERIFYING LOAD BALANCER CONTROLLER ROLE")
        print("=" * 80)
        
        lbcontroller_verifier = LbcontrollerRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.lbcontroller_trust_policy_file,
            args.lbcontroller_policy_file
        )
        if lbcontroller_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]):
        print("\n" + "=" * 80)
        print("VERIFYING S3 ACCESS ROLE")
        print("=" * 80)
        
        s3access_verifier = S3AccessRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.s3access_trust_policy_file,
            args.s3access_policy_file
        )
        if s3access_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]):
        print("\n" + "=" * 80)
        print("VERIFYING EKS CLUSTER ROLE")
        print("=" * 80)
        
        ekscluster_verifier = EksClusterRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.ekscluster_trust_policy_file
        )
        if ekscluster_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]) and args.company_name:
        print("\n" + "=" * 80)
        print("VERIFYING TRINO OIDC ROLE")
        print("=" * 80)
        
        trinooidc_verifier = TrinoOidcRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.company_name,
            args.trinooidc_trust_policy_file,
            args.trinooidc_policy_file
        )
        if trinooidc_verifier.run_verification():
            success_count += 1
        total_count += 1
    elif not any([args.verify_ebscsi_only, args.verify_autoscaler_only, args.verify_efscsi_only, args.verify_lbcontroller_only, args.verify_s3access_only, args.verify_ekscluster_only, args.verify_trinooidc_only]) and not args.company_name:
        print("\nWARNING: Skipping Trino OIDC role verification - --company-name not provided")
    
    if args.verify_ebscsi_only:
        print("=" * 80)
        print("VERIFYING EBS CSI ROLE (ONLY)")
        print("=" * 80)
        
        ebscsi_verifier = RoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.eks_cluster_name,
            args.company_name,
            args.ebscsi_trust_policy_file,
            args.ebscsi_customer_policy_file
        )
        if ebscsi_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if args.verify_autoscaler_only:
        if not args.eks_cluster_name:
            print("ERROR: --eks-cluster-name is required when verifying autoscaler role only")
            sys.exit(1)
        
        print("=" * 80)
        print("VERIFYING AUTOSCALER ROLE (ONLY)")
        print("=" * 80)
        
        autoscaler_verifier = AutoscalerRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.eks_cluster_name,
            args.company_name,
            args.autoscaler_trust_policy_file,
            args.autoscaler_policy_file
        )
        if autoscaler_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if args.verify_efscsi_only:
        if not args.company_name:
            print("ERROR: --company-name is required when verifying EFS CSI role only")
            sys.exit(1)
        
        print("=" * 80)
        print("VERIFYING EFS CSI ROLE (ONLY)")
        print("=" * 80)
        
        efscsi_verifier = EfscsiRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.company_name,
            args.efscsi_trust_policy_file,
            args.efscsi_policy_file
        )
        if efscsi_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if args.verify_lbcontroller_only:
        print("=" * 80)
        print("VERIFYING LOAD BALANCER CONTROLLER ROLE (ONLY)")
        print("=" * 80)
        
        lbcontroller_verifier = LbcontrollerRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.lbcontroller_trust_policy_file,
            args.lbcontroller_policy_file
        )
        if lbcontroller_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if args.verify_s3access_only:
        print("=" * 80)
        print("VERIFYING S3 ACCESS ROLE (ONLY)")
        print("=" * 80)
        
        s3access_verifier = S3AccessRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.s3access_trust_policy_file,
            args.s3access_policy_file
        )
        if s3access_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if args.verify_ekscluster_only:
        print("=" * 80)
        print("VERIFYING EKS CLUSTER ROLE (ONLY)")
        print("=" * 80)
        
        ekscluster_verifier = EksClusterRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.ekscluster_trust_policy_file
        )
        if ekscluster_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    if args.verify_trinooidc_only:
        if not args.company_name:
            print("ERROR: --company-name is required when verifying Trino OIDC role only")
            sys.exit(1)
        
        print("=" * 80)
        print("VERIFYING TRINO OIDC ROLE (ONLY)")
        print("=" * 80)
        
        trinooidc_verifier = TrinoOidcRoleVerifier(
            args.account_id, 
            args.region, 
            args.eks_oidc_id,
            args.company_name,
            args.trinooidc_trust_policy_file,
            args.trinooidc_policy_file
        )
        if trinooidc_verifier.run_verification():
            success_count += 1
        total_count += 1
    
    print("\n" + "=" * 80)
    print("FINAL RESULTS")
    print("=" * 80)
    print(f"Roles verified: {success_count}/{total_count}")
    
    if success_count == total_count and total_count > 0:
        print(" ALL VERIFICATIONS PASSED!")
        sys.exit(0)
    else:
        print("SOME VERIFICATIONS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
