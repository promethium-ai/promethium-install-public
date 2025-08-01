#!/usr/bin/env python3
"""
AWS IAM Role Verification Script

This script verifies that a customer's IAM role has all the required permissions
specified in the Promethium Terraform policies and validates the trust policy.

Usage:
    python aws_role_verification.py --account-id <account_id> --region <region> \
        --install-box-role-arn <install_box_role_arn> --customer-role-arn <customer_role_arn> \
        [--policies-dir <path_to_policies_directory>]
"""

import argparse
import json
import sys
import os
from typing import Dict, List, Set, Tuple, Any
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import re


class PolicyVerifier:
    def __init__(self, account_id: str, region: str, install_box_role_arn: str, customer_role_arn: str, policies_dir: str = None):
        self.account_id = account_id
        self.region = region
        self.install_box_role_arn = install_box_role_arn
        self.customer_role_arn = customer_role_arn
        
        if policies_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            self.policies_dir = os.path.join(script_dir, 'policies')
        else:
            self.policies_dir = policies_dir
        
        if not os.path.exists(self.policies_dir):
            print(f"ERROR: Policies directory not found: {self.policies_dir}")
            print("Please ensure the policies directory exists with the required policy JSON files.")
            sys.exit(1)
        
        try:
            self.iam_client = boto3.client('iam')
            self.sts_client = boto3.client('sts')
        except NoCredentialsError:
            print("ERROR: AWS credentials not configured. Please configure AWS CLI credentials.")
            sys.exit(1)
    
    def load_policy_from_file(self, filename: str) -> Dict:
        """Load a policy from a JSON file"""
        filepath = os.path.join(self.policies_dir, filename)
        try:
            with open(filepath, 'r') as f:
                policy = json.load(f)
                return self.substitute_placeholders(policy)
        except FileNotFoundError:
            print(f"ERROR: Policy file not found: {filepath}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON in policy file {filepath}: {e}")
            sys.exit(1)
    
    def substitute_placeholders(self, policy: Dict) -> Dict:
        """Replace placeholders in policy with actual values"""
        policy_str = json.dumps(policy)
        policy_str = policy_str.replace('<region>', self.region)
        policy_str = policy_str.replace('<account_id>', self.account_id)
        policy_str = policy_str.replace('<install_box_instance_profile_role_arn>', self.install_box_role_arn)
        return json.loads(policy_str)
    
    def get_required_policies(self) -> Dict[str, Dict]:
        """Load all required policies from filesystem"""
        policy_files = {
            "ACM Policy": "promethium-terraform-acm-policy",
            "EC2 Policy": "promethium-terraform-ec2-policy", 
            "EFS Policy": "promethium-terraform-efs-policy",
            "EKS Policy": "promethium-terraform-eks-policy",
            "ELB Policy": "promethium-terraform-elb-permissions",
            "Glue Policy": "promethium-terraform-glue-policy",
            #"IAM Policy": "promethium-terraform-iam-policy",
            "S3 Policy": "promethium-terraform-s3-policy",
            "VPC Network Policy": "promethium-terraform-vpc-network-policy",
        }
        
        policies = {}
        for policy_name, filename in policy_files.items():
            policies[policy_name] = self.load_policy_from_file(filename)
        
        return policies

    def get_required_trust_policy(self) -> Dict:
        """Load the required trust policy from filesystem"""
        return self.load_policy_from_file("promethium-terraform-install-role-trust-policy")

    def get_role_policies(self, role_name: str) -> Tuple[List[Dict], List[Dict]]:
        """Get all policies attached to a role (managed and inline)"""
        try:
            managed_policies = []
            paginator = self.iam_client.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy in page['AttachedPolicies']:
                    policy_arn = policy['PolicyArn']
                    policy_version = self.iam_client.get_policy(PolicyArn=policy_arn)
                    policy_document = self.iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy_version['Policy']['DefaultVersionId']
                    )
                    managed_policies.append({
                        'PolicyName': policy['PolicyName'],
                        'PolicyArn': policy_arn,
                        'Document': policy_document['PolicyVersion']['Document']
                    })

            inline_policies = []
            paginator = self.iam_client.get_paginator('list_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                for policy_name in page['PolicyNames']:
                    policy_document = self.iam_client.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    inline_policies.append({
                        'PolicyName': policy_name,
                        'Document': policy_document['PolicyDocument']
                    })

            return managed_policies, inline_policies

        except ClientError as e:
            print(f"ERROR: Failed to get policies for role {role_name}: {e}")
            return [], []

    def get_role_trust_policy(self, role_name: str) -> Dict:
        """Get the trust policy (assume role policy) for a role"""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return response['Role']['AssumeRolePolicyDocument']
        except ClientError as e:
            print(f"ERROR: Failed to get trust policy for role {role_name}: {e}")
            return {}

    def prepare_simulation_resources(self, resources: List[str]) -> List[str]:
        """Prepare resource ARNs for simulation, handling wildcards appropriately"""
        simulation_resources = []
        for resource in resources:
            if resource == '*':
                simulation_resources.append('*')
            elif '*' in resource:
                simulation_resources.append(resource)
            else:
                simulation_resources.append(resource)
        return simulation_resources
    
    def prepare_simulation_resources_for_action(self, action: str, resources: List[str]) -> List[str]:
        """Prepare resource ARNs for simulation based on specific action requirements"""
        actions_requiring_wildcard = {
            'ec2:TerminateInstances',
            'ec2:CreateTags',
            'ec2:DeleteTags',
            'ec2:DescribeInstances',
            'ec2:DescribeVolumes',
            'ec2:DescribeNetworkInterfaces',
            'ec2:DescribeTags'
        }
        
        actions_supporting_specific_resources = {
            's3:GetObject',
            's3:PutObject',
            's3:DeleteObject',
            'acm:DeleteCertificate',
            'acm:DescribeCertificate',
            'acm:AddTagsToCertificate',
            'acm:ListTagsForCertificate'
        }
        
        if action in actions_requiring_wildcard:
            return ['*']
        elif action in actions_supporting_specific_resources:
            return self.prepare_simulation_resources(resources)
        else:
            prepared = self.prepare_simulation_resources(resources)
            return prepared
    
    def get_context_entries(self, statement: Dict) -> List[Dict]:
        """Extract context entries from policy statement conditions for simulation"""
        context_entries = {}  # Use dict to deduplicate by context key
        conditions = statement.get('Condition', {})
        
        for condition_operator, condition_block in conditions.items():
            for context_key, values in condition_block.items():
                if isinstance(values, str):
                    values = [values]
                
                if context_key in context_entries:
                    existing_values = set(context_entries[context_key]['ContextKeyValues'])
                    new_values = set(values)
                    combined_values = list(existing_values.union(new_values))
                    context_entries[context_key]['ContextKeyValues'] = combined_values
                else:
                    context_entries[context_key] = {
                        'ContextKeyName': context_key,
                        'ContextKeyValues': list(values),
                        'ContextKeyType': 'string'
                    }
        
        return list(context_entries.values())

    def simulate_statement_permissions(self, required_statement: Dict, role_arn: str) -> Tuple[bool, List[str]]:
        """Use AWS IAM simulation to check if a required statement's permissions are covered by the role"""
        missing_permissions = []
        
        required_actions = required_statement.get('Action', [])
        if isinstance(required_actions, str):
            required_actions = [required_actions]
        
        required_resources = required_statement.get('Resource', ['*'])
        if isinstance(required_resources, str):
            required_resources = [required_resources]
        
        context_entries = self.get_context_entries(required_statement)
        
        for action in required_actions:
            max_retries = 3
            base_delay = 0.2
            
            for attempt in range(max_retries + 1):
                try:
                    import time
                    import random
                    
                    if attempt > 0:
                        delay = base_delay * (2 ** (attempt - 1)) + random.uniform(0, 0.1)
                        print(f"  Retrying {action} after {delay:.2f}s (attempt {attempt + 1}/{max_retries + 1})")
                        time.sleep(delay)
                    else:
                        time.sleep(0.1)  # Base delay between calls
                    
                    simulation_resources = self.prepare_simulation_resources_for_action(action, required_resources)
                    
                    simulation_params = {
                        'PolicySourceArn': role_arn,
                        'ActionNames': [action],  # Single action to avoid grouping issues
                        'ResourceArns': simulation_resources
                    }
                    
                    if context_entries:
                        simulation_params['ContextEntries'] = context_entries
                    
                    response = self.iam_client.simulate_principal_policy(**simulation_params)
                    
                    for result in response['EvaluationResults']:
                        if result['EvalDecision'] != 'allowed':
                            resource = result.get('EvalResourceName', '*')
                            decision = result['EvalDecision']
                            missing_permissions.append(f"Action: {action}, Resource: {resource}, Decision: {decision}")
                    
                    break
                    
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    
                    if error_code == 'Throttling' and attempt < max_retries:
                        continue
                    elif error_code == 'AccessDenied':
                        print(f"ERROR: Access denied for simulation. Ensure you have 'iam:SimulatePrincipalPolicy' permission.")
                        missing_permissions.append(f"Action: {action}, Simulation failed: Access denied")
                        break
                    elif error_code == 'NoSuchEntity':
                        print(f"ERROR: Role not found: {role_arn}")
                        missing_permissions.append(f"Action: {action}, Simulation failed: Role not found")
                        break
                    elif error_code == 'InvalidInput':
                        print(f"WARNING: AWS API limitation for action {action}: {e}")
                        try:
                            fallback_params = {
                                'PolicySourceArn': role_arn,
                                'ActionNames': [action],
                                'ResourceArns': ['*']  # Use wildcard for problematic actions
                            }
                            if context_entries:
                                fallback_params['ContextEntries'] = context_entries
                            
                            response = self.iam_client.simulate_principal_policy(**fallback_params)
                            for result in response['EvaluationResults']:
                                if result['EvalDecision'] != 'allowed':
                                    decision = result['EvalDecision']
                                    missing_permissions.append(f"Action: {action}, Resource: *, Decision: {decision}")
                        except ClientError as fallback_error:
                            print(f"ERROR: Fallback simulation also failed for {action}: {fallback_error}")
                            missing_permissions.append(f"Action: {action}, Simulation failed: {fallback_error}")
                        break
                    else:
                        if attempt < max_retries:
                            print(f"WARNING: Retrying {action} due to error: {e}")
                            continue
                        else:
                            print(f"ERROR: Failed to simulate permissions for {action} after {max_retries + 1} attempts: {e}")
                            missing_permissions.append(f"Action: {action}, Simulation failed: {e}")
                            break
        
        return len(missing_permissions) == 0, missing_permissions

    def verify_permissions(self) -> Tuple[bool, Dict[str, List[str]]]:
        """Verify that the role has all required permissions using AWS IAM simulation"""
        role_name = self.customer_role_arn.split('/')[-1]
        
        print(f"Verifying permissions for role: {role_name}")
        print(f"Role ARN: {self.customer_role_arn}")
        print("Using AWS IAM Policy Simulation for accurate verification...")
        
        try:
            self.iam_client.get_role(RoleName=role_name)
        except ClientError as e:
            print(f"ERROR: Failed to get role {role_name}: {e}")
            return False, {"Role Access": [f"Cannot access role: {e}"]}
        
        required_policies = self.get_required_policies()
        missing_permissions = {}
        all_permissions_valid = True
        
        for policy_name, policy_doc in required_policies.items():
            print(f"\nSimulating {policy_name}...")
            
            policy_missing = []
            statements = policy_doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            
            for statement in statements:
                statement_valid, statement_missing = self.simulate_statement_permissions(
                    statement, self.customer_role_arn
                )
                
                if not statement_valid:
                    policy_missing.extend(statement_missing)
            
            if policy_missing:
                missing_permissions[policy_name] = policy_missing
                all_permissions_valid = False
                print(f"   Missing permissions in {policy_name}")
            else:
                print(f"   All permissions verified for {policy_name}")
        
        return all_permissions_valid, missing_permissions

    def verify_trust_policy(self) -> Tuple[bool, str]:
        """Verify that the role's trust policy allows the install box role to assume it"""
        role_name = self.customer_role_arn.split('/')[-1]
        
        print(f"\nVerifying trust policy for role: {role_name}")
        
        trust_policy = self.get_role_trust_policy(role_name)
        if not trust_policy:
            return False, "Could not retrieve trust policy"
        
        required_trust_policy = self.get_required_trust_policy()
        
        statements = trust_policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            if 'sts:AssumeRole' not in statement.get('Action', []):
                continue
            
            principal = statement.get('Principal', {})
            if isinstance(principal, dict):
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                
                if self.install_box_role_arn in aws_principals:
                    print("   Trust policy allows install box role to assume this role")
                    return True, "Trust policy is valid"
                
                for aws_principal in aws_principals:
                    if aws_principal == '*':
                        print("    Trust policy allows any principal (wildcard)")
                        return True, "Trust policy allows wildcard access"
                    
                    if aws_principal == f"arn:aws:iam::{self.account_id}:root":
                        print("    Trust policy allows account root")
                        return True, "Trust policy allows account root access"
        
        print("   Trust policy does not allow install box role to assume this role")
        return False, f"Trust policy does not include install box role ARN: {self.install_box_role_arn}"

    def run_verification(self) -> bool:
        """Run the complete verification process"""
        print("=" * 80)
        print("AWS IAM Role Verification for Promethium Terraform")
        print("=" * 80)
        print(f"Account ID: {self.account_id}")
        print(f"Region: {self.region}")
        print(f"Install Box Role ARN: {self.install_box_role_arn}")
        print(f"Customer Role ARN: {self.customer_role_arn}")
        print("=" * 80)
        
        try:
            caller_identity = self.sts_client.get_caller_identity()
            print(f"Running verification as: {caller_identity.get('Arn', 'Unknown')}")
        except ClientError as e:
            print(f"ERROR: Failed to get caller identity: {e}")
            return False
        
        permissions_valid, missing_permissions = self.verify_permissions()
        
        trust_policy_valid, trust_policy_message = self.verify_trust_policy()
        
        print("\n" + "=" * 80)
        print("VERIFICATION SUMMARY")
        print("=" * 80)
        
        if permissions_valid:
            print(" PERMISSIONS: All required permissions are present")
        else:
            print(" PERMISSIONS: Missing required permissions")
            for policy_name, missing in missing_permissions.items():
                print(f"\n  Missing in {policy_name}:")
                for permission in missing:
                    print(f"    - {permission}")
        
        if trust_policy_valid:
            print(f" TRUST POLICY: {trust_policy_message}")
        else:
            print(f" TRUST POLICY: {trust_policy_message}")
        
        overall_result = permissions_valid and trust_policy_valid
        
        print(f"\n{' OVERALL RESULT: VERIFICATION PASSED' if overall_result else ' OVERALL RESULT: VERIFICATION FAILED'}")
        print("=" * 80)
        
        return overall_result


def main():
    parser = argparse.ArgumentParser(
        description='Verify AWS IAM role has required Promethium Terraform permissions'
    )
    parser.add_argument('--account-id', required=True,
                       help='AWS Account ID where the role exists')
    parser.add_argument('--region', required=True,
                       help='AWS Region')
    parser.add_argument('--install-box-role-arn', required=True,
                       help='ARN of the install box instance profile role')
    parser.add_argument('--customer-role-arn', required=True,
                       help='ARN of the customer role to verify')
    parser.add_argument('--policies-dir', 
                       help='Directory containing policy JSON files (default: ./policies)')
    
    args = parser.parse_args()
    
    verifier = PolicyVerifier(
        account_id=args.account_id,
        region=args.region,
        install_box_role_arn=args.install_box_role_arn,
        customer_role_arn=args.customer_role_arn,
        policies_dir=args.policies_dir
    )
    
    success = verifier.run_verification()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
