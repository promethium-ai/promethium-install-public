#!/usr/bin/env python3
"""
Promethium IAM Verification Script

This script verifies that all required AWS IAM roles and policies are properly
configured before running Terraform deployment. It uses minimal AWS permissions
and includes comprehensive testing for placeholder substitutions.

Usage:
    python promethium_iam_verifier.py --account-id 123456789012 --region us-west-2 --eks-oidc-id ABCD1234567890
    python promethium_iam_verifier.py --test-placeholders  # Test placeholder substitution
"""

import argparse
import boto3
import json
import sys
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from botocore.exceptions import ClientError, NoCredentialsError
import re
import hashlib


@dataclass
class VerificationResult:
    """Result of a single verification check"""
    name: str
    status: str  # PASSED, FAILED, WARNING
    message: str
    details: Optional[Dict[str, Any]] = None


class PromethiumIAMVerifier:
    """Main verification class for Promethium IAM setup"""
    
    def __init__(self, account_id: str, region: str, eks_oidc_id: str, company_name: Optional[str] = None):
        self.account_id = account_id
        self.region = region
        self.eks_oidc_id = eks_oidc_id
        self.company_name = company_name or account_id[:8]  # Default to first 8 chars of account ID
        self.iam_client = None
        self.results: List[VerificationResult] = []
        
        try:
            self.iam_client = boto3.client('iam', region_name=region)
            self.iam_client.get_user()
        except NoCredentialsError:
            print("❌ AWS credentials not configured. Run 'aws configure' first.")
            sys.exit(1)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                try:
                    sts_client = boto3.client('sts', region_name=region)
                    sts_client.get_caller_identity()
                    self.iam_client = boto3.client('iam', region_name=region)
                except Exception:
                    print(f"❌ AWS authentication failed: {e}")
                    sys.exit(1)
            else:
                print(f"❌ AWS client initialization failed: {e}")
                sys.exit(1)

    def substitute_placeholders(self, template: str) -> str:
        """Replace placeholders in policy/role templates with actual values"""
        substitutions = {
            '<ACCOUNT_ID>': self.account_id,
            '<account_id>': self.account_id,
            '<REGION>': self.region,
            '<region>': self.region,
            '<EKS_OIDC_ID>': self.eks_oidc_id,
            '<eks_cluster_name>': f'promethium-datafabric-prod-{self.account_id[:8]}-eks-cluster',
            '<company_name>': self.company_name,
            '<install_box_instance_profile_role_arn>': f'arn:aws:iam::{self.account_id}:role/promethium-install-box-role',
            '<terraform_install_role_arn>': f'arn:aws:iam::{self.account_id}:role/promethium-terraform-installation-role'
        }
        
        result = template
        for placeholder, value in substitutions.items():
            result = result.replace(placeholder, value)
        
        return result

    def get_expected_terraform_role_trust_policy(self) -> Dict[str, Any]:
        """Get expected trust policy for terraform installation role"""
        template = """{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "<install_box_instance_profile_role_arn>"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }"""
        
        return json.loads(self.substitute_placeholders(template))

    def get_expected_policies(self) -> Dict[str, Dict[str, Any]]:
        """Get all expected policy documents with placeholders substituted"""
        policies = {}
        
        policies['promethium-terraform-ec2-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EC2CoreActions",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AttachVolume",
                        "ec2:CreateLaunchTemplate",
                        "ec2:CreateLaunchTemplateVersion",
                        "ec2:DeleteLaunchTemplate",
                        "ec2:CreateKeyPair",
                        "ec2:DeleteKeyPair",
                        "ec2:CreateVolume",
                        "ec2:AttachNetworkInterface",
                        "ec2:DetachNetworkInterface",
                        "ec2:DeleteNetworkInterface",
                        "ec2:ModifyInstanceAttribute",
                        "ec2:RunInstances",
                        "ec2:TerminateInstances",
                        "ec2:DetachVolume",
                        "ec2:CreateNetworkInterface"
                    ],
                    "Resource": [
                        "arn:aws:ec2:<region>:<account_id>:instance/*",
                        "arn:aws:ec2:<region>:<account_id>:launch-template/*",
                        "arn:aws:ec2:<region>:<account_id>:key-pair/*",
                        "arn:aws:ec2:<region>:<account_id>:volume/*",
                        "arn:aws:ec2:<region>:<account_id>:network-interface/*",
                        "arn:aws:ec2:<region>:<account_id>:security-group/*",
                        "arn:aws:ec2:<region>:<account_id>:subnet/*",
                        "arn:aws:ec2:<region>::image/*"
                    ]
                },
                {
                    "Sid": "EC2DescribeActions",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceStatus",
                        "ec2:DescribeInstanceAttribute",
                        "ec2:DescribeInstanceTypes",
                        "ec2:DescribeIamInstanceProfileAssociations",
                        "ec2:DescribeInstanceCreditSpecifications",
                        "ec2:DescribeVolumes",
                        "ec2:DescribeKeyPairs",
                        "ec2:DescribeLaunchTemplates",
                        "ec2:DescribeLaunchTemplateVersions",
                        "ec2:DescribeImages",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeTags"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "EC2Tagging",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateTags",
                        "ec2:DeleteTags"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "STSPermissions",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::734236616923:role/promethium-terraform-saas-assume-role"
                },
                {
                    "Sid": "SSMParameter",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:GetParameter"
                    ],
                    "Resource": "arn:aws:ssm:*::parameter/aws/service/eks/optimized-ami/*/amazon-linux-*/recommended/release_version"
                }
            ]
        }"""))

        
        policies['promethium-terraform-acm-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ACMCertGetPermissions",
                    "Effect": "Allow",
                    "Action": [
                        "acm:RequestCertificate",
                        "acm:ListCertificates",
                        "acm:GetCertificate"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "ACMCertCreatePermissions",
                    "Effect": "Allow",
                    "Action": [
                        "acm:DeleteCertificate",
                        "acm:DescribeCertificate",
                        "acm:AddTagsToCertificate",
                        "acm:ListTagsForCertificate"
                    ],
                    "Resource": "arn:aws:acm:<region>:<account_id>:certificate/*"
                }
            ]
        }"""))

        policies['promethium-terraform-efs-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EFSPermissions",
                    "Effect": "Allow",
                    "Action": [
                        "elasticfilesystem:ModifyMountTargetSecurityGroups",
                        "elasticfilesystem:DescribeMountTargets",
                        "elasticfilesystem:UntagResource",
                        "elasticfilesystem:CreateMountTarget",
                        "elasticfilesystem:DescribeLifecycleConfiguration",
                        "elasticfilesystem:DescribeAccessPoints",
                        "elasticfilesystem:DescribeFileSystems",
                        "elasticfilesystem:DeleteMountTarget",
                        "elasticfilesystem:DeleteFileSystem",
                        "elasticfilesystem:DescribeMountTargetSecurityGroups",
                        "elasticfilesystem:TagResource"
                    ],
                    "Resource": [
                        "arn:aws:elasticfilesystem:<region>:<account_id>:access-point/*",
                        "arn:aws:elasticfilesystem:<region>:<account_id>:file-system/*"
                    ]
                },
                {
                    "Sid": "EFSCreatePermissions",
                    "Effect": "Allow",
                    "Action": "elasticfilesystem:CreateFileSystem",
                    "Resource": "*"
                }
            ]
        }"""))

        policies['promethium-terraform-eks-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EKSPermissions",
                    "Effect": "Allow",
                    "Action": [
                        "eks:UpdateClusterVersion",
                        "eks:ListNodegroups",
                        "eks:UntagResource",
                        "eks:ListTagsForResource",
                        "eks:UpdateClusterConfig",
                        "eks:CreateNodegroup",
                        "eks:DeleteCluster",
                        "eks:CreateFargateProfile",
                        "eks:UpdateNodegroupVersion",
                        "eks:ListFargateProfiles",
                        "eks:DescribeNodegroup",
                        "eks:ListUpdates",
                        "eks:DeleteNodegroup",
                        "eks:DescribeUpdate",
                        "eks:TagResource",
                        "eks:UpdateNodegroupConfig",
                        "eks:DescribeCluster"
                    ],
                    "Resource": [
                        "arn:aws:eks:<region>:<account_id>:cluster/<company_name>",
                        "arn:aws:eks:<region>:<account_id>:cluster/promethium*",
                        "arn:aws:eks:<region>:<account_id>:nodegroup/promethium*/*/*"
                    ]
                },
                {
                    "Sid": "EKSCreatePermissions",
                    "Effect": "Allow",
                    "Action": [
                        "eks:ListClusters",
                        "eks:CreateCluster"
                    ],
                    "Resource": "arn:aws:eks:<region>:<account_id>:cluster/*"
                }
            ]
        }"""))

        policies['promethium-terraform-elb-permissions'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "elasticloadbalancing:DescribeLoadBalancerAttributes",
                        "elasticloadbalancing:DescribeLoadBalancers",
                        "elasticloadbalancing:DescribeTags"
                    ],
                    "Resource": "*"
                }
            ]
        }"""))

        policies['promethium-terraform-glue-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "GlueDatabaseManagement",
                    "Effect": "Allow",
                    "Action": [
                        "glue:CreateDatabase",
                        "glue:DeleteDatabase",
                        "glue:UpdateDatabase",
                        "glue:GetDatabase",
                        "glue:GetDatabases"
                    ],
                    "Resource": [
                        "arn:aws:glue:*:<account_id>:database/*_trino",
                        "arn:aws:glue:*:<account_id>:database/*_trino*/*",
                        "arn:aws:glue:*:<account_id>:table/*trino*/*",
                        "arn:aws:glue:*:<account_id>:userDefinedFunction/*trino*/*",
                        "arn:aws:glue:*:<account_id>:catalog"
                    ]
                },
                {
                    "Sid": "GlueCatalogAccess",
                    "Effect": "Allow",
                    "Action": [
                        "glue:GetTags",
                        "glue:TagResource"
                    ],
                    "Resource": [
                        "arn:aws:glue:*:<account_id>:catalog",
                        "arn:aws:glue:*:<account_id>:database/*_trino"
                    ]
                },
                {
                    "Sid": "GlueReadOnlyAccess",
                    "Effect": "Allow",
                    "Action": [
                        "glue:GetDatabase",
                        "glue:GetDatabases"
                    ],
                    "Resource": "*"
                }
            ]
        }"""))

        policies['promethium-terraform-s3-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VisualEditor0",
                    "Effect": "Allow",
                    "Action": [
                        "kms:Decrypt",
                        "kms:Encrypt",
                        "kms:GenerateDataKey",
                        "kms:DescribeKey",
                        "kms:ReEncrypt*"
                    ],
                    "Resource": "arn:aws:kms:*:*:key/*"
                },
                {
                    "Sid": "VisualEditor1",
                    "Effect": "Allow",
                    "Action": [
                        "kms:EnableKeyRotation",
                        "kms:EnableKey",
                        "kms:Decrypt",
                        "kms:ListKeyPolicies",
                        "kms:UntagResource",
                        "kms:PutKeyPolicy",
                        "kms:GetKeyPolicy",
                        "kms:Verify",
                        "kms:ListResourceTags",
                        "kms:DisableKey",
                        "kms:DisableKeyRotation",
                        "kms:TagResource",
                        "kms:Encrypt",
                        "kms:GetKeyRotationStatus",
                        "kms:ScheduleKeyDeletion",
                        "kms:CreateAlias",
                        "kms:DescribeKey",
                        "kms:Sign",
                        "kms:DeleteAlias"
                    ],
                    "Resource": [
                        "arn:aws:kms:<region>:<account_id>:alias/*",
                        "arn:aws:kms:*:<account_id>:key/*"
                    ]
                },
                {
                    "Sid": "VisualEditor2",
                    "Effect": "Allow",
                    "Action": [
                        "s3:CreateBucket",
                        "s3:ListBucket",
                        "s3:GetBucketLocation",
                        "s3:DeleteBucket"
                    ],
                    "Resource": [
                        "arn:aws:s3:::*-trino-*",
                        "arn:aws:s3:::*-postgres-backups-*"
                    ]
                },
                {
                    "Sid": "VisualEditor3",
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutEncryptionConfiguration",
                        "s3:GetEncryptionConfiguration",
                        "s3:GetLifecycleConfiguration",
                        "s3:GetBucketTagging",
                        "s3:PutBucketTagging",
                        "s3:PutLifecycleConfiguration",
                        "s3:PutBucketPolicy",
                        "s3:GetBucketVersioning",
                        "s3:DeleteBucketPolicy",
                        "s3:GetBucketPolicy",
                        "s3:PutBucketVersioning"
                    ],
                    "Resource": [
                        "arn:aws:s3:::*-trino-*",
                        "arn:aws:s3:::*-postgres-backups-*"
                    ]
                },
                {
                    "Sid": "VisualEditor4",
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetAccelerateConfiguration",
                        "s3:GetBucket*",
                        "s3:GetReplicationConfiguration"
                    ],
                    "Resource": [
                        "arn:aws:s3:::*-trino-*",
                        "arn:aws:s3:::*-postgres-backups-*"
                    ]
                },
                {
                    "Sid": "VisualEditor5",
                    "Effect": "Allow",
                    "Action": "s3:List*",
                    "Resource": [
                        "arn:aws:s3:::*-trino-*",
                        "arn:aws:s3:::*-postgres-backups-*"
                    ]
                },
                {
                    "Sid": "VisualEditor6",
                    "Effect": "Allow",
                    "Action": [
                        "kms:CreateKey",
                        "kms:ListAliases"
                    ],
                    "Resource": "*"
                }
            ]
        }"""))

        policies['promethium-terraform-vpc-network-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "VPCModifyResources",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateVpc",
                        "ec2:DeleteVpc",
                        "ec2:ModifyVpcAttribute",
                        "ec2:EnableVpcClassicLink",
                        "ec2:DisableVpcClassicLink",
                        "ec2:EnableVpcClassicLinkDnsSupport"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "SubnetModifyResources",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateSubnet",
                        "ec2:DeleteSubnet",
                        "ec2:ModifySubnetAttribute"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "InternetAndNatGateway",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateInternetGateway",
                        "ec2:DeleteInternetGateway",
                        "ec2:AttachInternetGateway",
                        "ec2:DetachInternetGateway",
                        "ec2:CreateNatGateway",
                        "ec2:DeleteNatGateway"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "RouteTableActions",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateRouteTable",
                        "ec2:DeleteRouteTable",
                        "ec2:CreateRoute",
                        "ec2:DeleteRoute",
                        "ec2:AssociateRouteTable",
                        "ec2:DisassociateRouteTable"
                    ],
                    "Resource": "*"
                },
                {
                    "Sid": "SecurityGroupActions",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:CreateSecurityGroup",
                        "ec2:DeleteSecurityGroup",
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupIngress",
                        "ec2:AuthorizeSecurityGroupEgress",
                        "ec2:RevokeSecurityGroupEgress"
                    ],
                    "Resource": [
                        "arn:aws:ec2:<region>:<account_id>:security-group/*",
                        "arn:aws:ec2:<region>:<account_id>:vpc/*"
                    ]
                },
                {
                    "Sid": "ElasticIPActions",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:AllocateAddress",
                        "ec2:ReleaseAddress",
                        "ec2:AssociateAddress",
                        "ec2:DisassociateAddress"
                    ],
                    "Resource": "arn:aws:ec2:<region>:<account_id>:elastic-ip/*"
                },
                {
                    "Sid": "VPCDescribeResources",
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeVpcs",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeNatGateways",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeAddressesAttribute",
                        "ec2:DescribeVpcAttribute",
                        "ec2:DescribeVpcClassicLink",
                        "ec2:DescribeVpcClassicLinkDnsSupport",
                        "ec2:DescribeAvailabilityZones",
                        "ec2:DescribeSecurityGroups"
                    ],
                    "Resource": "*"
                }
            ]
        }"""))

        policies['promethium-terraform-iam-policy'] = json.loads(self.substitute_placeholders("""{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "IAMResourceScopedPermissions",
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateUser",
                        "iam:CreateRole",
                        "iam:CreateGroup",
                        "iam:AttachUserPolicy",
                        "iam:DetachUserPolicy",
                        "iam:AttachGroupPolicy",
                        "iam:AttachRolePolicy",
                        "iam:PutUserPolicy",
                        "iam:PutRolePolicy",
                        "iam:PutGroupPolicy",
                        "iam:UpdateRole",
                        "iam:UpdateUser",
                        "iam:UpdateGroup",
                        "iam:AddUserToGroup",
                        "iam:PassRole",
                        "iam:TagRole",
                        "iam:CreatePolicyVersion",
                        "iam:CreatePolicy",
                        "iam:CreateOpenIDConnectProvider",
                        "iam:TagOpenIDConnectProvider",
                        "iam:GetOpenIDConnectProvider",
                        "iam:CreateInstanceProfile",
                        "iam:TagPolicy",
                        "iam:TagInstanceProfile",
                        "iam:AddRoleToInstanceProfile",
                        "iam:UpdateAssumeRolePolicy"
                    ],
                    "Resource": [
                        "arn:aws:iam::<account_id>:user/promethium-*",
                        "arn:aws:iam::<account_id>:role/promethium-*",
                        "arn:aws:iam::<account_id>:policy/promethium-*",
                        "arn:aws:iam::<account_id>:policy/*kms*",
                        "arn:aws:iam::<account_id>:group/promethium-*",
                        "arn:aws:iam::<account_id>:instance-profile/promethium*",
                        "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.*.amazonaws.com/id/*"
                    ]
                },
                {
                    "Sid": "IAMResourceDeletePermissions",
                    "Effect": "Allow",
                    "Action": [
                        "iam:DeleteUser",
                        "iam:DeleteRole",
                        "iam:DeleteGroup",
                        "iam:DetachUserPolicy",
                        "iam:DetachGroupPolicy",
                        "iam:DetachRolePolicy",
                        "iam:DeleteUserPolicy",
                        "iam:DeleteRolePolicy",
                        "iam:DeleteGroupPolicy",
                        "iam:RemoveUserFromGroup",
                        "iam:UntagRole",
                        "iam:DeleteOpenIDConnectProvider",
                        "iam:UntagOpenIDConnectProvider",
                        "iam:DeleteInstanceProfile",
                        "iam:UntagPolicy",
                        "iam:UntagInstanceProfile",
                        "iam:RemoveRoleFromInstanceProfile",
                        "iam:DeletePolicy",
                        "iam:DeletePolicyVersion"
                    ],
                    "Resource": [
                        "arn:aws:iam::<account_id>:user/promethium-*",
                        "arn:aws:iam::<account_id>:role/promethium-*",
                        "arn:aws:iam::<account_id>:policy/promethium-*",
                        "arn:aws:iam::<account_id>:policy/*kms*",
                        "arn:aws:iam::<account_id>:policy/*KMS*",
                        "arn:aws:iam::<account_id>:group/promethium-*",
                        "arn:aws:iam::<account_id>:instance-profile/promethium*",
                        "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.*.amazonaws.com/id/*"
                    ]
                },
                {
                    "Sid": "IAMServiceLinkedRole",
                    "Effect": "Allow",
                    "Action": [
                        "iam:CreateServiceLinkedRole",
                        "iam:DeleteServiceLinkedRole"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "iam:AWSServiceName": [
                                "eks.amazonaws.com",
                                "glue.amazonaws.com",
                                "eks-nodegroup.amazonaws.com",
                                "eks-addons.amazonaws.com"
                            ]
                        }
                    }
                }
            ]
        }"""))

        return policies

    def get_expected_custom_policies(self) -> Dict[str, Dict[str, Any]]:
        """Get expected custom policy documents for EKS services"""
        policies = {}
        
        policies['promethium-eks-kms-access-policy'] = json.loads(self.substitute_placeholders("""{
            "Statement": [
                {
                    "Action": [
                        "kms:CreateGrant",
                        "kms:ListGrants",
                        "kms:RevokeGrant"
                    ],
                    "Condition": {
                        "Bool": {
                            "kms:GrantIsForAWSResource": "true"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:kms:<region>:<account_id>:key/*"
                    ]
                },
                {
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:DescribeKey"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:kms:<region>:<account_id>:key/*"
                    ]
                }
            ],
            "Version": "2012-10-17"
        }"""))

        policies['promethium-efscsi-policy'] = json.loads(self.substitute_placeholders("""{
            "Statement": [
                {
                    "Action": [
                        "elasticfilesystem:DescribeAccessPoints",
                        "elasticfilesystem:DescribeFileSystems",
                        "elasticfilesystem:DescribeMountTargets",
                        "ec2:DescribeAvailabilityZones"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "elasticfilesystem:CreateAccessPoint"
                    ],
                    "Condition": {
                        "StringLike": {
                            "aws:RequestTag/cluster-name": "promethium-datafabric-prod-<company_name>-eks-cluster",
                            "aws:RequestTag/efs.csi.aws.com/cluster": "true"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": "elasticfilesystem:DeleteAccessPoint",
                    "Condition": {
                        "StringLike": {
                            "aws:RequestTag/cluster-name": "promethium-datafabric-prod-<company_name>-eks-cluster",
                            "aws:RequestTag/efs.csi.aws.com/cluster": "true"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        }"""))

        policies['promethium-eks-autoscaler-policy'] = json.loads(self.substitute_placeholders("""{
            "Statement": [
                {
                    "Action": [
                        "autoscaling:SetDesiredCapacity",
                        "autoscaling:TerminateInstanceInAutoScalingGroup"
                    ],
                    "Condition": {
                        "StringEquals": {
                            "aws:ResourceTag/k8s.io/cluster-autoscaler/<eks_cluster_name>": "owned"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*",
                    "Sid": "VisualEditor0"
                },
                {
                    "Action": [
                        "autoscaling:DescribeAutoScalingGroups",
                        "autoscaling:DescribeAutoScalingInstances",
                        "autoscaling:DescribeLaunchConfigurations",
                        "autoscaling:DescribeScalingActivities",
                        "ec2:DescribeImages",
                        "ec2:DescribeInstanceTypes",
                        "ec2:DescribeLaunchTemplateVersions",
                        "ec2:GetInstanceTypesFromInstanceRequirements",
                        "eks:DescribeNodegroup"
                    ],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Sid": "VisualEditor1"
                }
            ],
            "Version": "2012-10-17"
        }"""))

        policies['promethium-lbcontroller-policy'] = json.loads(self.substitute_placeholders("""{
            "Statement": [
                {
                    "Action": [
                        "iam:CreateServiceLinkedRole"
                    ],
                    "Condition": {
                        "StringEquals": {
                            "iam:AWSServiceName": "elasticloadbalancing.amazonaws.com"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "ec2:DescribeAccountAttributes",
                        "ec2:DescribeAddresses",
                        "ec2:DescribeAvailabilityZones",
                        "ec2:DescribeInternetGateways",
                        "ec2:DescribeVpcs",
                        "ec2:DescribeVpcPeeringConnections",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeSecurityGroups",
                        "ec2:DescribeInstances",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeTags",
                        "ec2:GetCoipPoolUsage",
                        "ec2:DescribeCoipPools",
                        "elasticloadbalancing:DescribeLoadBalancers",
                        "elasticloadbalancing:DescribeLoadBalancerAttributes",
                        "elasticloadbalancing:DescribeListeners",
                        "elasticloadbalancing:DescribeListenerCertificates",
                        "elasticloadbalancing:DescribeSSLPolicies",
                        "elasticloadbalancing:DescribeRules",
                        "elasticloadbalancing:DescribeTargetGroups",
                        "elasticloadbalancing:DescribeTargetGroupAttributes",
                        "elasticloadbalancing:DescribeTargetHealth",
                        "elasticloadbalancing:DescribeTags"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "cognito-idp:DescribeUserPoolClient",
                        "acm:ListCertificates",
                        "acm:DescribeCertificate",
                        "iam:ListServerCertificates",
                        "iam:GetServerCertificate",
                        "waf-regional:GetWebACL",
                        "waf-regional:GetWebACLForResource",
                        "waf-regional:AssociateWebACL",
                        "waf-regional:DisassociateWebACL",
                        "wafv2:GetWebACL",
                        "wafv2:GetWebACLForResource",
                        "wafv2:AssociateWebACL",
                        "wafv2:DisassociateWebACL",
                        "shield:GetSubscriptionState",
                        "shield:DescribeProtection",
                        "shield:CreateProtection",
                        "shield:DeleteProtection"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupIngress"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "ec2:CreateSecurityGroup"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "ec2:CreateTags"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                        },
                        "StringEquals": {
                            "ec2:CreateAction": "CreateSecurityGroup"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "arn:aws:ec2:*:*:security-group/*"
                },
                {
                    "Action": [
                        "ec2:CreateTags",
                        "ec2:DeleteTags"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "arn:aws:ec2:*:*:security-group/*"
                },
                {
                    "Action": [
                        "ec2:AuthorizeSecurityGroupIngress",
                        "ec2:RevokeSecurityGroupIngress",
                        "ec2:DeleteSecurityGroup"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "elasticloadbalancing:CreateLoadBalancer",
                        "elasticloadbalancing:CreateTargetGroup"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "elasticloadbalancing:CreateListener",
                        "elasticloadbalancing:DeleteListener",
                        "elasticloadbalancing:CreateRule",
                        "elasticloadbalancing:DeleteRule"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "elasticloadbalancing:AddTags",
                        "elasticloadbalancing:RemoveTags"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "true",
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
                    ]
                },
                {
                    "Action": [
                        "elasticloadbalancing:AddTags",
                        "elasticloadbalancing:RemoveTags"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:elasticloadbalancing:*:*:listener/net/*/*/*",
                        "arn:aws:elasticloadbalancing:*:*:listener/app/*/*/*",
                        "arn:aws:elasticloadbalancing:*:*:listener-rule/net/*/*/*",
                        "arn:aws:elasticloadbalancing:*:*:listener-rule/app/*/*/*"
                    ]
                },
                {
                    "Action": [
                        "elasticloadbalancing:ModifyLoadBalancerAttributes",
                        "elasticloadbalancing:SetIpAddressType",
                        "elasticloadbalancing:SetSecurityGroups",
                        "elasticloadbalancing:SetSubnets",
                        "elasticloadbalancing:DeleteLoadBalancer",
                        "elasticloadbalancing:ModifyTargetGroup",
                        "elasticloadbalancing:ModifyTargetGroupAttributes",
                        "elasticloadbalancing:DeleteTargetGroup"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:ResourceTag/elbv2.k8s.aws/cluster": "false"
                        }
                    },
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "elasticloadbalancing:AddTags"
                    ],
                    "Condition": {
                        "Null": {
                            "aws:RequestTag/elbv2.k8s.aws/cluster": "false"
                        },
                        "StringEquals": {
                            "elasticloadbalancing:CreateAction": [
                                "CreateTargetGroup",
                                "CreateLoadBalancer"
                            ]
                        }
                    },
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/net/*/*",
                        "arn:aws:elasticloadbalancing:*:*:loadbalancer/app/*/*"
                    ]
                },
                {
                    "Action": [
                        "elasticloadbalancing:RegisterTargets",
                        "elasticloadbalancing:DeregisterTargets"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:elasticloadbalancing:*:*:targetgroup/*/*"
                },
                {
                    "Action": [
                        "elasticloadbalancing:SetWebAcl",
                        "elasticloadbalancing:ModifyListener",
                        "elasticloadbalancing:AddListenerCertificates",
                        "elasticloadbalancing:RemoveListenerCertificates",
                        "elasticloadbalancing:ModifyRule"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        }"""))

        policies['promethium-s3-access-policy'] = json.loads("""{
            "Statement": [
                {
                    "Action": [
                        "s3:PutObject",
                        "s3:PutObjectAcl"
                    ],
                    "Effect": "Allow",
                    "Resource": "arn:aws:s3:::promethium-postgres-backups-*/*"
                },
                {
                    "Action": [
                        "ecr:GetAuthorizationToken",
                        "ecr:BatchCheckLayerAvailability",
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:GetRepositoryPolicy",
                        "ecr:DescribeRepositories",
                        "ecr:ListImages",
                        "ecr:DescribeImages",
                        "ecr:BatchGetImage",
                        "ecr:GetLifecyclePolicy",
                        "ecr:GetLifecyclePolicyPreview",
                        "ecr:ListTagsForResource",
                        "ecr:DescribeImageScanFindings"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        }""")

        policies['promethium-trino-glue-policy'] = json.loads(self.substitute_placeholders("""{
            "Statement": [
                {
                    "Action": [
                        "glue:GetDatabase",
                        "glue:GetDatabases",
                        "glue:GetTable",
                        "glue:GetTables",
                        "glue:GetPartition",
                        "glue:GetPartitions",
                        "glue:BatchCreatePartition",
                        "glue:CreateTable",
                        "glue:UpdateTable",
                        "glue:DeleteTable",
                        "glue:BatchDeleteTable",
                        "glue:DeleteDatabase",
                        "glue:GetCrawler",
                        "glue:DeleteCrawler",
                        "glue:StopCrawler",
                        "glue:UpdateCrawler",
                        "glue:StartCrawler",
                        "glue:BatchGetPartition"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:glue:<region>:<account_id>:database/cwt*",
                        "arn:aws:glue:<region>:<account_id>:table/*",
                        "arn:aws:glue:<region>:<account_id>:catalog",
                        "arn:aws:glue:<region>:<account_id>:userDefinedFunction/*/*",
                        "arn:aws:glue:<region>:<account_id>:crawler/**"
                    ]
                },
                {
                    "Action": [
                        "glue:GetCrawlers",
                        "glue:ListCrawlers",
                        "glue:CreateDatabase",
                        "glue:CreateCrawler"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "s3:PutObject",
                        "s3:GetObject",
                        "s3:GetObjectTagging",
                        "s3:DeleteObject",
                        "s3:DeleteObjectVersion",
                        "s3:GetObjectVersion",
                        "s3:GetObjectVersionTagging",
                        "s3:GetObjectACL",
                        "s3:PutObjectACL",
                        "s3:ListBucket"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:s3:::*",
                        "arn:aws:s3:::*/*"
                    ]
                },
                {
                    "Action": [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:GenerateDataKey",
                        "kms:DescribeKey"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:kms:<region>:<account_id>:key/*"
                    ]
                },
                {
                    "Action": [
                        "iam:PassRole"
                    ],
                    "Effect": "Allow",
                    "Resource": [
                        "arn:aws:iam::<account_id>:role/AWSGlueServiceRoleDefault"
                    ]
                }
            ],
            "Version": "2012-10-17"
        }"""))
        
        return policies

    def get_expected_roles(self) -> Dict[str, Dict[str, Any]]:
        """Get expected role configurations with trust policies"""
        roles = {}
        
        roles['promethium-ebscsi-role'] = {
            'trust_policy': json.loads(self.substitute_placeholders("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa"
                            }
                        }
                    }
                ]
            }""")),
            'managed_policies': ['arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy'],
            'custom_policies': ['promethium-eks-kms-access-policy']
        }
        
        roles['promethium-eks-cluster-role'] = {
            'trust_policy': json.loads("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "eks.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }"""),
            'managed_policies': [
                'arn:aws:iam::aws:policy/AmazonEKSClusterPolicy',
                'arn:aws:iam::aws:policy/AmazonEKSVPCResourceController'
            ],
            'custom_policies': []
        }
        roles['promethium-efscsi-role'] = {
            'trust_policy': json.loads(self.substitute_placeholders("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>:sub": "system:serviceaccount:kube-system:efs-csi-controller-sa"
                            }
                        }
                    }
                ]
            }""")),
            'managed_policies': [],
            'custom_policies': ['promethium-efscsi-policy']
        }

        roles['promethium-eks-autoscaler-role'] = {
            'trust_policy': json.loads(self.substitute_placeholders("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>:sub": "system:serviceaccount:kube-system:cluster-autoscaler"
                            }
                        }
                    }
                ]
            }""")),
            'managed_policies': [],
            'custom_policies': ['promethium-eks-autoscaler-policy']
        }

        roles['promethium-lbcontroller-role'] = {
            'trust_policy': json.loads(self.substitute_placeholders("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>:sub": "system:serviceaccount:kube-system:aws-load-balancer-controller"
                            }
                        }
                    }
                ]
            }""")),
            'managed_policies': [],
            'custom_policies': ['promethium-lbcontroller-policy']
        }

        roles['promethium-s3-access-role'] = {
            'trust_policy': json.loads(self.substitute_placeholders("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>:sub": [
                                    "system:serviceaccount:intelligentedge:s3-backup-sa",
                                    "system:serviceaccount:intelligentedge:sa-ecr-registry",
                                    "system:serviceaccount:cluster-management:sa-ecr-registry"
                                ]
                            }
                        }
                    }
                ]
            }""")),
            'managed_policies': [],
            'custom_policies': ['promethium-s3-access-policy']
        }

        roles['promethium-eks-worker-role'] = {
            'trust_policy': json.loads("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }"""),
            'managed_policies': [
                'arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly',
                'arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy',
                'arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy',
                'arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore'
            ],
            'custom_policies': ['promethium-eks-kms-access-policy', 'promethium-efscsi-policy']
        }

        roles['promethium-trino-oidc-role'] = {
            'trust_policy': json.loads(self.substitute_placeholders("""{
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Federated": "arn:aws:iam::<account_id>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>"
                        },
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {
                            "StringEquals": {
                                "oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>:sub": "system:serviceaccount:intelligentedge:trino-sa"
                            }
                        }
                    }
                ]
            }""")),
            'managed_policies': [],
            'custom_policies': ['promethium-trino-glue-policy']
        }
        
        return roles

    def verify_role_exists(self, role_name: str) -> VerificationResult:
        """Verify that a role exists"""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            return VerificationResult(
                name=f"Role {role_name}",
                status="PASSED",
                message=f"Role {role_name} exists",
                details={'arn': response['Role']['Arn']}
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return VerificationResult(
                    name=f"Role {role_name}",
                    status="FAILED",
                    message=f"Role {role_name} does not exist"
                )
            else:
                return VerificationResult(
                    name=f"Role {role_name}",
                    status="FAILED",
                    message=f"Error checking role {role_name}: {e}"
                )

    def verify_policy_exists(self, policy_name: str) -> VerificationResult:
        """Verify that a policy exists"""
        policy_arn = f"arn:aws:iam::{self.account_id}:policy/{policy_name}"
        try:
            response = self.iam_client.get_policy(PolicyArn=policy_arn)
            return VerificationResult(
                name=f"Policy {policy_name}",
                status="PASSED",
                message=f"Policy {policy_name} exists",
                details={'arn': policy_arn}
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return VerificationResult(
                    name=f"Policy {policy_name}",
                    status="FAILED",
                    message=f"Policy {policy_name} does not exist"
                )
            else:
                return VerificationResult(
                    name=f"Policy {policy_name}",
                    status="FAILED",
                    message=f"Error checking policy {policy_name}: {e}"
                )

    def verify_trust_policy(self, role_name: str, expected_trust_policy: Dict[str, Any]) -> VerificationResult:
        """Verify role trust policy matches expected"""
        try:
            response = self.iam_client.get_role(RoleName=role_name)
            actual_trust_policy = response['Role']['AssumeRolePolicyDocument']
            
            def normalize_policy(policy):
                return json.dumps(policy, sort_keys=True, separators=(',', ':'))
            
            if normalize_policy(actual_trust_policy) == normalize_policy(expected_trust_policy):
                return VerificationResult(
                    name=f"Trust policy for {role_name}",
                    status="PASSED",
                    message=f"Trust policy for {role_name} matches expected"
                )
            else:
                return VerificationResult(
                    name=f"Trust policy for {role_name}",
                    status="FAILED",
                    message=f"Trust policy for {role_name} does not match expected",
                    details={
                        'expected': expected_trust_policy,
                        'actual': actual_trust_policy
                    }
                )
        except ClientError as e:
            return VerificationResult(
                name=f"Trust policy for {role_name}",
                status="FAILED",
                message=f"Error checking trust policy for {role_name}: {e}"
            )

    def compare_policies(self, actual_policy: Dict[str, Any], expected_policy: Dict[str, Any]) -> str:
        """Compare two policies and return detailed differences"""
        differences = []
        
        if actual_policy.get('Version') != expected_policy.get('Version'):
            differences.append(f"Version mismatch: actual='{actual_policy.get('Version')}' vs expected='{expected_policy.get('Version')}'")
        
        actual_statements = actual_policy.get('Statement', [])
        expected_statements = expected_policy.get('Statement', [])
        
        if len(actual_statements) != len(expected_statements):
            differences.append(f"Statement count mismatch: actual={len(actual_statements)} vs expected={len(expected_statements)}")
        
        for i, (actual_stmt, expected_stmt) in enumerate(zip(actual_statements, expected_statements)):
            stmt_diffs = []
            
            if actual_stmt.get('Sid') != expected_stmt.get('Sid'):
                stmt_diffs.append(f"Sid: actual='{actual_stmt.get('Sid')}' vs expected='{expected_stmt.get('Sid')}'")
            
            if actual_stmt.get('Effect') != expected_stmt.get('Effect'):
                stmt_diffs.append(f"Effect: actual='{actual_stmt.get('Effect')}' vs expected='{expected_stmt.get('Effect')}'")
            
            actual_actions = set(actual_stmt.get('Action', []) if isinstance(actual_stmt.get('Action'), list) else [actual_stmt.get('Action', '')])
            expected_actions = set(expected_stmt.get('Action', []) if isinstance(expected_stmt.get('Action'), list) else [expected_stmt.get('Action', '')])
            
            if actual_actions != expected_actions:
                missing_actions = expected_actions - actual_actions
                extra_actions = actual_actions - expected_actions
                if missing_actions:
                    stmt_diffs.append(f"Missing actions: {sorted(missing_actions)}")
                if extra_actions:
                    stmt_diffs.append(f"Extra actions: {sorted(extra_actions)}")
            
            actual_resources = actual_stmt.get('Resource', [])
            expected_resources = expected_stmt.get('Resource', [])
            if isinstance(actual_resources, str):
                actual_resources = [actual_resources]
            if isinstance(expected_resources, str):
                expected_resources = [expected_resources]
            
            if set(actual_resources) != set(expected_resources):
                stmt_diffs.append(f"Resource mismatch: actual={actual_resources} vs expected={expected_resources}")
            
            actual_condition = actual_stmt.get('Condition', {})
            expected_condition = expected_stmt.get('Condition', {})
            if actual_condition != expected_condition:
                stmt_diffs.append(f"Condition mismatch: actual={actual_condition} vs expected={expected_condition}")
            
            if stmt_diffs:
                differences.append(f"Statement {i} ({actual_stmt.get('Sid', 'unnamed')}): {'; '.join(stmt_diffs)}")
        
        return '; '.join(differences) if differences else "No differences found"

    def verify_policy_document(self, policy_name: str, expected_document: Dict[str, Any]) -> VerificationResult:
        """Verify policy document matches expected"""
        policy_arn = f"arn:aws:iam::{self.account_id}:policy/{policy_name}"
        try:
            policy_response = self.iam_client.get_policy(PolicyArn=policy_arn)
            default_version_id = policy_response['Policy']['DefaultVersionId']
            
            version_response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=default_version_id
            )
            actual_document = version_response['PolicyVersion']['Document']
            
            def normalize_policy(policy):
                return json.dumps(policy, sort_keys=True, separators=(',', ':'))
            
            if normalize_policy(actual_document) == normalize_policy(expected_document):
                return VerificationResult(
                    name=f"Policy document for {policy_name}",
                    status="PASSED",
                    message=f"Policy document for {policy_name} matches expected"
                )
            else:
                differences = self.compare_policies(actual_document, expected_document)
                return VerificationResult(
                    name=f"Policy document for {policy_name}",
                    status="FAILED",
                    message=f"Policy document for {policy_name} does not match expected. Differences: {differences}",
                    details={
                        'expected': expected_document,
                        'actual': actual_document,
                        'differences': differences
                    }
                )
        except ClientError as e:
            return VerificationResult(
                name=f"Policy document for {policy_name}",
                status="FAILED",
                message=f"Error checking policy document for {policy_name}: {e}"
            )

    def verify_all(self) -> Dict[str, Any]:
        """Run all verifications and return comprehensive results"""
        print("🔍 Starting Promethium IAM verification...")
        print(f"   Account ID: {self.account_id}")
        print(f"   Region: {self.region}")
        print(f"   EKS OIDC ID: {self.eks_oidc_id}")
        print()
        
        expected_policies = self.get_expected_policies()
        expected_roles = self.get_expected_roles()
        
        terraform_role_result = self.verify_role_exists('promethium-terraform-installation-role')
        self.results.append(terraform_role_result)
        
        if terraform_role_result.status == "PASSED":
            trust_policy_result = self.verify_trust_policy(
                'promethium-terraform-installation-role',
                self.get_expected_terraform_role_trust_policy()
            )
            self.results.append(trust_policy_result)
        
        print("📋 Verifying Terraform custom policies...")
        for policy_name, expected_doc in expected_policies.items():
            policy_result = self.verify_policy_exists(policy_name)
            self.results.append(policy_result)
            
            if policy_result.status == "PASSED":
                doc_result = self.verify_policy_document(policy_name, expected_doc)
                self.results.append(doc_result)
        
        print("📋 Verifying EKS custom policies...")
        expected_custom_policies = self.get_expected_custom_policies()
        for policy_name, expected_doc in expected_custom_policies.items():
            policy_result = self.verify_policy_exists(policy_name)
            self.results.append(policy_result)
            
            if policy_result.status == "PASSED":
                doc_result = self.verify_policy_document(policy_name, expected_doc)
                self.results.append(doc_result)
        
        print("👥 Verifying EKS service roles...")
        for role_name, config in expected_roles.items():
            role_result = self.verify_role_exists(role_name)
            self.results.append(role_result)
            
            if role_result.status == "PASSED":
                trust_result = self.verify_trust_policy(role_name, config['trust_policy'])
                self.results.append(trust_result)
        
        passed = len([r for r in self.results if r.status == "PASSED"])
        failed = len([r for r in self.results if r.status == "FAILED"])
        warnings = len([r for r in self.results if r.status == "WARNING"])
        
        overall_status = "PASSED" if failed == 0 else "FAILED"
        if warnings > 0 and failed == 0:
            overall_status = "WARNINGS"
        
        return {
            "verification_status": overall_status,
            "timestamp": "2025-07-18T03:29:18Z",
            "account_id": self.account_id,
            "region": self.region,
            "eks_oidc_id": self.eks_oidc_id,
            "summary": {
                "total_checks": len(self.results),
                "passed": passed,
                "failed": failed,
                "warnings": warnings
            },
            "results": [
                {
                    "name": r.name,
                    "status": r.status,
                    "message": r.message,
                    "details": r.details
                }
                for r in self.results
            ]
        }

    def print_results(self, results: Dict[str, Any]):
        """Print formatted verification results"""
        status_emoji = {
            "PASSED": "✅",
            "FAILED": "❌", 
            "WARNINGS": "⚠️"
        }
        
        print(f"\n{status_emoji[results['verification_status']]} Verification {results['verification_status']}")
        print(f"📊 Summary: {results['summary']['passed']} passed, {results['summary']['failed']} failed, {results['summary']['warnings']} warnings")
        print()
        
        for status in ["FAILED", "WARNING", "PASSED"]:
            status_results = [r for r in results['results'] if r['status'] == status]
            if status_results:
                print(f"{status_emoji[status]} {status} ({len(status_results)}):")
                for result in status_results:
                    print(f"  • {result['message']}")
                print()


def test_placeholder_substitution():
    """Test placeholder substitution functionality"""
    print("🧪 Testing placeholder substitution...")
    
    test_account_id = "123456789012"
    test_region = "us-west-2"
    test_eks_oidc_id = "ABCD1234567890EXAMPLE"
    
    test_company_name = "testcomp"
    
    verifier = PromethiumIAMVerifier.__new__(PromethiumIAMVerifier)
    verifier.account_id = test_account_id
    verifier.region = test_region
    verifier.eks_oidc_id = test_eks_oidc_id
    verifier.company_name = test_company_name
    verifier.iam_client = None
    verifier.results = []
    
    test_cases = [
        {
            "name": "Basic placeholders",
            "template": "arn:aws:iam::<account_id>:role/test-<region>-role",
            "expected": f"arn:aws:iam::{test_account_id}:role/test-{test_region}-role"
        },
        {
            "name": "EKS OIDC placeholder",
            "template": "oidc.eks.<region>.amazonaws.com/id/<EKS_OIDC_ID>:sub",
            "expected": f"oidc.eks.{test_region}.amazonaws.com/id/{test_eks_oidc_id}:sub"
        },
        {
            "name": "Company name derivation",
            "template": "promethium-datafabric-prod-<company_name>-eks-cluster",
            "expected": f"promethium-datafabric-prod-{test_company_name}-eks-cluster"
        },
        {
            "name": "Mixed case placeholders",
            "template": "<ACCOUNT_ID> and <account_id> should both work",
            "expected": f"{test_account_id} and {test_account_id} should both work"
        }
    ]
    
    all_passed = True
    for test_case in test_cases:
        result = verifier.substitute_placeholders(test_case["template"])
        if result == test_case["expected"]:
            print(f"  ✅ {test_case['name']}: PASSED")
        else:
            print(f"  ❌ {test_case['name']}: FAILED")
            print(f"     Expected: {test_case['expected']}")
            print(f"     Got:      {result}")
            all_passed = False
    
    print("\n🔧 Testing policy template substitution...")
    expected_policies = verifier.get_expected_policies()
    
    for policy_name, policy_doc in expected_policies.items():
        policy_str = json.dumps(policy_doc)
        remaining_placeholders = re.findall(r'<[^>]+>', policy_str)
        
        if remaining_placeholders:
            print(f"  ❌ {policy_name}: Found unsubstituted placeholders: {remaining_placeholders}")
            all_passed = False
        else:
            print(f"  ✅ {policy_name}: All placeholders substituted")
    
    print("\n🔧 Testing EKS custom policy template substitution...")
    expected_custom_policies = verifier.get_expected_custom_policies()
    
    for policy_name, policy_doc in expected_custom_policies.items():
        policy_str = json.dumps(policy_doc)
        remaining_placeholders = re.findall(r'<[^>]+>', policy_str)
        
        if remaining_placeholders:
            print(f"  ❌ {policy_name}: Found unsubstituted placeholders: {remaining_placeholders}")
            all_passed = False
        else:
            print(f"  ✅ {policy_name}: All placeholders substituted")
    
    print("\n👥 Testing role trust policy substitution...")
    expected_roles = verifier.get_expected_roles()
    
    for role_name, role_config in expected_roles.items():
        trust_policy_str = json.dumps(role_config['trust_policy'])
        remaining_placeholders = re.findall(r'<[^>]+>', trust_policy_str)
        
        if remaining_placeholders:
            print(f"  ❌ {role_name}: Found unsubstituted placeholders: {remaining_placeholders}")
            all_passed = False
        else:
            print(f"  ✅ {role_name}: All placeholders substituted")
    
    print(f"\n{'✅ All placeholder tests PASSED!' if all_passed else '❌ Some placeholder tests FAILED!'}")
    return all_passed


def main():
    parser = argparse.ArgumentParser(description='Verify Promethium IAM setup')
    parser.add_argument('--account-id', required=False, help='AWS Account ID')
    parser.add_argument('--region', required=False, help='AWS Region')
    parser.add_argument('--eks-oidc-id', required=False, help='EKS OIDC Provider ID')
    parser.add_argument('--company-name', required=False, help='Company name for cluster naming (defaults to first 8 chars of account ID)')
    parser.add_argument('--test-placeholders', action='store_true', help='Test placeholder substitution')
    parser.add_argument('--output-json', help='Output results to JSON file')
    
    args = parser.parse_args()
    
    if args.test_placeholders:
        success = test_placeholder_substitution()
        sys.exit(0 if success else 1)
    
    if not all([args.account_id, args.region, args.eks_oidc_id]):
        print("❌ Missing required arguments. Use --help for usage information.")
        sys.exit(1)
    
    try:
        verifier = PromethiumIAMVerifier(args.account_id, args.region, args.eks_oidc_id, args.company_name)
        results = verifier.verify_all()
        
        verifier.print_results(results)
        
        if args.output_json:
            with open(args.output_json, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"📄 Results saved to {args.output_json}")
        
        sys.exit(0 if results['verification_status'] == 'PASSED' else 1)
        
    except Exception as e:
        print(f"❌ Verification failed with error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
