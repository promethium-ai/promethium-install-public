#!/bin/bash

# Exit on error
set -e

if [ -z "$1" ] || [ -z "$2" ] || [-z "$3" ]; then
  echo "Usage: $0 <vpc_id> <region> <company_name>"
  exit 1
fi

VPC_ID="$1"
REGION="$2"
CUSTOMER="$3"

echo "Fetching subnets for VPC ID: $VPC_ID in region: $REGION..."

# Get list of Subnet IDs in the VPC
SUBNET_IDS=$(aws ec2 describe-subnets \
  --region "$REGION" \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query "Subnets[*].SubnetId" \
  --output text)

if [ -z "$SUBNET_IDS" ]; then
  echo "No subnets found for VPC ID: $VPC_ID in region: $REGION"
  exit 1
fi

echo "Found subnets: $SUBNET_IDS"

# Apply tags to each subnet
for subnet_id in $SUBNET_IDS; do
  echo "Tagging subnet: $subnet_id"
  aws ec2 create-tags \
    --region "$REGION" \
    --resources "$subnet_id" \
    --tags \
      Key=promethium-datafabric-prod-${CUSTOMER}-eks-cluster,Value=owned \
      Key=kubernetes.io/role/internal-elb,Value=1
done

echo "Tagging complete."
