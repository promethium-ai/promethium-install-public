#!/bin/bash

# Exit on error
set -e

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
  echo "Usage: $0 <vpc_id> <region> <company_name> [cluster_name]"
  exit 1
fi

VPC_ID="$1"
REGION="$2"
CUSTOMER="$3"
CLUSTER_NAME="$4"

# If cluster name is not provided, build it
if [ -z "$CLUSTER_NAME" ]; then
  CLUSTER_NAME="promethium-datafabric-prod-${CUSTOMER}-eks-cluster"
fi

echo "Using cluster name: $CLUSTER_NAME"
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

# Apply tags only to PUBLIC subnets (local + igw)
for subnet_id in $SUBNET_IDS; do
  echo "Checking subnet: $subnet_id"

  # Get all routes for this subnet (via its route tables)
  ROUTES=$(aws ec2 describe-route-tables \
    --region "$REGION" \
    --filters "Name=association.subnet-id,Values=$subnet_id" \
    --query "RouteTables[].Routes[].GatewayId" \
    --output text)

  # If no explicit route table association, check the main one
  if [ -z "$ROUTES" ]; then
    ROUTES=$(aws ec2 describe-route-tables \
      --region "$REGION" \
      --filters "Name=vpc-id,Values=$VPC_ID" "Name=association.main,Values=true" \
      --query "RouteTables[].Routes[].GatewayId" \
      --output text)
  fi

  echo "Routes for subnet $subnet_id: $ROUTES"

  # Check if one of the routes is an Internet Gateway
  if echo "$ROUTES" | grep -q "igw-"; then
    echo "Subnet $subnet_id has IGW (PUBLIC). Tagging..."
    aws ec2 create-tags \
      --region "$REGION" \
      --resources "$subnet_id" \
      --tags \
        Key=kubernetes.io/cluster/${CLUSTER_NAME},Value=owned \
        Key=kubernetes.io/role/internal-elb,Value=1
  else
    echo "Subnet $subnet_id is PRIVATE. Skipping..."
  fi
done

echo "Tagging complete."

