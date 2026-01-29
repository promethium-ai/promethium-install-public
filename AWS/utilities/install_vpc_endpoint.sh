#!/usr/bin/env bash
set -euo pipefail

############################################
# Usage:
# ./install_vpc_endpoint.sh \
#   --region us-east-1 \
#   --stack-name my-stack \
#   --template-file path/to/template.yaml \
#   --parameters \
#     VpcId=vpc-xxxx \
#     RouteTableIds=rtb-xxxx \
#     SubnetId=subnet-xxxx \
#     AvailabilityZone=us-east-1b \
#     SecurityGroupIds=sg-xxxx \
#     AwsRegion=us-east-1 \
#     AddEndpointPolicy=false \
#     AllowedBucketArns='' \
#     GlueConnectionName=my-glue-connection \
#     GlueConnectionDescription="Glue connection"
#
# To delete an existing stack:
# ./install_vpc_endpoint.sh --region us-east-1 --stack-name my-stack --delete-stack
############################################

REGION=""
STACK_NAME=""
TEMPLATE_FILE=""
DELETE_STACK=false
PARAMS=()

############################################
# Argument parsing
############################################
while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)
      REGION="$2"
      shift 2
      ;;
    --stack-name)
      STACK_NAME="$2"
      shift 2
      ;;
    --template-file)
      TEMPLATE_FILE="$2"
      shift 2
      ;;
    --parameters)
      shift
      while [[ $# -gt 0 && "$1" != --* ]]; do
        PARAMS+=("$1")
        shift
      done
      ;;
    --delete-stack)
      DELETE_STACK=true
      shift
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

############################################
# Validation
############################################
if [[ -z "$REGION" || -z "$STACK_NAME" ]]; then
  echo "❌ Missing required arguments"
  exit 1
fi

if [[ "$DELETE_STACK" == "false" && -z "$TEMPLATE_FILE" ]]; then
  echo "❌ Missing --template-file for stack creation"
  exit 1
fi

############################################
# Build parameter overrides
############################################
PARAMETER_OVERRIDES=()
for p in "${PARAMS[@]}"; do
  KEY="${p%%=*}"
  VALUE="${p#*=}"
  PARAMETER_OVERRIDES+=("ParameterKey=$KEY,ParameterValue=$VALUE")
done

if [[ "$DELETE_STACK" == "true" ]]; then
  ############################################
  # Delete stack
  ############################################
  echo "🗑️ Deleting CloudFormation stack: $STACK_NAME"

  aws cloudformation delete-stack \
    --region "$REGION" \
    --stack-name "$STACK_NAME"

  echo "⏳ Waiting for stack delete to complete..."

  if aws cloudformation wait stack-delete-complete \
    --region "$REGION" \
    --stack-name "$STACK_NAME"; then

    echo "✅ Stack deletion completed successfully!"
    exit 0

  else
    echo "❌ Stack deletion failed!"
    echo ""
    echo "🔥 Failure events:"

    aws cloudformation describe-stack-events \
      --region "$REGION" \
      --stack-name "$STACK_NAME" \
      --query 'StackEvents[?ResourceStatus==`DELETE_FAILED`].[LogicalResourceId,ResourceType,ResourceStatusReason]' \
      --output table

    exit 1
  fi
fi

############################################
# Create stack
############################################
echo "🚀 Creating CloudFormation stack: $STACK_NAME"

aws cloudformation create-stack \
  --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --template-body "file://$TEMPLATE_FILE" \
  --capabilities CAPABILITY_IAM \
  --parameters "${PARAMETER_OVERRIDES[@]}"

############################################
# Monitor stack
############################################
echo "⏳ Waiting for stack to complete..."

if aws cloudformation wait stack-create-complete \
  --region "$REGION" \
  --stack-name "$STACK_NAME"; then

  echo "✅ Stack creation completed successfully!"

  ############################################
  # Print created resources
  ############################################
  echo ""
  echo "📦 Resources created:"
  aws cloudformation describe-stack-resources \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --query 'StackResources[*].[LogicalResourceId,ResourceType,PhysicalResourceId]' \
    --output table

else
  echo "❌ Stack creation failed!"
  echo ""
  echo "🔥 Failure events:"

  aws cloudformation describe-stack-events \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --query 'StackEvents[?ResourceStatus==`CREATE_FAILED`].[LogicalResourceId,ResourceType,ResourceStatusReason]' \
    --output table

  exit 1
fi
