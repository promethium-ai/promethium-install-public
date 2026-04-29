#!/bin/bash
# Pre-install verification: checks VPC, subnets, routing, and EKS subnet tags
#
# Usage: ./verify_network.sh <company_name> <vpc_id> <aws_region> [--stack <network_stack_name>]
#
# - company_name:   used to derive expected cluster name for tag validation
# - vpc_id:         VPC ID to verify
# - aws_region:     AWS region
# - --stack:        (optional) Promethium network CFT stack name — auto-populates subnet IDs
#
# Examples:
#   ./verify_network.sh acme vpc-0abc123 us-east-1
#   ./verify_network.sh acme vpc-0abc123 us-east-1 --stack pmie-network-acme

COMPANY=${1:-}
VPC_ID=${2:-}
REGION=${3:-us-east-1}
STACK_NAME=""

shift 3 2>/dev/null
while [ $# -gt 0 ]; do
  case "$1" in
    --stack) STACK_NAME="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$COMPANY" ] || [ -z "$VPC_ID" ]; then
  echo "Usage: $0 <company_name> <vpc_id> [aws_region] [--stack <network_stack_name>]"
  echo ""
  echo "Examples:"
  echo "  $0 acme vpc-0abc123 us-east-1"
  echo "  $0 acme vpc-0abc123 us-east-1 --stack pmie-network-acme"
  exit 1
fi

EXPECTED_CLUSTER="promethium-datafabric-prod-${COMPANY}-eks-cluster"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
PASS=0; FAIL=0; WARN=0

check_pass() { echo "  ✅ $1"; PASS=$((PASS+1)); }
check_fail() { echo "  ❌ $1 — $2"; FAIL=$((FAIL+1)); }
check_warn() { echo "  ⚠️  $1 — $2"; WARN=$((WARN+1)); }

echo ""
echo "============================================================"
echo " Promethium Network Verification"
echo " Company: ${COMPANY}"
echo " VPC:     ${VPC_ID}"
echo " Account: ${ACCOUNT_ID}"
echo " Region:  ${REGION}"
[ -n "$STACK_NAME" ] && echo " Stack:   ${STACK_NAME}"
echo "============================================================"

# ── 1. VPC exists and is large enough ────────────────────────────────────────
echo ""
echo "── 1. VPC"
VPC_CIDR=$(aws ec2 describe-vpcs \
  --vpc-ids "$VPC_ID" \
  --query 'Vpcs[0].CidrBlock' \
  --output text --region "$REGION" 2>/dev/null)

if [ -z "$VPC_CIDR" ] || [ "$VPC_CIDR" = "None" ]; then
  check_fail "VPC exists" "VPC ${VPC_ID} not found in ${REGION}"
  echo ""
  echo "  FATAL: VPC not found. Cannot continue."
  exit 1
fi
check_pass "VPC exists: ${VPC_ID} (${VPC_CIDR})"

# Check VPC is at least /22
PREFIX=$(echo "$VPC_CIDR" | cut -d'/' -f2)
if [ "$PREFIX" -le 22 ]; then
  check_pass "VPC CIDR /${PREFIX} is /22 or larger"
else
  check_fail "VPC CIDR /${PREFIX}" "VPC must be at least /22 — current CIDR is too small for EKS"
fi

DNS_SUPPORT=$(aws ec2 describe-vpc-attribute \
  --vpc-id "$VPC_ID" \
  --attribute enableDnsSupport \
  --query 'EnableDnsSupport.Value' \
  --output text --region "$REGION" 2>/dev/null)
DNS_HOSTNAMES=$(aws ec2 describe-vpc-attribute \
  --vpc-id "$VPC_ID" \
  --attribute enableDnsHostnames \
  --query 'EnableDnsHostnames.Value' \
  --output text --region "$REGION" 2>/dev/null)

[ "$DNS_SUPPORT" = "True" ] \
  && check_pass "DNS support enabled" \
  || check_fail "DNS support" "DISABLED — EKS requires DNS support on the VPC"

[ "$DNS_HOSTNAMES" = "True" ] \
  && check_pass "DNS hostnames enabled" \
  || check_warn "DNS hostnames" "DISABLED — recommended for EKS node communication"

# ── 2. Subnets ────────────────────────────────────────────────────────────────
echo ""
echo "── 2. Subnets"

# Get subnet IDs — from stack or discover from VPC
if [ -n "$STACK_NAME" ]; then
  SUBNET1=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='Subnet1Id'].OutputValue" \
    --output text --region "$REGION" 2>/dev/null)
  SUBNET2=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='Subnet2Id'].OutputValue" \
    --output text --region "$REGION" 2>/dev/null)
  echo "     Using subnet IDs from stack outputs."
else
  echo "     No stack provided — scanning all subnets in VPC ${VPC_ID}."
  echo "     Private subnets (NAT route) will be checked for EKS tags."
fi

# Get all subnets in VPC
ALL_SUBNETS=$(aws ec2 describe-subnets \
  --filters "Name=vpc-id,Values=${VPC_ID}" \
  --query 'Subnets[*].[SubnetId,CidrBlock,AvailabilityZone,MapPublicIpOnLaunch]' \
  --output text --region "$REGION" 2>/dev/null)

PRIVATE_SUBNETS=()
PUBLIC_SUBNETS=()
PRIVATE_AZS=()

while IFS=$'\t' read -r SUBNET_ID CIDR AZ PUBLIC_IP; do
  # Determine if subnet is private (routes via NAT) or public (routes via IGW)
  RT_ID=$(aws ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=${SUBNET_ID}" \
    --query 'RouteTables[0].RouteTableId' \
    --output text --region "$REGION" 2>/dev/null)

  if [ -z "$RT_ID" ] || [ "$RT_ID" = "None" ]; then
    # Use main route table
    RT_ID=$(aws ec2 describe-route-tables \
      --filters "Name=vpc-id,Values=${VPC_ID}" "Name=association.main,Values=true" \
      --query 'RouteTables[0].RouteTableId' \
      --output text --region "$REGION" 2>/dev/null)
  fi

  ROUTES=$(aws ec2 describe-route-tables \
    --route-table-ids "$RT_ID" \
    --query 'RouteTables[0].Routes[*].GatewayId' \
    --output text --region "$REGION" 2>/dev/null)

  if echo "$ROUTES" | grep -q "igw-"; then
    PUBLIC_SUBNETS+=("$SUBNET_ID ($CIDR, $AZ)")
  else
    PRIVATE_SUBNETS+=("$SUBNET_ID ($CIDR, $AZ)")
    PRIVATE_AZS+=("$AZ")
  fi
done <<< "$ALL_SUBNETS"

echo "     Private subnets found: ${#PRIVATE_SUBNETS[@]}"
for S in "${PRIVATE_SUBNETS[@]}"; do echo "       $S"; done
echo "     Public subnets found:  ${#PUBLIC_SUBNETS[@]}"
for S in "${PUBLIC_SUBNETS[@]}"; do echo "       $S"; done

[ "${#PRIVATE_SUBNETS[@]}" -ge 2 ] \
  && check_pass "At least 2 private subnets exist" \
  || check_fail "Private subnets" "Only ${#PRIVATE_SUBNETS[@]} found — need at least 2 in different AZs for EKS"

[ "${#PUBLIC_SUBNETS[@]}" -ge 2 ] \
  && check_pass "At least 2 public subnets exist (for ALB)" \
  || check_warn "Public subnets" "Only ${#PUBLIC_SUBNETS[@]} found — ALB requires 2 subnets in different AZs"

# Check private subnets are in different AZs
if [ "${#PRIVATE_AZS[@]}" -ge 2 ]; then
  UNIQUE_AZS=$(printf '%s\n' "${PRIVATE_AZS[@]}" | sort -u | wc -l)
  [ "$UNIQUE_AZS" -ge 2 ] \
    && check_pass "Private subnets span multiple availability zones" \
    || check_fail "Private subnet AZs" "Both private subnets are in the same AZ — EKS requires subnets in different AZs"
fi

# ── 3. Subnet tags ────────────────────────────────────────────────────────────
echo ""
echo "── 3. EKS subnet tags"
echo "     Expected cluster name: ${EXPECTED_CLUSTER}"
echo ""

check_subnet_tags() {
  local subnet_id=$1
  local expected_role=$2  # "elb" or "internal-elb"
  local subnet_label=$3

  TAGS=$(aws ec2 describe-tags \
    --filters "Name=resource-id,Values=${subnet_id}" \
    --query 'Tags[*].[Key,Value]' \
    --output text --region "$REGION" 2>/dev/null)

  echo "     ${subnet_label} (${subnet_id}):"

  # Check cluster ownership tag
  CLUSTER_TAG=$(echo "$TAGS" | grep "kubernetes.io/cluster/${EXPECTED_CLUSTER}" | awk '{print $2}')
  if [ "$CLUSTER_TAG" = "owned" ] || [ "$CLUSTER_TAG" = "shared" ]; then
    check_pass "kubernetes.io/cluster/${EXPECTED_CLUSTER}=${CLUSTER_TAG}"
  else
    check_fail "kubernetes.io/cluster/${EXPECTED_CLUSTER}" "MISSING — add tag: Key=kubernetes.io/cluster/${EXPECTED_CLUSTER} Value=owned. Run: ./utilities/tag_subnets.sh ${VPC_ID} ${REGION} ${COMPANY}"
  fi

  # Check role tag
  ROLE_TAG=$(echo "$TAGS" | grep "kubernetes.io/role/${expected_role}" | awk '{print $2}')
  if [ "$ROLE_TAG" = "1" ]; then
    check_pass "kubernetes.io/role/${expected_role}=1"
  else
    check_fail "kubernetes.io/role/${expected_role}" "MISSING — add tag: Key=kubernetes.io/role/${expected_role} Value=1. Run: ./utilities/tag_subnets.sh ${VPC_ID} ${REGION} ${COMPANY}"
  fi
}

# Check tags on private subnets
PRIVATE_IDX=1
while IFS=$'\t' read -r SUBNET_ID CIDR AZ PUBLIC_IP; do
  RT_ID=$(aws ec2 describe-route-tables \
    --filters "Name=association.subnet-id,Values=${SUBNET_ID}" \
    --query 'RouteTables[0].RouteTableId' \
    --output text --region "$REGION" 2>/dev/null)
  [ -z "$RT_ID" ] || [ "$RT_ID" = "None" ] && \
    RT_ID=$(aws ec2 describe-route-tables \
      --filters "Name=vpc-id,Values=${VPC_ID}" "Name=association.main,Values=true" \
      --query 'RouteTables[0].RouteTableId' \
      --output text --region "$REGION" 2>/dev/null)
  ROUTES=$(aws ec2 describe-route-tables \
    --route-table-ids "$RT_ID" \
    --query 'RouteTables[0].Routes[*].GatewayId' \
    --output text --region "$REGION" 2>/dev/null)
  if ! echo "$ROUTES" | grep -q "igw-"; then
    check_subnet_tags "$SUBNET_ID" "internal-elb" "Private subnet ${PRIVATE_IDX}"
    PRIVATE_IDX=$((PRIVATE_IDX+1))
  else
    check_subnet_tags "$SUBNET_ID" "elb" "Public subnet"
  fi
done <<< "$ALL_SUBNETS"

# ── 4. NAT Gateway ────────────────────────────────────────────────────────────
echo ""
echo "── 4. NAT Gateway"
NAT_GW=$(aws ec2 describe-nat-gateways \
  --filter "Name=vpc-id,Values=${VPC_ID}" "Name=state,Values=available" \
  --query 'NatGateways[0].NatGatewayId' \
  --output text --region "$REGION" 2>/dev/null)

[ -n "$NAT_GW" ] && [ "$NAT_GW" != "None" ] \
  && check_pass "NAT Gateway exists and is available: ${NAT_GW}" \
  || check_fail "NAT Gateway" "No available NAT Gateway found — private subnets cannot reach the internet for tool downloads and ECR"

# ── 5. Internet Gateway ───────────────────────────────────────────────────────
echo ""
echo "── 5. Internet Gateway"
IGW=$(aws ec2 describe-internet-gateways \
  --filters "Name=attachment.vpc-id,Values=${VPC_ID}" \
  --query 'InternetGateways[0].InternetGatewayId' \
  --output text --region "$REGION" 2>/dev/null)

[ -n "$IGW" ] && [ "$IGW" != "None" ] \
  && check_pass "Internet Gateway attached: ${IGW}" \
  || check_fail "Internet Gateway" "No Internet Gateway attached — ALB and public subnets will not work"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo " Summary: ✅ $PASS passed | ❌ $FAIL failed | ⚠️  $WARN warnings"
echo "============================================================"
if [ $FAIL -gt 0 ]; then
  echo " ACTION REQUIRED: Fix failures above before running terraform."
  echo " For missing subnet tags, run:"
  echo "   cd AWS && ./utilities/tag_subnets.sh ${VPC_ID} ${REGION} ${COMPANY}"
elif [ $WARN -gt 0 ]; then
  echo " Review warnings before proceeding."
else
  echo " Network looks good. Proceed with terraform."
fi
echo ""
