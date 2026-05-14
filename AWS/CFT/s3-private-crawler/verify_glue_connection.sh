#!/usr/bin/env bash
# verify_glue_connection.sh
#
# Sanity-check a Promethium S3 private-crawler install end-to-end.
# Designed to be runnable by QA on a fresh deployment OR after edits
# to the IAM role / bucket policy / network connection.
#
# Performs (in order):
#   1. Validates the IAM role exists and its trust policy contains
#      both the EKS OIDC and glue.amazonaws.com principals.
#   2. Validates the role has each required permission Sid present
#      (presence check only — does NOT simulate Action evaluation).
#      Also flags the ec2:CreateTags-with-condition trap.
#   3. Validates the Glue NETWORK connection exists and points at a
#      private subnet whose route table contains the S3 prefix-list
#      route via the gateway endpoint.
#   4. Validates the security group on the connection has a self-
#      referencing inbound rule.
#   5. Validates the bucket policy references the role principal and
#      gates by aws:SourceVpce on the stack's VPCE id.
#   6. Runs a kubectl-driven AWS CLI s3 ls from inside the cluster as
#      the trino-sa service account (catches DNS/route/SG issues that
#      look the same as IAM failures from outside).
#   7. (Optional) Tails the most recent GlueJobRunnerSession events
#      from CloudTrail and surfaces any AccessDenied / errorCode rows.
#
# Designed for bash 4+ / awscli v2 / jq / kubectl. Read-only — does
# NOT create or modify any resources.
#
# Usage:
#   ./verify_glue_connection.sh \
#     --region us-east-1 \
#     --crawler-role promethium-prod-glue-trino-role-demo2-inc \
#     --connection-name promethium-glue-connection \
#     --bucket bucketnewpolicy-copy \
#     --bucket-account 646322277713 \
#     [--namespace intelligentedge] \
#     [--service-account trino-sa] \
#     [--prefix SiriusXM/] \
#     [--vpce-id vpce-xxxxxxxxxxxxxxxxx] \
#     [--cloudtrail-lookback 30]
#
# Exit codes:
#   0 — all checks passed
#   1 — at least one check failed (details printed)
#   2 — invocation error (missing flag, missing tool)

set -u
set -o pipefail

REGION=""
CRAWLER_ROLE=""
CONNECTION_NAME=""
BUCKET=""
BUCKET_ACCOUNT=""
NAMESPACE="intelligentedge"
SERVICE_ACCOUNT="trino-sa"
PREFIX=""
VPCE_ID=""
CLOUDTRAIL_LOOKBACK="30"

usage() {
  sed -n '2,40p' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --region)               REGION="$2"; shift 2 ;;
    --crawler-role)         CRAWLER_ROLE="$2"; shift 2 ;;
    --connection-name)      CONNECTION_NAME="$2"; shift 2 ;;
    --bucket)               BUCKET="$2"; shift 2 ;;
    --bucket-account)       BUCKET_ACCOUNT="$2"; shift 2 ;;
    --namespace)            NAMESPACE="$2"; shift 2 ;;
    --service-account)      SERVICE_ACCOUNT="$2"; shift 2 ;;
    --prefix)               PREFIX="$2"; shift 2 ;;
    --vpce-id)              VPCE_ID="$2"; shift 2 ;;
    --cloudtrail-lookback)  CLOUDTRAIL_LOOKBACK="$2"; shift 2 ;;
    -h|--help)              usage; exit 0 ;;
    *)                      echo "Unknown flag: $1"; usage; exit 2 ;;
  esac
done

missing=()
for required_var in REGION CRAWLER_ROLE CONNECTION_NAME BUCKET; do
  [[ -z "${!required_var}" ]] && missing+=("--${required_var,,}")
done
if (( ${#missing[@]} > 0 )); then
  echo "Missing required flags: ${missing[*]}" >&2
  usage
  exit 2
fi

for cmd in aws jq kubectl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required tool not on PATH: $cmd" >&2
    exit 2
  fi
done

# ---------------------------------------------------------------------------
# Pretty-printing helpers
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }

pass() { printf '  [%s] %s\n' "$(green PASS)" "$1"; PASS=$((PASS+1)); }
fail() { printf '  [%s] %s\n' "$(red FAIL)" "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  [%s] %s\n' "$(yellow SKIP)" "$1"; SKIP=$((SKIP+1)); }

section() { echo; bold "== $1 =="; }

# ---------------------------------------------------------------------------
# 1. IAM role + trust policy
# ---------------------------------------------------------------------------
section "1. IAM role $CRAWLER_ROLE"

role_doc=$(aws iam get-role --role-name "$CRAWLER_ROLE" --output json 2>/dev/null) || true
if [[ -z "$role_doc" ]]; then
  fail "Role does not exist (or current credentials cannot read it)"
else
  pass "Role exists"
  IE_ACCOUNT=$(echo "$role_doc" | jq -r '.Role.Arn | split(":") | .[4]')
  echo "      IE account: $IE_ACCOUNT"

  trust_doc=$(echo "$role_doc" | jq -r '.Role.AssumeRolePolicyDocument | tostring')
  if echo "$trust_doc" | grep -q '"glue.amazonaws.com"'; then
    pass "Trust policy includes glue.amazonaws.com"
  else
    fail "Trust policy MISSING glue.amazonaws.com (Glue cannot assume the role; Test Connection will fail before producing CloudTrail events)"
  fi
  if echo "$trust_doc" | grep -q 'sts:AssumeRoleWithWebIdentity'; then
    pass "Trust policy includes EKS OIDC (sts:AssumeRoleWithWebIdentity)"
  else
    fail "Trust policy MISSING EKS OIDC — Trino IRSA will fail"
  fi
fi

# ---------------------------------------------------------------------------
# 2. Inline policies — required Sid presence + ec2:CreateTags condition trap
# ---------------------------------------------------------------------------
section "2. Crawler role permissions"

policies_json="[]"
if [[ -n "$role_doc" ]]; then
  inline_names=$(aws iam list-role-policies --role-name "$CRAWLER_ROLE" \
    --query 'PolicyNames' --output json 2>/dev/null || echo '[]')
  for pname in $(echo "$inline_names" | jq -r '.[]'); do
    p=$(aws iam get-role-policy --role-name "$CRAWLER_ROLE" --policy-name "$pname" \
        --query 'PolicyDocument' --output json 2>/dev/null || echo '{}')
    policies_json=$(jq -c --argjson p "$p" '. + [$p]' <<<"$policies_json")
  done
  attached=$(aws iam list-attached-role-policies --role-name "$CRAWLER_ROLE" \
    --query 'AttachedPolicies[].PolicyArn' --output json 2>/dev/null || echo '[]')
  for arn in $(echo "$attached" | jq -r '.[]'); do
    ver=$(aws iam get-policy --policy-arn "$arn" --query 'Policy.DefaultVersionId' --output text 2>/dev/null || echo "")
    [[ -z "$ver" ]] && continue
    p=$(aws iam get-policy-version --policy-arn "$arn" --version-id "$ver" \
        --query 'PolicyVersion.Document' --output json 2>/dev/null || echo '{}')
    policies_json=$(jq -c --argjson p "$p" '. + [$p]' <<<"$policies_json")
  done
fi

stmts=$(jq -c '[.[] | .Statement[]?]' <<<"$policies_json")

check_action() {
  local label="$1"; local action="$2"
  if jq -e --arg a "$action" '
    any(.[]; (.Effect=="Allow")
      and ((.Action // []) | (if type=="string" then [.] else . end) | index($a)))
  ' <<<"$stmts" >/dev/null; then
    pass "$label ($action)"
  else
    fail "$label — no Allow statement on $action found"
  fi
}

check_action "glue:GetConnection"            "glue:GetConnection"
check_action "iam:PassRole (to Glue)"        "iam:PassRole"
check_action "logs:PutLogEvents"             "logs:PutLogEvents"
check_action "ec2:DescribeSubnets"           "ec2:DescribeSubnets"
check_action "ec2:CreateNetworkInterface"    "ec2:CreateNetworkInterface"
check_action "ec2:CreateTags"                "ec2:CreateTags"

# The trap: ec2:CreateTags must not have an ec2:CreateAction condition.
trap_violation=$(jq -c '
  [.[]
    | select((.Action // []) | (if type=="string" then [.] else . end) | index("ec2:CreateTags"))
    | select(.Condition? // {} | tostring | contains("CreateNetworkInterface"))]
' <<<"$stmts")
if [[ "$trap_violation" != "[]" ]]; then
  fail "ec2:CreateTags has a Condition referencing CreateNetworkInterface — this is the silent-failure trap. Remove the Condition block."
else
  pass "ec2:CreateTags has no CreateAction=CreateNetworkInterface condition"
fi

# ---------------------------------------------------------------------------
# 3. Glue connection + subnet + route table
# ---------------------------------------------------------------------------
section "3. Glue NETWORK connection $CONNECTION_NAME"

conn=$(aws glue get-connection --region "$REGION" --name "$CONNECTION_NAME" \
       --output json 2>/dev/null || true)
if [[ -z "$conn" ]]; then
  fail "Connection $CONNECTION_NAME not found in $REGION"
  CONN_SUBNET=""
  CONN_SG=""
else
  pass "Connection exists"
  CONN_TYPE=$(echo "$conn" | jq -r '.Connection.ConnectionType')
  if [[ "$CONN_TYPE" == "NETWORK" ]]; then
    pass "Connection type is NETWORK"
  else
    fail "Connection type is $CONN_TYPE — expected NETWORK"
  fi
  CONN_SUBNET=$(echo "$conn" | jq -r '.Connection.PhysicalConnectionRequirements.SubnetId')
  CONN_SG=$(echo "$conn" | jq -r '.Connection.PhysicalConnectionRequirements.SecurityGroupIdList[0]')
  echo "      Subnet: $CONN_SUBNET"
  echo "      Security group: $CONN_SG"
fi

if [[ -n "$CONN_SUBNET" ]]; then
  rt_id=$(aws ec2 describe-route-tables --region "$REGION" \
            --filters "Name=association.subnet-id,Values=$CONN_SUBNET" \
            --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || echo "")
  if [[ -z "$rt_id" || "$rt_id" == "None" ]]; then
    # Try the VPC's main route table
    vpc_id=$(aws ec2 describe-subnets --region "$REGION" --subnet-ids "$CONN_SUBNET" \
              --query 'Subnets[0].VpcId' --output text 2>/dev/null || echo "")
    rt_id=$(aws ec2 describe-route-tables --region "$REGION" \
              --filters "Name=vpc-id,Values=$vpc_id" "Name=association.main,Values=true" \
              --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || echo "")
  fi
  if [[ -n "$rt_id" && "$rt_id" != "None" ]]; then
    s3_route=$(aws ec2 describe-route-tables --region "$REGION" --route-table-ids "$rt_id" \
                --query 'RouteTables[0].Routes[?GatewayId!=null && starts_with(GatewayId, `vpce-`)]' \
                --output json 2>/dev/null || echo '[]')
    if [[ "$(echo "$s3_route" | jq 'length')" -gt 0 ]]; then
      DETECTED_VPCE=$(echo "$s3_route" | jq -r '.[0].GatewayId')
      pass "Subnet's route table has gateway-endpoint route via $DETECTED_VPCE"
      [[ -z "$VPCE_ID" ]] && VPCE_ID="$DETECTED_VPCE"
    else
      fail "Subnet's route table has no S3 gateway-endpoint route"
    fi
  else
    skip "Could not resolve route table for subnet $CONN_SUBNET"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Security group — self-reference rule
# ---------------------------------------------------------------------------
section "4. Security group $CONN_SG"
if [[ -n "$CONN_SG" ]]; then
  self_ref=$(aws ec2 describe-security-groups --region "$REGION" --group-ids "$CONN_SG" \
              --query "SecurityGroups[0].IpPermissions[?UserIdGroupPairs[?GroupId=='$CONN_SG']]" \
              --output json 2>/dev/null || echo '[]')
  if [[ "$(echo "$self_ref" | jq 'length')" -gt 0 ]]; then
    pass "Security group has an inbound self-reference rule"
  else
    fail "Security group MISSING inbound self-reference rule — Glue NETWORK connection ENI health checks will fail"
  fi
fi

# ---------------------------------------------------------------------------
# 5. Bucket policy
# ---------------------------------------------------------------------------
section "5. Bucket policy on $BUCKET"
bp_args=(--bucket "$BUCKET")
[[ -n "$BUCKET_ACCOUNT" ]] && bp_args+=(--expected-bucket-owner "$BUCKET_ACCOUNT")
bp=$(aws s3api get-bucket-policy "${bp_args[@]}" --output json 2>/dev/null \
      | jq -r '.Policy' 2>/dev/null || echo "")
if [[ -z "$bp" || "$bp" == "null" ]]; then
  fail "No bucket policy returned (or current credentials cannot read it from $BUCKET_ACCOUNT)"
else
  if [[ -n "$role_doc" ]]; then
    role_arn=$(echo "$role_doc" | jq -r '.Role.Arn')
    if echo "$bp" | jq -e --arg r "$role_arn" '
      .Statement[] | (.Principal.AWS // []) |
      (if type=="string" then [.] else . end) | index($r)' >/dev/null 2>&1; then
      pass "Bucket policy includes role principal $role_arn"
    else
      fail "Bucket policy does NOT include $role_arn as a principal"
    fi
  fi
  if echo "$bp" | jq -e '.Statement[] | (.Action // []) |
    (if type=="string" then [.] else . end) | index("s3:GetBucketLocation")' >/dev/null 2>&1; then
    pass "Bucket policy grants s3:GetBucketLocation"
  else
    fail "Bucket policy MISSING s3:GetBucketLocation (Glue requires this; omission produces the generic 'Test connection failed')"
  fi
  if [[ -n "$VPCE_ID" ]]; then
    if echo "$bp" | grep -q "$VPCE_ID"; then
      pass "Bucket policy references VPCE id $VPCE_ID"
    else
      fail "Bucket policy aws:SourceVpce does NOT match detected VPCE $VPCE_ID"
    fi
  else
    skip "Cannot validate aws:SourceVpce (no VPCE id supplied or detected)"
  fi
fi

# ---------------------------------------------------------------------------
# 6. In-cluster network probe
# ---------------------------------------------------------------------------
section "6. In-cluster S3 probe (kubectl run, $NAMESPACE/$SERVICE_ACCOUNT)"
if kubectl get sa "$SERVICE_ACCOUNT" -n "$NAMESPACE" >/dev/null 2>&1; then
  s3_target="s3://$BUCKET/${PREFIX}"
  echo "      Listing $s3_target ..."
  if kubectl run -n "$NAMESPACE" verify-s3-$$ --rm -i --restart=Never --quiet \
        --image=amazon/aws-cli:latest \
        --overrides="{\"spec\":{\"serviceAccountName\":\"$SERVICE_ACCOUNT\"}}" \
        --command -- aws s3 ls "$s3_target" --region "$REGION" >/tmp/verify-s3-out.$$ 2>&1; then
    pass "In-cluster S3 list succeeded (network + IAM + bucket policy all OK)"
  else
    fail "In-cluster S3 list FAILED — see /tmp/verify-s3-out.$$"
    head -20 "/tmp/verify-s3-out.$$" | sed 's/^/      /'
  fi
else
  skip "Service account $NAMESPACE/$SERVICE_ACCOUNT not found"
fi

# ---------------------------------------------------------------------------
# 7. CloudTrail tail for GlueJobRunnerSession
# ---------------------------------------------------------------------------
section "7. CloudTrail (last ${CLOUDTRAIL_LOOKBACK}m, GlueJobRunnerSession on $CRAWLER_ROLE)"
start_time=$(date -u -v-"${CLOUDTRAIL_LOOKBACK}"M +%FT%TZ 2>/dev/null \
             || date -u --date="${CLOUDTRAIL_LOOKBACK} minutes ago" +%FT%TZ)
events=$(aws cloudtrail lookup-events --region "$REGION" \
          --start-time "$start_time" --max-results 200 --output json 2>/dev/null \
          | jq --arg role "$CRAWLER_ROLE" '
            [.Events[] | .CloudTrailEvent | fromjson
              | select(.userIdentity.sessionContext.sessionIssuer.userName == $role
                       and ((.userIdentity.arn // "") | contains("GlueJobRunnerSession")))
              | {time:.eventTime, event:.eventName, src:.eventSource,
                 err:(.errorMessage // .errorCode // null)}]
            | sort_by(.time)' 2>/dev/null || echo '[]')
err_count=$(echo "$events" | jq '[.[] | select(.err != null)] | length')
total=$(echo "$events" | jq 'length')
if [[ "$total" -eq 0 ]]; then
  skip "No GlueJobRunnerSession events in the lookback window (trigger a crawl/test, then re-run)"
elif [[ "$err_count" -eq 0 ]]; then
  pass "$total GlueJobRunnerSession events, no errors"
else
  fail "$err_count of $total events had an error"
  echo "$events" | jq -r '.[] | select(.err != null) | "      \(.time)  \(.event)  \(.err)"' | head -20
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
bold "Summary: $(green "$PASS pass"), $(red "$FAIL fail"), $(yellow "$SKIP skip")"
if (( FAIL > 0 )); then
  exit 1
fi
exit 0
