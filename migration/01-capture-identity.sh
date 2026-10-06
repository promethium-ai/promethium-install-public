#!/usr/bin/env bash
# Phase 1 — capture the tenant's real identity + infra IDs from the LIVE spoke (read-only)
# and AWS. Prints the values you paste into tenants/<env>/<tenant>.yaml, and writes OIDC_ID
# back into migration.env for the later phases. NEVER fabricate tenantId — the SaaS OPA
# group-provider keys on it (a wrong value silently breaks SHOW CATALOGS auth).
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

say "from the live spoke (read-only kubectl)"
TENANT_ID=$(kc -n "$NAMESPACE" get cm promethium-metrics-exporter -o jsonpath='{.data.TENANT_ID}' 2>/dev/null)
COGNITO=$(kc -n "$NAMESPACE" get secret edge-setting -o jsonpath='{.data.USERPOOL_ID}' 2>/dev/null | base64 -d 2>/dev/null)
# trino ServiceAccount IRSA role — READ it from the live SA annotation; never assume the
# promethium-<env>-<tenant>-trino-oidc-role convention (installs allow custom role names).
# Reuse-mode consumes THIS existing role (spec.ie.trinoRoleArn) instead of creating a new one.
TRINO_ROLE_ARN=$(kc -n "$NAMESPACE" get sa trino-sa -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}' 2>/dev/null || true)
echo "  tenantId            : ${TENANT_ID:-<not found — check promethium-metrics-exporter CM>}"
echo "  cognito userPoolId  : ${COGNITO:-<not found — check edge-setting/USERPOOL_ID>}"
echo "  trino IRSA role     : ${TRINO_ROLE_ARN:-(none)}   (reuse-mode: set spec.ie.trinoRoleArn to THIS existing role; do NOT create a new one)"

say "from AWS (needs your creds)"
read -r VPC OIDC_ISSUER < <(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" \
  --query 'cluster.[resourcesVpcConfig.vpcId,identity.oidc.issuer]' --output text 2>/dev/null)
OIDC_ID="${OIDC_ISSUER##*/}"
# SQS lives in the CONTROL-PLANE account (Promethium's own — 308 for preview/prod, 734 for
# dev/qa), NOT this spoke account, so the spoke-guessed ARN below and the get-queue-url probe
# only resolve for same-account dev/qa tenants. The authoritative queue name is on the LIVE
# sqs-listener — read it so a "NOT found" is self-documenting (see the resolution hint below).
SQS_LIVE_QUEUE=$(kc -n "$NAMESPACE" get deploy sqs-listener \
  -o jsonpath='{.spec.template.spec.containers[*].env[?(@.name=="SQS_QUEUE_NAME")].value}' 2>/dev/null)
SQS_ARN="arn:aws:sqs:${REGION}:${ACCOUNT}:${TENANT}-sqs-queue"
if aws sqs get-queue-url --queue-name "${SQS_LIVE_QUEUE:-${TENANT}-sqs-queue}" --region "$REGION" >/dev/null 2>&1; then
  SQS_OK="(exists in this spoke account)"
else
  SQS_OK="(NOT in this spoke account — SQS is CONTROL-PLANE, Promethium's account)"
fi
KMS_KEY=$(aws kms list-aliases --region "$REGION" \
  --query "Aliases[?ends_with(AliasName,'${CLUSTER}-s3-encrypt-key')].TargetKeyId" --output text 2>/dev/null)
echo "  vpc                 : ${VPC:-<none>}"
echo "  oidc provider id    : ${OIDC_ID:-<none>}"
echo "  sqs (spoke-guessed) : ${SQS_ARN}  ${SQS_OK}"
echo "  sqs live queue name : ${SQS_LIVE_QUEUE:-<sqs-listener not found>}  (authoritative — live sqs-listener SQS_QUEUE_NAME)"
[ "$SQS_OK" = "(exists in this spoke account)" ] || \
  echo "  -> tenant-file sqsArn = arn:aws:sqs:<control-plane-region>:<control-plane-account>:${SQS_LIVE_QUEUE:-${TENANT}-sqs-queue}   (Promethium control-plane acct: 308 preview/prod, 734 dev/qa — NOT this spoke ${ACCOUNT})"
echo "  s3 kms key id       : ${KMS_KEY:-<none — check kms aliases>}"

# vpc + oidc are load-bearing (IRSA trust + the tenant file). Empty here = a BROKEN capture
# (usually wrong AWS creds/region or cluster name) — warn loudly; do NOT author the tenant file from it.
if [ -z "$VPC" ] || [ -z "$OIDC_ID" ]; then
  MISS=""; [ -z "$VPC" ] && MISS="vpc"; [ -z "$OIDC_ID" ] && MISS="${MISS:+$MISS + }oidc"
  printf '\n  !!!! WARNING: %s came back EMPTY — capture is INCOMPLETE. Fix AWS creds/region + cluster name and re-run BEFORE authoring the tenant file. !!!!\n' "$MISS"
fi

# persist OIDC_ID for the later phases
if [ -n "$OIDC_ID" ] && [ -f "${_LIB_DIR}/migration.env" ]; then
  if grep -q '^OIDC_ID=' "${_LIB_DIR}/migration.env"; then
    sed -i.bak "s|^OIDC_ID=.*|OIDC_ID=${OIDC_ID}|" "${_LIB_DIR}/migration.env" && rm -f "${_LIB_DIR}/migration.env.bak"
  else
    printf '\nOIDC_ID=%s\n' "$OIDC_ID" >> "${_LIB_DIR}/migration.env"
  fi
  echo "  (wrote OIDC_ID to migration.env)"
fi

cat <<EOF

--- paste into tenants/${ENV}/${TENANT}.yaml (base it on an existing tenant file) ---
  metadata.annotations:
    registry.promethium.ai/ie-cluster-name: ${CLUSTER}
    registry.promethium.ai/ie-kms-arn: arn:aws:kms:${REGION}:${ACCOUNT}:key/${KMS_KEY}
    registry.promethium.ai/ie-sqs-arn: ${SQS_ARN}
    registry.promethium.ai/ie-vpc-id: ${VPC}
  spec.identity.tenantId: ${TENANT_ID}
  spec.ie.cognito.userPoolId: ${COGNITO}
  spec.ie.infra.s3KmsKeyArn: arn:aws:kms:${REGION}:${ACCOUNT}:key/${KMS_KEY}
  spec.ie.infra.sqsArn: ${SQS_ARN}
  spec.ie.trinoRoleArn: ${TRINO_ROLE_ARN}
  spec.ie.release / component versions: PIN to the tenant's RUNNING image tags (see below)
------------------------------------------------------------------------------------

Running image tags (pin the tenant file to these so the umbrella ADOPTS with no upgrade):
EOF
kc -n "$NAMESPACE" get deploy pm61trino-coordinator server nginx \
  -o jsonpath='{range .items[*]}  {.metadata.name}: {.spec.template.spec.containers[0].image}{"\n"}{end}' 2>/dev/null
kc -n "$NAMESPACE" get sts promethium-postgres-postgresql \
  -o jsonpath='  {.metadata.name}: {.spec.template.spec.containers[0].image}{"\n"}' 2>/dev/null
