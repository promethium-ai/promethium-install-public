#!/usr/bin/env bash
# Phase 1 — capture the tenant's real identity + infra IDs from the LIVE spoke (read-only)
# and AWS. Prints the values you paste into tenants/<env>/<tenant>.yaml, and writes OIDC_ID
# back into migration.env for the later phases. NEVER fabricate tenantId — the SaaS OPA
# group-provider keys on it (a wrong value silently breaks SHOW CATALOGS auth).
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

say "from the live spoke (read-only kubectl)"
TENANT_ID=$(kc -n "$NAMESPACE" get cm promethium-metrics-exporter -o jsonpath='{.data.TENANT_ID}' 2>/dev/null)
COGNITO=$(kc -n "$NAMESPACE" get secret edge-setting -o jsonpath='{.data.USERPOOL_ID}' 2>/dev/null | base64 -d 2>/dev/null)
echo "  tenantId            : ${TENANT_ID:-<not found — check promethium-metrics-exporter CM>}"
echo "  cognito userPoolId  : ${COGNITO:-<not found — check edge-setting/USERPOOL_ID>}"

say "from AWS (needs your creds)"
read -r VPC OIDC_ISSUER < <(aws eks describe-cluster --name "$CLUSTER" --region "$REGION" \
  --query 'cluster.[resourcesVpcConfig.vpcId,identity.oidc.issuer]' --output text 2>/dev/null)
OIDC_ID="${OIDC_ISSUER##*/}"
SQS_ARN="arn:aws:sqs:${REGION}:${ACCOUNT}:${TENANT}-sqs-queue"
aws sqs get-queue-url --queue-name "${TENANT}-sqs-queue" --region "$REGION" >/dev/null 2>&1 \
  && SQS_OK="(exists)" || SQS_OK="(NOT found — check queue name)"
KMS_KEY=$(aws kms list-aliases --region "$REGION" \
  --query "Aliases[?ends_with(AliasName,'${CLUSTER}-s3-encrypt-key')].TargetKeyId" --output text 2>/dev/null)
echo "  vpc                 : ${VPC:-<none>}"
echo "  oidc provider id    : ${OIDC_ID:-<none>}"
echo "  sqs                 : ${SQS_ARN}  ${SQS_OK}"
echo "  s3 kms key id       : ${KMS_KEY:-<none — check kms aliases>}"

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
  spec.ie.release / component versions: PIN to the tenant's RUNNING image tags (see below)
------------------------------------------------------------------------------------

Running image tags (pin the tenant file to these so the umbrella ADOPTS with no upgrade):
EOF
kc -n "$NAMESPACE" get deploy pm61trino-coordinator server nginx \
  -o jsonpath='{range .items[*]}  {.metadata.name}: {.spec.template.spec.containers[0].image}{"\n"}{end}' 2>/dev/null
kc -n "$NAMESPACE" get sts promethium-postgres-postgresql \
  -o jsonpath='  {.metadata.name}: {.spec.template.spec.containers[0].image}{"\n"}' 2>/dev/null
