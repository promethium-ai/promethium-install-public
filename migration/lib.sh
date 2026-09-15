#!/usr/bin/env bash
# Common config + helpers for the legacy -> Model-A' (argocd-agent umbrella) migration.
# Every phase script sources this. Nothing is hardcoded to one tenant — all config comes
# from migration.env (see migration.env.example) or the environment.
#
# Secrets rule (council 2026-08-30): no phase ever decodes a customer/platform secret to
# operator disk. The SM seed pipes plaintext via file:///dev/stdin; the in-cluster backup
# copies base64 as-is. Keep it that way.
set -euo pipefail

_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -f "${_LIB_DIR}/migration.env" ] && . "${_LIB_DIR}/migration.env"

# ---- required / defaulted inputs ----
: "${TENANT:?set TENANT (e.g. <tenant>) in migration.env}"
: "${ENV:=dev}"
: "${ACCOUNT:?set ACCOUNT in migration.env}"
: "${REGION:=us-east-1}"
: "${NAMESPACE:=intelligentedge}"
# HOSTED_ZONE_ID: the Route53 zone for <ENV>.promethium.ai. This differs per env/account
# (no single correct default) — ask your Promethium contact for the zone id.
: "${HOSTED_ZONE_ID:?set HOSTED_ZONE_ID (Route53 zone id for <ENV>.promethium.ai) in migration.env}"
# ECR_ACCOUNT: the Promethium container-registry AWS account — NOT ${ACCOUNT} (your own
# tenant account); see the gen_perms_refresher comment below for why. Ask your Promethium contact.
: "${ECR_ACCOUNT:?set ECR_ACCOUNT (Promethium registry account, provided by your Promethium contact) in migration.env}"

# ---- derived ----
# Detect CLUSTER/SPOKE_CTX inherited from the SHELL ENVIRONMENT: migration.env
# usually does NOT set them, so a value present here is a stale export from a prior
# tenant that overrides migration.env via ${VAR:-}. A real near-miss: an exported
# CLUSTER (<tenant-a>) + SPOKE_CTX (<tenant-b>) left over from a PRIOR tenant's run
# silently retargeted the capture — and would have retargeted the WIPE — at the
# wrong cluster. Surfaced in the identity banner below.
if [ -n "${CLUSTER:-}" ];   then _CLUSTER_FROM_ENV=1; else _CLUSTER_FROM_ENV=0; fi
if [ -n "${SPOKE_CTX:-}" ]; then _SPOKE_FROM_ENV=1;   else _SPOKE_FROM_ENV=0;   fi
CLUSTER="${CLUSTER:-promethium-datafabric-${ENV}-${TENANT}-eks-cluster}"
SPOKE_CTX="${SPOKE_CTX:-arn:aws:eks:${REGION}:${ACCOUNT}:cluster/${CLUSTER}}"
HUB_CTX="${HUB_CTX:-}"
BNS="${BNS:-migration-backup}"
SM_PREFIX="${ENV}/ie/${TENANT}/${NAMESPACE}"          # SecretsManager path prefix
ESO_ROLE="promethium-${ENV}-${TENANT}-eso-reader"
REF_ROLE="promethium-${ENV}-${TENANT}-argocd-ecr-refresher"
OIDC_HOST="oidc.eks.${REGION}.amazonaws.com"
DOMAIN="${ENV}.promethium.ai"
# the 5 platform secrets ESO projects (must match the umbrella's externalSecrets.secrets list)
PLATFORM_SECRETS=(promethium-pipeline-executor-secret edge-setting promethium-redash-config remote-job-service promethium-postgres-postgresql)

kc(){ kubectl --context "$SPOKE_CTX" "$@"; }   # spoke (the tenant cluster)
kch(){ kubectl --context "$HUB_CTX" "$@"; }    # hub (Promethium control-plane cluster; operator-only, set HUB_CTX in migration.env)
say(){ printf '\n== %s ==\n' "$*"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---- identity banner (safety) ----
# Every phase sources lib.sh, so this prints WHAT the invocation will act on before
# it acts — catch a wrong tenant/cluster/context (e.g. from a stale exported var)
# immediately, before a backup/wipe/restore touches it.
{
  printf '\n== identity ==\n  %s/%s  acct=%s region=%s\n  spoke=%s\n  hub=%s\n' \
    "$ENV" "$TENANT" "$ACCOUNT" "$REGION" "${SPOKE_CTX##*/}" "${HUB_CTX##*/}"
  if [ "$_CLUSTER_FROM_ENV" = 1 ]; then printf '  !! CLUSTER inherited from the shell env, not migration.env — VERIFY it is correct\n'; fi
  if [ "$_SPOKE_FROM_ENV" = 1 ];   then printf '  !! SPOKE_CTX inherited from the shell env, not migration.env — VERIFY it is correct\n'; fi
} >&2

# IRSA trust policy federating one SA via the tenant's cluster OIDC (needs OIDC_ID)
gen_trust(){ # $1=sa-namespace $2=sa-name
  : "${OIDC_ID:?set OIDC_ID in migration.env (run 01-capture-identity.sh first)}"
  cat <<JSON
{ "Version":"2012-10-17","Statement":[{
  "Effect":"Allow",
  "Principal":{"Federated":"arn:aws:iam::${ACCOUNT}:oidc-provider/${OIDC_HOST}/id/${OIDC_ID}"},
  "Action":"sts:AssumeRoleWithWebIdentity",
  "Condition":{"StringEquals":{
    "${OIDC_HOST}/id/${OIDC_ID}:sub":"system:serviceaccount:${1}:${2}",
    "${OIDC_HOST}/id/${OIDC_ID}:aud":"sts.amazonaws.com"}}}]}
JSON
}

# SecretsManager read policy scoped to this tenant only
gen_perms_eso(){
  cat <<JSON
{ "Version":"2012-10-17","Statement":[{
  "Effect":"Allow",
  "Action":["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret"],
  "Resource":"arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:${ENV}/ie/${TENANT}/*"}]}
JSON
}

# ECR pull policy for the argocd ECR cred refresher (account-shared repos, no tenant scope).
# The ECR registry is ALWAYS ${ECR_ACCOUNT}/us-west-1 (see account-topology), NOT the spoke
# account. Do NOT reuse ${ACCOUNT} here: it equals the registry account for same-account
# spokes (dev/qa/preview) but resolves to the SPOKE account cross-account -> wrong/nonexistent
# repo ARNs -> the refresher can't pull. Registry account comes from ECR_ACCOUNT (migration.env).
# ★ The repo list MUST match the S4 grant's image_repositories: a cross-account puller needs its OWN IAM to
# allow each repo, not just the registry's own resource policy. Omitting iac/* + promethium/* =
# ImagePullBackOff on postgres (iac/docker/promethium-bitnami-postgres-16) + nginx/redis/trino-stream
# (promethium/*) — a lesson from an earlier migration. charts/intelligent-edge = the OCI umbrella
# (repo-server chart pull); services/ie/* + iac/* + promethium/* = the container images kubelet
# pulls via aws-ecr-docker-creds.
gen_perms_refresher(){
  cat <<JSON
{ "Version":"2012-10-17","Statement":[
  {"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"},
  {"Effect":"Allow","Action":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:BatchCheckLayerAvailability","ecr:DescribeImages"],
   "Resource":[
     "arn:aws:ecr:us-west-1:${ECR_ACCOUNT}:repository/charts/intelligent-edge",
     "arn:aws:ecr:us-west-1:${ECR_ACCOUNT}:repository/services/ie/*",
     "arn:aws:ecr:us-west-1:${ECR_ACCOUNT}:repository/iac/*",
     "arn:aws:ecr:us-west-1:${ECR_ACCOUNT}:repository/promethium/*"]}]}
JSON
}
