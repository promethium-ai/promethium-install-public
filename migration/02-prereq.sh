#!/usr/bin/env bash
# Phase 2 — umbrella prereq stack on the legacy spoke (what a greenfield cluster already has):
#   1. External Secrets Operator (chart >=0.10 / v2.x for the external-secrets.io/v1 API)
#   2. eso-reader IRSA role  (SM read dev/ie/<tenant>/*) + annotate the ESO SA
#   3. ecr-refresher IRSA role (ECR pull for the OCI umbrella)
#   4. seed the 5 platform secrets from the LIVE cluster into SecretsManager (secure: no disk)
#   5. throwaway ESO->SM probe to prove the IRSA+SM chain BEFORE the wipe
# Needs your privileged AWS creds (IAM + SecretsManager) and spoke kube access. No secret
# value is ever written to disk or placed in argv (piped via file:///dev/stdin).
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
: "${OIDC_ID:?run 01-capture-identity.sh first (sets OIDC_ID)}"

say "1. install External Secrets Operator (if absent)"
if kc get ns external-secrets >/dev/null 2>&1 && kc -n external-secrets get deploy external-secrets >/dev/null 2>&1; then
  echo "  ESO already present"
else
  helm repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
  helm repo update external-secrets >/dev/null 2>&1 || true
  helm --kube-context "$SPOKE_CTX" install external-secrets external-secrets/external-secrets \
    -n external-secrets --create-namespace --set installCRDs=true --wait --timeout 5m >/dev/null
  echo "  ESO installed"
fi

say "2. eso-reader IRSA role + annotate the ESO SA"
aws iam create-role --role-name "$ESO_ROLE" --assume-role-policy-document "$(gen_trust external-secrets external-secrets)" >/dev/null 2>&1 \
  && echo "  role $ESO_ROLE created" || echo "  role $ESO_ROLE exists"
aws iam put-role-policy --role-name "$ESO_ROLE" --policy-name sm-read --policy-document "$(gen_perms_eso)"
kc -n external-secrets annotate sa external-secrets eks.amazonaws.com/role-arn="arn:aws:iam::${ACCOUNT}:role/${ESO_ROLE}" --overwrite >/dev/null
kc -n external-secrets rollout restart deploy external-secrets >/dev/null
kc -n external-secrets rollout status deploy external-secrets --timeout=90s >/dev/null && echo "  annotated + ESO restarted"

say "3. ecr-refresher IRSA role"
aws iam create-role --role-name "$REF_ROLE" --assume-role-policy-document "$(gen_trust argocd argocd-ecr-cred-refresher)" >/dev/null 2>&1 \
  && echo "  role $REF_ROLE created" || echo "  role $REF_ROLE exists"
aws iam put-role-policy --role-name "$REF_ROLE" --policy-name ecr-pull --policy-document "$(gen_perms_refresher)"
echo "  ECR_REFRESHER_ROLE_ARN = arn:aws:iam::${ACCOUNT}:role/${REF_ROLE}   (put this in agent-install.env)"

say "4. seed the 5 platform SM secrets from the live cluster (secure, no disk)"
GIT_PAT=""
for s in "${PLATFORM_SECRETS[@]}"; do
  ID="${SM_PREFIX}/${s}"
  VAL="$(kc -n "$NAMESPACE" get secret "$s" -o json | jq -c '[.data|to_entries[]|{(.key):(.value|@base64d)}]|add')"
  if [ "$s" = "remote-job-service" ]; then
    # GITHUB_CREDS_SECRET_ID / REMOTE_JOB_GIT_USERNAME: default to the values every existing
    # tenant already uses (see migration.env.example) so this is a no-op unless overridden.
    GIT_PAT="$(aws secretsmanager get-secret-value --secret-id "${GITHUB_CREDS_SECRET_ID:-promethium-ie-github-credentials}" \
      --region "$REGION" --query SecretString --output text | jq -r '.["remote-job-github-pat"]')"
    VAL="$(printf '%s' "$VAL" | jq -c --arg u "${REMOTE_JOB_GIT_USERNAME:-promethium_ai_support}" --arg p "$GIT_PAT" '. + {GIT_USERNAME:$u, GIT_PAT:$p}')"
  fi
  if printf '%s' "$VAL" | aws secretsmanager create-secret --name "$ID" --secret-string file:///dev/stdin --region "$REGION" >/dev/null 2>&1; then
    echo "  created $s"
  else
    printf '%s' "$VAL" | aws secretsmanager put-secret-value --secret-id "$ID" --secret-string file:///dev/stdin --region "$REGION" >/dev/null
    echo "  updated $s"
  fi
  unset VAL
done
unset GIT_PAT

say "5. probe the ESO->SM chain (throwaway store + ES; deleted after)"
cat <<YAML | kc apply -f - >/dev/null
apiVersion: external-secrets.io/v1
kind: ClusterSecretStore
metadata: {name: mig-probe-store}
spec:
  provider: {aws: {service: SecretsManager, region: ${REGION}, auth: {jwt: {serviceAccountRef: {name: external-secrets, namespace: external-secrets}}}}}
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: mig-probe, namespace: external-secrets}
spec:
  refreshInterval: 1h
  secretStoreRef: {name: mig-probe-store, kind: ClusterSecretStore}
  target: {name: mig-probe-out, creationPolicy: Owner}
  dataFrom: [{extract: {key: ${SM_PREFIX}/promethium-postgres-postgresql}}]
YAML
for i in $(seq 1 15); do sleep 1; done
STORE=$(kc get clustersecretstore mig-probe-store -o jsonpath='{.status.conditions[-1].status}' 2>/dev/null)
ESST=$(kc -n external-secrets get externalsecret mig-probe -o jsonpath='{.status.conditions[-1].reason}' 2>/dev/null)
echo "  store Ready=${STORE:-?}  externalsecret=${ESST:-?}  (want Ready=True / SecretSynced)"
kc -n external-secrets delete externalsecret mig-probe >/dev/null 2>&1 || true
kc -n external-secrets delete secret mig-probe-out >/dev/null 2>&1 || true
kc delete clustersecretstore mig-probe-store >/dev/null 2>&1 || true
[ "$STORE" = "True" ] && [ "$ESST" = "SecretSynced" ] && echo "DONE. ESO chain proven." || die "ESO chain NOT healthy — fix before wiping (check OIDC id, SA annotation, SM seed)."
