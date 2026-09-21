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

# --- reuse-mode gate (EXTERNAL_SECRETS=false) --------------------------------------------
# Read the SAME way 05-wipe.sh reads it (via lib.sh sourcing migration.env). When false, this
# legacy-migration tenant reuses its existing legacy IAM roles (trino etc.) and keeps the 5 platform
# secrets as plain k8s Secrets (05-wipe preserves them, 06-restore verifies them) — so the ESO half
# of this phase is NOT needed: no ESO install, no eso-reader role, no SM seed, no probe (those are
# the IAM writes an org SCP would deny). The ONE piece a migration tenant STILL needs is the
# ecr-refresher IRSA role: the spoke pulls the IE umbrella OCI chart from ECR, and — unlike a
# greenfield tenant, whose infra tf (argocd-ecr-refresher-oidc.tf) mints it at deploy time — a legacy
# tenant never ran our infra, so THIS bundle creates it. Created inline + scoped to REF_ROLE, which
# needs the org SCP to permit iam:CreateRole + iam:PutRolePolicy for that role (see the DSA
# SCP-relaxation request). Set CREATE_ECR_REFRESHER_ROLE=false for a truly-locked tenant that cannot
# get the relaxation (then supply ie-ecr-oci another way). Default (unset/true) leaves the ESO-on
# path below byte-for-byte unchanged.
EXTERNAL_SECRETS="${EXTERNAL_SECRETS:-true}"
CREATE_ECR_REFRESHER_ROLE="${CREATE_ECR_REFRESHER_ROLE:-true}"
if [ "$EXTERNAL_SECRETS" = false ]; then
  say "reuse-mode (EXTERNAL_SECRETS=false): reuse the tenant's existing legacy IAM roles + keep the 5 platform secrets as plain k8s Secrets — skipping ESO install / eso-reader / SM seed / probe (none needed; they are the IAM writes an org SCP would deny)."
  if [ "$CREATE_ECR_REFRESHER_ROLE" = false ]; then
    say "CREATE_ECR_REFRESHER_ROLE=false → also skipping the ecr-refresher role (truly-locked tenant with no SCP relaxation; supply ie-ecr-oci another way)."
    exit 0
  fi
  : "${OIDC_ID:?run 01-capture-identity.sh first (sets OIDC_ID)}"
  say "3. ecr-refresher IRSA role (the ONE IAM write a migration tenant makes — needs the SCP to permit iam:CreateRole + iam:PutRolePolicy for ${REF_ROLE})"
  aws iam create-role --role-name "$REF_ROLE" --assume-role-policy-document "$(gen_trust argocd argocd-ecr-cred-refresher)" >/dev/null 2>&1 \
    && echo "  role $REF_ROLE created" || echo "  role $REF_ROLE exists"
  aws iam put-role-policy --role-name "$REF_ROLE" --policy-name ecr-pull --policy-document "$(gen_perms_refresher)"
  echo "  ECR_REFRESHER_ROLE_ARN = arn:aws:iam::${ACCOUNT}:role/${REF_ROLE}   (put this in agent-install.env)"

  # 4. reuse the tenant's OWN git creds. Legacy tf bakes GIT_USERNAME/GIT_PAT INLINE into the
  # remote-job-service deployment's git-clone init container (promethium/modules/dbt/deploy.tf) —
  # they are NOT in any k8s secret. The A' umbrella instead reads them from the remote-job-service
  # Secret (secretKeyRef GIT_USERNAME/GIT_PAT), normally ESO-populated. In reuse-mode (ESO off)
  # there is no source, so extract them from the LIVE legacy init container (in-cluster — no
  # platform-SM / cross-account read, so it works in a locked customer account) and seed them into
  # the secret BEFORE the wipe preserves it. Never echoed / written to disk.
  say "4. reuse the tenant's git creds: legacy remote-job-service init container -> the remote-job-service secret"
  RJ_CLONE=$(kc -n "$NAMESPACE" get deploy remote-job-service -o jsonpath='{range .spec.template.spec.initContainers[*]}{.command}{end}' 2>/dev/null || true)
  GIT_U=$(printf '%s' "$RJ_CLONE" | sed -nE 's#.*https://([^:]+):[^@]+@github\.com.*#\1#p')
  GIT_P=$(printf '%s' "$RJ_CLONE" | sed -nE 's#.*https://[^:]+:([^@]+)@github\.com.*#\1#p')
  if [ -n "$GIT_U" ] && [ -n "$GIT_P" ]; then
    kc -n "$NAMESPACE" patch secret remote-job-service --type merge \
      -p "$(jq -n --arg u "$(printf %s "$GIT_U" | base64)" --arg p "$(printf %s "$GIT_P" | base64)" '{data:{GIT_USERNAME:$u,GIT_PAT:$p}}')" >/dev/null \
      && echo "  seeded GIT_USERNAME/GIT_PAT into remote-job-service (reused from the legacy init container)"
  else
    echo "  WARN: no git creds in the legacy remote-job-service init container — if this tenant clones drivers, seed GIT_USERNAME/GIT_PAT into the remote-job-service secret manually (Promethium PAT: promethium-ie-github-credentials key remote-job-github-pat, user promethium_ai_support)."
  fi
  unset RJ_CLONE GIT_U GIT_P
  exit 0
fi

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
    # CAPTURE-FROM-LIVE (2026-09-15): the tenant's running remote-job-service secret already
    # carries GIT_USERNAME/GIT_PAT — its init container clones with them (the deployment reads
    # them from THIS secret via secretKeyRef). Keep those; no cross-account fetch, so this works
    # for a self-serve customer who can't read Promethium's control-plane secret. Fall back to the
    # control-plane github-credentials secret ONLY if the live secret lacks them (managed/legacy
    # tenants whose git creds live centrally). See task_e56dc0c7 (self-serve) / task_1ff7b7d5.
    if [ "$(printf '%s' "$VAL" | jq -r 'has("GIT_USERNAME") and has("GIT_PAT")')" = "true" ]; then
      echo "  remote-job-service: git creds captured from the live tenant secret (no cross-account fetch)"
    else
      GIT_PAT="$(aws secretsmanager get-secret-value --secret-id "${GITHUB_CREDS_SECRET_ID:-promethium-ie-github-credentials}" \
        --region "$REGION" --query SecretString --output text | jq -r '.["remote-job-github-pat"]')"
      VAL="$(printf '%s' "$VAL" | jq -c --arg u "${REMOTE_JOB_GIT_USERNAME:-promethium_ai_support}" --arg p "$GIT_PAT" '. + {GIT_USERNAME:$u, GIT_PAT:$p}')"
      echo "  remote-job-service: git creds not in live secret — seeded from control-plane (fallback)"
    fi
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
