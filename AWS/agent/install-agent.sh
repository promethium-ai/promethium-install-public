#!/usr/bin/env bash
# =============================================================================
# Promethium Intelligent-Edge — Model A' agent installer (customer-run, spoke-only)
# =============================================================================
# Installs the argocd-agent stack onto YOUR cluster. It runs entirely against a
# kubeconfig for your own EKS cluster — it never needs access to Promethium's
# control plane. The agent dials OUT to the Promethium hub over mTLS; nothing
# inbound is opened, and Promethium holds no credential to this cluster.
#
# You need, from Promethium (delivered out-of-band, once, per cluster):
#   1. A cert bundle directory containing:  tls.crt  tls.key  ca.crt
#      (your agent's mTLS client identity + the CA that signs the hub principal)
#   2. A config file (agent-install.env) — see agent-install.env.example.
#
# You provide (your cloud, stood up by the Promethium install Terraform):
#   * an EKS cluster (the "spoke") and a kubeconfig context for it
#   * if UMBRELLA_SOURCE=oci: an IRSA role in YOUR account that can pull the
#     Promethium umbrella chart from ECR (ECR_REFRESHER_ROLE_ARN) — created by
#     the install Terraform; its trust policy names this cluster's OIDC provider.
#
# Usage:
#   ./install-agent.sh --config agent-install.env --bundle ./bundle [--context <ctx>] [--dry-run]
#
# Idempotent: safe to re-run. Applies are declarative; the agent restarts at the
# end to pick up config.
# =============================================================================
set -euo pipefail

# ---- args -------------------------------------------------------------------
CONFIG=""; BUNDLE=""; KUBE_CONTEXT=""; DRY_RUN="false"
while [ $# -gt 0 ]; do
  case "$1" in
    --config)  CONFIG="$2"; shift 2 ;;
    --bundle)  BUNDLE="$2"; shift 2 ;;
    --context) KUBE_CONTEXT="$2"; shift 2 ;;
    --dry-run) DRY_RUN="true"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

die(){ echo "ERROR: $*" >&2; exit 1; }
note(){ echo ">> $*"; }
kc(){ if [ -n "$KUBE_CONTEXT" ]; then kubectl --context "$KUBE_CONTEXT" "$@"; else kubectl "$@"; fi; }

# ---- load + validate config -------------------------------------------------
[ -n "$CONFIG" ] && [ -f "$CONFIG" ] || die "--config <file> is required (see agent-install.env.example)"
[ -n "$BUNDLE" ] && [ -d "$BUNDLE" ] || die "--bundle <dir> is required (the cert bundle from Promethium)"
# shellcheck disable=SC1090
set -a; . "$CONFIG"; set +a

: "${TENANT:?set TENANT in the config (your tenant name)}"
: "${PRINCIPAL_ADDRESS:?set PRINCIPAL_ADDRESS (e.g. argocdagent.dev.promethium.ai)}"
: "${PRINCIPAL_PORT:=443}"
: "${ARGOCD_AGENT_REF:=v0.9.0}"
: "${UMBRELLA_SOURCE:=oci}"

for f in tls.crt tls.key ca.crt; do
  [ -s "$BUNDLE/$f" ] || die "bundle is missing $BUNDLE/$f — re-request the cert bundle from Promethium"
done

if [ "$UMBRELLA_SOURCE" = "oci" ]; then
  : "${ECR_REFRESHER_ROLE_ARN:?oci mode needs ECR_REFRESHER_ROLE_ARN (IRSA role in your account, from the install Terraform)}"
  : "${ECR_REGION:?oci mode needs ECR_REGION}"
  : "${ECR_REGISTRY:?oci mode needs ECR_REGISTRY (e.g. 734236616923.dkr.ecr.us-west-1.amazonaws.com)}"
  : "${CHART_NS:=charts}"
fi

# ---- confirm the target cluster (guard against wrong-context applies) --------
CUR_CTX="$(kc config current-context 2>/dev/null || true)"
[ -n "$KUBE_CONTEXT" ] && CUR_CTX="$KUBE_CONTEXT"
SRV="$(kc config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
cat <<EOF

  Promethium A' agent install
  ---------------------------
  tenant            : $TENANT
  kube context      : ${CUR_CTX:-<current>}
  cluster API        : ${SRV:-<unknown>}
  hub principal     : ${PRINCIPAL_ADDRESS}:${PRINCIPAL_PORT} (outbound mTLS only)
  umbrella source   : ${UMBRELLA_SOURCE}$( [ "$UMBRELLA_SOURCE" = oci ] && echo " (ECR ${ECR_REGISTRY}/${CHART_NS})" )
  argocd-agent      : ${ARGOCD_AGENT_REF}
  dry-run           : ${DRY_RUN}

EOF
kc get nodes >/dev/null 2>&1 || die "cannot reach the cluster with this context — check your kubeconfig / --context"
if [ "$DRY_RUN" != "true" ]; then
  printf "Proceed installing the agent into the cluster above? [y/N] "
  read -r ans; [ "$ans" = "y" ] || [ "$ans" = "Y" ] || die "aborted by user"
fi

APPLY="kc apply -f -"; [ "$DRY_RUN" = "true" ] && APPLY="kc apply --dry-run=client -f -"
BASE="https://github.com/argoproj-labs/argocd-agent/install/kubernetes"

# ---- 1. namespace -----------------------------------------------------------
note "ensure argocd namespace"
kc create namespace argocd --dry-run=client -o yaml | eval "$APPLY"

# ---- 2. agent stack (managed data plane + agent) ----------------------------
note "install argocd-agent managed data plane + agent (${ARGOCD_AGENT_REF})"
if [ "$DRY_RUN" = "true" ]; then
  echo "   (dry-run) would: kubectl apply -n argocd -k ${BASE}/argo-cd/agent-managed?ref=${ARGOCD_AGENT_REF}"
  echo "   (dry-run) would: kubectl apply -n argocd -k ${BASE}/agent?ref=${ARGOCD_AGENT_REF}"
else
  kc apply -n argocd -k "${BASE}/argo-cd/agent-managed?ref=${ARGOCD_AGENT_REF}"
  kc apply -n argocd -k "${BASE}/agent?ref=${ARGOCD_AGENT_REF}"
fi

# ---- 3. mTLS identity (from the Promethium-issued bundle) --------------------
note "apply agent client cert + CA (from the bundle)"
TLS_CRT_B64="$(base64 < "$BUNDLE/tls.crt" | tr -d '\n')"
TLS_KEY_B64="$(base64 < "$BUNDLE/tls.key" | tr -d '\n')"
CA_CRT_B64="$(base64 < "$BUNDLE/ca.crt"  | tr -d '\n')"
eval "$APPLY" <<EOF
apiVersion: v1
kind: Secret
metadata: { name: argocd-agent-client-tls, namespace: argocd }
type: kubernetes.io/tls
data:
  tls.crt: ${TLS_CRT_B64}
  tls.key: ${TLS_KEY_B64}
---
apiVersion: v1
kind: Secret
metadata: { name: argocd-agent-ca, namespace: argocd }
type: Opaque
data:
  ca.crt: ${CA_CRT_B64}
EOF

# ---- 4. umbrella source credential -----------------------------------------
if [ "$UMBRELLA_SOURCE" = "oci" ]; then
  note "install ECR->Argo OCI credential refresher (no GitHub cred on this cluster)"
  MANIFEST="$(dirname "$0")/manifests/ecr-oci-cred-refresh.yaml"
  [ -f "$MANIFEST" ] || die "missing $MANIFEST (bundled with this installer)"
  # Restrict envsubst to ONLY our placeholders so the CronJob's runtime shell
  # vars ($TOKEN etc.) survive — a bare envsubst would blank them.
  export ECR_REFRESHER_ROLE_ARN ECR_REGION ECR_REGISTRY CHART_NS
  envsubst '${ECR_REFRESHER_ROLE_ARN} ${ECR_REGION} ${ECR_REGISTRY} ${CHART_NS}' < "$MANIFEST" | eval "$APPLY"
  if [ "$DRY_RUN" != "true" ]; then
    note "seed the OCI repo secret now (one-shot, don't wait for the 6h schedule)"
    kc -n argocd create job "ie-ecr-oci-bootstrap-$(date +%s)" --from=cronjob/argocd-ecr-cred-refresh || true
    kc -n argocd wait --for=condition=complete job -l job-name --timeout=150s 2>/dev/null || true
    kc -n argocd get secret ie-ecr-oci >/dev/null 2>&1 \
      && note "ie-ecr-oci present (real ECR token written)" \
      || echo "   WARN: ie-ecr-oci not yet present — check the refresher job + IRSA role ${ECR_REFRESHER_ROLE_ARN}"
  fi
else
  : "${GIT_REPO_URL:?git mode needs GIT_REPO_URL}"; : "${GIT_USERNAME:?}"; : "${GIT_PASSWORD:?}"
  note "install git repo-creds for the umbrella (git mode)"
  eval "$APPLY" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: repo-creds-promethium-ai
  namespace: argocd
  labels: { argocd.argoproj.io/secret-type: repo-creds }
type: Opaque
stringData:
  type: git
  url: ${GIT_REPO_URL}
  username: ${GIT_USERNAME}
  password: ${GIT_PASSWORD}
EOF
fi

# ---- 5. agent params (managed mode, mTLS, point at the hub principal) --------
note "patch argocd-agent-params -> managed/mTLS, principal ${PRINCIPAL_ADDRESS}:${PRINCIPAL_PORT}"
if [ "$DRY_RUN" = "true" ]; then
  echo "   (dry-run) would patch configmap argocd-agent-params"
else
  kc -n argocd patch configmap argocd-agent-params --type merge -p "{\"data\":{\"agent.mode\":\"managed\",\"agent.creds\":\"mtls:\",\"agent.server.address\":\"${PRINCIPAL_ADDRESS}\",\"agent.server.port\":\"${PRINCIPAL_PORT}\",\"agent.destination-based-mapping\":\"true\",\"agent.label-selector\":\"argocd-agent=true\",\"agent.tls.secret-name\":\"argocd-agent-client-tls\",\"agent.tls.root-ca-secret-name\":\"argocd-agent-ca\",\"agent.resource-proxy.enable\":\"true\"}}"
  note "ignore any unmanaged apps already on the cluster"
  kc -n argocd set env deployment/argocd-agent-agent ARGOCD_AGENT_IGNORE_UNMANAGED_APPS=true
fi

# ---- 6. restart + verify ----------------------------------------------------
if [ "$DRY_RUN" = "true" ]; then
  echo; note "dry-run complete — no changes applied."; exit 0
fi
note "restart the agent to pick up params + secrets"
kc -n argocd rollout restart deployment/argocd-agent-agent
kc -n argocd rollout status  deployment/argocd-agent-agent --timeout=180s

# ---- 7. seed the intelligentedge image-pull secret (agent BYO) --------------
# The OCI umbrella's pods pull container images cross-account from ECR via
# aws-ecr-docker-creds. In BYO the same-account 10-min ecr-cron-job does not
# provide this, so seed it here from the refresher's ie-ecr-oci token once the
# hub Application has created the intelligentedge namespace, and give EVERY ns
# SA the pull secret (bitnami postgres + trino's presto-catalog-account/trino-sa
# use named SAs, not just default). One-shot — the ECR token TTL covers an
# install/demo; the durable 6h refresh is tracked as codify C.
: "${ECR_REGISTRY:=734236616923.dkr.ecr.us-west-1.amazonaws.com}"
note "waiting for the intelligentedge namespace (hub umbrella sync) to seed the image-pull secret..."
for _ in $(seq 1 30); do kc get ns intelligentedge >/dev/null 2>&1 && break; sleep 10; done
if kc get ns intelligentedge >/dev/null 2>&1; then
  IE_PW="$(kc -n argocd get secret ie-ecr-oci -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null || true)"
  if [ -n "$IE_PW" ]; then
    kc -n intelligentedge create secret docker-registry aws-ecr-docker-creds \
      --docker-server="${ECR_REGISTRY}" --docker-username=AWS --docker-password="$IE_PW" \
      --dry-run=client -o yaml | kc apply -f -
    for sa in $(kc -n intelligentedge get sa -o name 2>/dev/null | sed 's|serviceaccount/||'); do
      kc -n intelligentedge patch sa "$sa" -p '{"imagePullSecrets":[{"name":"aws-ecr-docker-creds"}]}' >/dev/null 2>&1 || true
    done
    kc -n intelligentedge delete pod --field-selector=status.phase!=Succeeded >/dev/null 2>&1 || true
    note "seeded aws-ecr-docker-creds + patched intelligentedge SAs."
  else
    note "WARN: argocd/ie-ecr-oci has no password yet — image pull may stall until the refresher writes it."
  fi
else
  note "WARN: intelligentedge namespace not present after ~5m — image pull will stall until aws-ecr-docker-creds is seeded there."
fi

echo
note "DONE. Agent installed and dialing out to ${PRINCIPAL_ADDRESS}:${PRINCIPAL_PORT}."
kc -n argocd get pods | grep argocd-agent || true
cat <<EOF

Next: Promethium's hub generates your tenant's Application once your tenant file
is registered; it reconciles here via the agent. Check workloads with:
  kubectl -n intelligentedge get pods
This cluster holds no Promethium credential and exposes nothing inbound.
EOF
