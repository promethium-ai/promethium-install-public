#!/usr/bin/env bash
# Phase 5 — wipe the legacy IE workloads so the umbrella deploys fresh. KEEPS: ServiceAccounts,
# PVCs (incl the phase-4 re-bind), aws-ecr-docker-creds, the legacy postgres-backup-cronjob, INGRESSES
# (they stay on the promethium-ingress ALB with working DNS — do NOT re-create them), and the
# migration-backup namespace. On a MANTRA tenant it ALSO keeps the live mantra-edge layer
# (deploy/mantra-edge{,-mcp}, cronjob/mantra-edge-data-sampling, secret/mantra-edge-secret and
# any mantra-edge* svc/cm/role) — auto-detected, or forced with MANTRA_TENANT=true in migration.env.
# GUARDED: refuses unless the phase-3 backup exists.
#
# ⚠ BEFORE running this, raise the nodegroup floor so the emptied cluster's autoscaler can't
#    scale to 0 and deadlock the redeploy:
#      aws eks update-nodegroup-config --cluster-name <cluster> --nodegroup-name <ng> \
#        --scaling-config minSize=3,desiredSize=4,maxSize=6 --region <region>
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

kc get ns "$BNS" >/dev/null 2>&1 && [ "$(kc -n "$BNS" get cm,secret --no-headers 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] \
  || die "no ns/${BNS} contents — run 03-backup.sh first (catalog + password.db would be lost)."

# safety: don't wipe an emptied-to-0 cluster
NODES=$(kc get nodes --no-headers 2>/dev/null | grep -c ' Ready')
[ "${NODES:-0}" -ge 1 ] || die "no Ready nodes — raise the nodegroup floor first (see header)."

# --- mantra carve-out --------------------------------------------------------------------
# A mantra-enabled tenant runs its LIVE mantra layer in THIS namespace; the umbrella migration
# must leave it running. Auto-detected by a mantra-edge* deployment; force on/off with
# MANTRA_TENANT=true|false in migration.env. When on, every mantra-edge*-named object is spared.
case "${MANTRA_TENANT:-auto}" in
  true|1|yes) KEEP_MANTRA=true ;;
  false|0|no) KEEP_MANTRA=false ;;
  *) if kc -n "$NAMESPACE" get deploy -o name 2>/dev/null | grep -q '/mantra-edge'; then
       KEEP_MANTRA=true; else KEEP_MANTRA=false; fi ;;
esac
# exclusion regexes for the enumerate-and-grep-v deletes (mantra tail added only when KEEP_MANTRA)
# ecr-registry-helper dropped 2026-09-15 — redundant on A′ (agent refresher owns ECR creds) + leaks pod-slots; see ecr-registry-helper-slot-leak.
CJ_KEEP='^postgres-backup-cronjob$'
SEC_KEEP='^aws-ecr-docker-creds$'
MANTRA_MSG=''
if [ "$KEEP_MANTRA" = true ]; then
  # Spare mantra-edge* objects AND the mantra-edge HELM RELEASE secret
  # (`sh.helm.release.v1.mantra-edge.v<n>`) — its name starts with `sh.helm.release`, not
  # `mantra-edge`, so a bare ^mantra-edge would MISS it and the wipe would orphan the live
  # mantra-edge release from helm (workloads survive but become un-upgradeable/un-manageable).
  CJ_KEEP="$CJ_KEEP|^mantra-edge"
  SEC_KEEP="$SEC_KEEP|^mantra-edge|^sh\.helm\.release\.v1\.mantra-edge"
  MANTRA_MSG=' + mantra-edge*'
  say "MANTRA tenant — sparing the live mantra-edge layer (deploy/svc/cm/role/cronjob/secret named mantra-edge*, + its sh.helm.release.v1.mantra-edge* release secret)"
fi

# --- ESO carve-out (platform secrets) ----------------------------------------------------
# EXTERNAL_SECRETS=false (migration.env) → this tenant's umbrella has externalSecrets DISABLED
# (tenant file spec.ie.externalSecrets: false), so NO ExternalSecret will recreate the platform
# secrets after the wipe — e.g. DSA, whose account forbids IAM writes (no eso-reader role / SM).
# PRESERVE the plain platform secrets (${PLATFORM_SECRETS[@]}, defined in lib.sh) through the wipe
# so the umbrella's secretKeyRefs resolve. Anchored ^name$ per secret so ^edge-setting$ does NOT
# also spare edge-setting-managed (06-restore re-seeds that). Default true (every other tenant)
# leaves SEC_KEEP untouched → the ESO-on path is byte-for-byte unchanged.
EXTERNAL_SECRETS="${EXTERNAL_SECRETS:-true}"
ESO_MSG=''
# services-subchart SA-token secrets: the chart's charts/services/templates/secrets.yaml renders
# edge-setting + presto-catalog-account-secret + prestosync-token, ALL gated on createTenantSecret(s).
# Reuse-mode derives global.createTenantSecrets=false (from externalSecrets:false), so the chart
# SKIPS all three. edge-setting is in PLATFORM_SECRETS below; the two SA-token secrets are NOT — but
# edge-update/prestosync/createredashuser consume prestosync-token via secretKeyRef{,token}, and the
# chart won't re-create it, so the working legacy copies MUST survive the wipe too. (norole 2026-09-20)
SATOKEN_SECRETS=(presto-catalog-account-secret prestosync-token)
if [ "$EXTERNAL_SECRETS" = false ]; then
  for s in "${PLATFORM_SECRETS[@]}" "${SATOKEN_SECRETS[@]}"; do SEC_KEEP="$SEC_KEEP|^${s}$"; done
  ESO_MSG=' + platform + SA-token secrets (ESO off)'
  say "ESO OFF (EXTERNAL_SECRETS=false) — also sparing the ${#PLATFORM_SECRETS[@]} plain platform secrets (${PLATFORM_SECRETS[*]}) + the services SA-token secrets (${SATOKEN_SECRETS[*]}) so the umbrella's secretKeyRefs resolve without ExternalSecrets."
fi

say "workloads (deploy/sts/ds/rs/svc/cm/role/rolebinding/hpa/job)${MANTRA_MSG:+, EXCEPT mantra-edge*}"
if [ "$KEEP_MANTRA" = true ]; then
  # --all can't spare by name, so enumerate + grep -v like the cronjob/secret loops below.
  # -o name prints <type>/<name> (or <type>.<group>/<name>); '/mantra-edge' anchors on that
  # single '/', matching only objects whose NAME begins mantra-edge. '|| true' tolerates the
  # owner/child GC race (e.g. an rs already reaped after its deploy) so the wipe can't abort.
  for obj in $(kc -n "$NAMESPACE" get deploy,sts,ds,rs,svc,cm,role,rolebinding,hpa,job -o name 2>/dev/null | grep -vE '/mantra-edge'); do
    kc -n "$NAMESPACE" delete "$obj" --wait=false 2>&1 || true
  done | tail -3
else
  kc -n "$NAMESPACE" delete deploy,sts,ds,rs,svc,cm,role,rolebinding,hpa,job --all --wait=false 2>&1 | tail -3
fi
say "cronjobs EXCEPT postgres-backup-cronjob${MANTRA_MSG}"
for cj in $(kc -n "$NAMESPACE" get cronjob -o name 2>/dev/null | sed 's|.*/||' | grep -vE "$CJ_KEEP"); do
  kc -n "$NAMESPACE" delete cronjob "$cj" --wait=false 2>&1
done
say "secrets EXCEPT aws-ecr-docker-creds${MANTRA_MSG}${ESO_MSG}"
for s in $(kc -n "$NAMESPACE" get secret -o name 2>/dev/null | sed 's|secret/||' | grep -vE "$SEC_KEEP"); do
  kc -n "$NAMESPACE" delete secret "$s" --wait=false >/dev/null 2>&1
done
echo "  kept: SAs, PVCs, aws-ecr-docker-creds, cronjobs {postgres-backup-cronjob}, INGRESSES, ns/${BNS}${MANTRA_MSG:+, mantra-edge* (live mantra layer)}${ESO_MSG:+, platform secrets {${PLATFORM_SECRETS[*]}} + SA-token secrets {${SATOKEN_SECRETS[*]}} (ESO off — plain k8s Secrets)}"
echo "DONE. Enroll the agent (phase after this), then hard-refresh the hub app:"
echo "  kubectl --context <hub> -n argocd annotate application ${TENANT}-${ENV}-ie argocd.argoproj.io/refresh=hard --overwrite"
