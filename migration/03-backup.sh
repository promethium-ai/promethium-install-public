#!/usr/bin/env bash
# Phase 3 — SECURE in-cluster backup of the runtime-mutated trino pieces the umbrella does
# NOT recreate: the catalog layer (pm61trino-catalog + *-credentials) AND the trino users
# (password.db, inside pm61trino-coordinator). Everything is copied to the `migration-backup`
# namespace ON THE SAME CLUSTER — nothing is decoded, written to disk, or leaves the cluster.
# Run BEFORE the wipe (phase 5). Idempotent.
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
export BNS

kc get ns "$BNS" >/dev/null 2>&1 || kc create ns "$BNS"

copy_into_backup(){ # $1=kind $2=name
  kc -n "$NAMESPACE" get "$1" "$2" -o json 2>/dev/null | python3 -c '
import json,sys,os
d=json.load(sys.stdin); k=d["kind"]; n=d["metadata"]["name"]
d["metadata"]={"name":"backup-"+n,"namespace":os.environ["BNS"],
  "labels":{"migration-backup/of":n,"migration-backup/kind":k.lower()}}
for f in ("status","managedFields"): d.pop(f,None)
d.get("metadata",{}).pop("ownerReferences",None)
print(json.dumps(d))' | kc apply -f - >/dev/null && echo "  backed up $1/$2"
}

say "catalog layer"
copy_into_backup configmap pm61trino-catalog
for s in $(kc -n "$NAMESPACE" get secret -o name 2>/dev/null | sed 's|secret/||' | grep -- '-credentials'); do
  copy_into_backup secret "$s"
done
say "password.db (via the coordinator CM)"
copy_into_backup configmap pm61trino-coordinator

# edge-setting split (umbrella 0.1.15+): the 15 Promethium-managed secrets live in the
# edge-update-owned `edge-setting-managed` Secret, which the umbrella renders EMPTY (Argo
# /data-ignored) and 05-wipe DELETES along with the legacy plain `edge-setting`. Back the
# live edge-setting up here (whole secret, base64 as-is — never decoded) so 06-restore can
# re-seed edge-setting-managed post-sync. Guarded: a tenant with no edge-setting is skipped.
say "edge-setting (Promethium-managed secrets — for the edge-setting-managed re-seed)"
if kc -n "$NAMESPACE" get secret edge-setting >/dev/null 2>&1; then
  copy_into_backup secret edge-setting
else
  echo "  edge-setting not present — SKIPPED (a 0.1.15+ migration needs the 15 managed keys; verify)"
fi

# --- forensic namespace inventory (added 2026-09-14) -----------------------------------------
# The copies above are the TARGETED restore-backup (trino catalog layer + creds + edge-setting);
# they do NOT record what was RUNNING. 05-wipe then removes the namespace's workloads, so without
# this there is no way to answer "was <X> (e.g. mantra-edge) ever deployed here" after a wipe.
# Capture a full object INVENTORY — kinds + names + wide status — into the backup ns. NOTE: this
# is names/metadata only (secret VALUES are never included: `get secret -o wide` prints only
# name/type/data-count), so it is safe to hold in a ConfigMap and honours the no-plaintext rule.
say "namespace inventory (forensic record of every object present, pre-wipe)"
INV="$(kc -n "$NAMESPACE" get all,cm,secret,ingress,cronjob,pvc,sa,role,rolebinding,networkpolicy,pdb,externalsecret -o wide 2>&1)"
kc -n "$BNS" create configmap backup-namespace-inventory \
  --from-literal=captured="$(date -u +%FT%TZ)" \
  --from-literal=namespace="$NAMESPACE" \
  --from-literal=inventory="$INV" \
  --dry-run=client -o yaml 2>/dev/null | kc apply -f - >/dev/null \
  && echo "  saved backup-namespace-inventory ($(printf '%s\n' "$INV" | grep -c .) lines)"

CAT=$(kc -n "$BNS" get cm backup-pm61trino-catalog -o json 2>/dev/null | python3 -c 'import json,sys;print(sum(1 for k in json.load(sys.stdin).get("data",{}) if k.endswith(".properties")))')
USR=$(kc -n "$BNS" get cm backup-pm61trino-coordinator -o json 2>/dev/null | python3 -c 'import json,sys;print(sum(1 for l in json.load(sys.stdin).get("data",{}).get("password.db","").splitlines() if ":" in l))')
CRD=$(kc -n "$BNS" get secret --no-headers 2>/dev/null | grep -c -- '-credentials')
ESM=$(kc -n "$BNS" get secret backup-edge-setting -o json 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin).get("data") or {}
except Exception: print("0"); sys.exit()
m={"CORE_API_SECRET_KEY","TENANT_INFO_API_KEY","JOB_SCHEDULER_API_KEY","EBS_API_KEY","HEALTHCHECK_ACCESS_KEY","HEALTHCHECK_SECRET_KEY","HEALTHCHECK_COGNITO_PASSWORD","REDASH_SERVICE_USER_PASSWORD","CDATA_DB2_RTK","CDATA_OEM_KEY","TRINO_PASSWORD","ACCESS_KEY_ID","SECRET_KEY_ID","SQS_ACCESS_KEY_ID","SQS_SECRET_ACCESS_KEY"}
print(sum(1 for k in d if k in m))' 2>/dev/null || echo 0)
echo "DONE. backup: catalogs=${CAT} users=${USR} creds=${CRD} edge-managed=${ESM}/15 (nothing on disk). Record these as the baseline."
