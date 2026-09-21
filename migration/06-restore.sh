#!/usr/bin/env bash
# Phase 6 — restore the runtime-mutated trino pieces from the in-cluster backup AFTER the
# umbrella has synced (post-wipe): the data-source catalogs AND the trino users (password.db),
# all under field-manager OpenAPI-Generator so Argo's ignoreDifferences keeps them (no
# self-heal revert). In-process only — nothing written to operator disk. Run once the umbrella
# app is Synced/Healthy and the fresh pm61trino pods are up.
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
export NS="$NAMESPACE"          # for the secret-restore python (os.environ["NS"])
FM="--field-manager=OpenAPI-Generator"

# ESO toggle (see 05-wipe.sh + migration.env). Default true = the umbrella's ExternalSecrets
# recreate the platform secrets post-sync. When false (e.g. DSA — account forbids IAM writes, no
# ESO), 05-wipe PRESERVED the plain platform secrets through the wipe; verify they survived so the
# umbrella's secretKeyRefs resolve. Read-only (kubectl get) — no secret value is decoded. Skipped
# on the default (ESO-on) path, so every other tenant is byte-for-byte unaffected.
EXTERNAL_SECRETS="${EXTERNAL_SECRETS:-true}"
if [ "$EXTERNAL_SECRETS" = false ]; then
  say "0. ESO OFF — verify the ${#PLATFORM_SECRETS[@]} plain platform secrets survived the wipe (05-wipe keep-list)"
  for s in "${PLATFORM_SECRETS[@]}"; do
    if kc -n "$NAMESPACE" get secret "$s" >/dev/null 2>&1; then
      echo "  present: $s"
    else
      echo "  >>> WARNING: $s MISSING — 05-wipe should have preserved it (EXTERNAL_SECRETS=false); the umbrella's secretKeyRef will not resolve"
    fi
  done
fi

say "1. restore *-credentials secrets (base64-preserved, never decoded)"
for b in $(kc -n "$BNS" get secret -o name 2>/dev/null | sed 's|secret/||' | grep '^backup-.*-credentials'); do
  kc -n "$BNS" get secret "$b" -o json | python3 -c '
import json,sys,os
d=json.load(sys.stdin); orig=d["metadata"]["labels"]["migration-backup/of"]
d["metadata"]={"name":orig,"namespace":os.environ["NS"]}
for f in ("status","managedFields"): d.pop(f,None)
print(json.dumps(d))' | kc apply -f - >/dev/null
done
echo "  restored $(kc -n "$NAMESPACE" get secret -o name 2>/dev/null | grep -c -- -credentials) credential secrets"

say "1b. re-seed edge-setting-managed (15 Promethium-managed keys, base64-preserved, never decoded)"
# edge-setting split (umbrella 0.1.15+): the umbrella renders edge-setting-managed EMPTY (Argo
# /data-ignored, edge-update-owned). Re-seed it from 03-backup's pre-wipe backup-edge-setting,
# selecting ONLY the 15 managed keys. base64 flows json->json->apply — never decoded/echoed/to
# disk. Argo /data-ignores every intelligentedge Secret, so these persist (no self-heal revert).
if kc -n "$BNS" get secret backup-edge-setting >/dev/null 2>&1; then
  kc -n "$BNS" get secret backup-edge-setting -o json | python3 -c '
import json,sys,os
MANAGED={"CORE_API_SECRET_KEY","TENANT_INFO_API_KEY","JOB_SCHEDULER_API_KEY","EBS_API_KEY","HEALTHCHECK_ACCESS_KEY","HEALTHCHECK_SECRET_KEY","HEALTHCHECK_COGNITO_PASSWORD","REDASH_SERVICE_USER_PASSWORD","CDATA_DB2_RTK","CDATA_OEM_KEY","TRINO_PASSWORD","ACCESS_KEY_ID","SECRET_KEY_ID","SQS_ACCESS_KEY_ID","SQS_SECRET_ACCESS_KEY"}
d=json.load(sys.stdin); data={k:v for k,v in (d.get("data") or {}).items() if k in MANAGED}
print(json.dumps({"apiVersion":"v1","kind":"Secret","type":"Opaque",
  "metadata":{"name":"edge-setting-managed","namespace":os.environ["NS"],
    "labels":{"app.kubernetes.io/part-of":"intelligent-edge","edge-setting/managed-by":"edge-update"}},
  "data":data}))' | kc apply -f - >/dev/null
  ESM=$(kc -n "$NAMESPACE" get secret edge-setting-managed -o json 2>/dev/null | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("data") or {}))')
  echo "  edge-setting-managed: re-seeded ${ESM}/15 keys"
  [ "$ESM" = 15 ] || echo "  >>> WARNING: expected 15 (backup-edge-setting missing some managed keys)"
else
  echo "  edge-setting-managed: SKIPPED (no backup-edge-setting; CDATA_OEM_KEY/TRINO_PASSWORD refs will not resolve)"
fi

say "2/3/4. merge catalog .properties + password.db users + coordinator/worker env-patches (OpenAPI-Generator)"
eval "$(kc -n "$BNS" get cm backup-pm61trino-catalog backup-pm61trino-coordinator -o json 2>/dev/null | python3 -c '
import json,sys,re,shlex
objs=json.load(sys.stdin)["items"]
cat={o["metadata"]["labels"]["migration-backup/of"]:o for o in objs}
catalog=cat["pm61trino-catalog"]["data"]
static={"hive.properties","tpcds.properties","tpch.properties"}
srcs={k:v for k,v in catalog.items() if k not in static}
print("CM_PATCH="+shlex.quote(json.dumps({"data":srcs})))
print("PWDB="+shlex.quote(cat["pm61trino-coordinator"]["data"].get("password.db","")))
env={}
for fn,body in srcs.items():
    src=fn[:-len(".properties")]; sec=src.replace("_","-")+"-credentials"
    for X in re.findall(r"\$\{ENV:([A-Z0-9_]+)\}", body):
        if X in env: continue
        # CDATA_OEM_KEY moved to edge-setting-managed in the 0.1.15 split (edge-setting now empty).
        tgt=("edge-setting-managed","CDATA_OEM_KEY") if X=="CDATA_OEM_KEY" else (sec,X)
        env[X]={"name":X,"valueFrom":{"secretKeyRef":{"name":tgt[0],"key":tgt[1]}}}
for cont in ("pm61trino-coordinator","pm61trino-worker"):
    p={"spec":{"template":{"spec":{"containers":[{"name":cont,"env":list(env.values())}]}}}}
    print("ENV_%s=%s"%(cont.replace("-","_"),shlex.quote(json.dumps(p))))
')"
kc -n "$NAMESPACE" patch cm pm61trino-catalog --type=merge $FM -p "$CM_PATCH" >/dev/null \
  && echo "  catalog: +$(printf '%s' "$CM_PATCH" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["data"]))') .properties"
# TLS truststores: backup catalog CM's binaryData (.jks, base64) + any non-.properties data
# keys never got merged above (that step only carries the .properties text) — without this,
# cassandra/db2 TLS catalogs crash-loop the coordinator on a missing truststore-path file.
eval "$(kc -n "$BNS" get cm backup-pm61trino-catalog -o json 2>/dev/null | python3 -c '
import json,sys,shlex
d=json.load(sys.stdin)
b=d.get("binaryData") or {}
extra={k:v for k,v in (d.get("data") or {}).items() if not k.endswith(".properties")}
print("BIN_PATCH="+(shlex.quote(json.dumps({"data":extra,"binaryData":b})) if (b or extra) else ""))
print("BIN_N="+str(len(b)))
')"
if [ -n "$BIN_PATCH" ]; then
  kc -n "$NAMESPACE" patch cm pm61trino-catalog --type=merge $FM -p "$BIN_PATCH" >/dev/null \
    && echo "  truststores: +$BIN_N .jks"
else
  echo "  truststores: +0 .jks"
fi
PWDB_PATCH="$(printf '%s' "$PWDB" | python3 -c 'import json,sys;print(json.dumps({"data":{"password.db":sys.stdin.read()}}))')"
kc -n "$NAMESPACE" patch cm pm61trino-coordinator --type=merge $FM -p "$PWDB_PATCH" >/dev/null \
  && echo "  password.db: restored ($(printf '%s' "$PWDB" | grep -c :) users)"
kc -n "$NAMESPACE" patch deploy pm61trino-coordinator --type=strategic $FM -p "$ENV_pm61trino_coordinator" >/dev/null && echo "  coordinator env-patch applied"
kc -n "$NAMESPACE" patch deploy pm61trino-worker      --type=strategic $FM -p "$ENV_pm61trino_worker"      >/dev/null && echo "  worker env-patch applied"

say "5. restart coordinator + worker so trino loads the catalogs + users"
# Force-DELETE the pods (not just `rollout restart`): the catalog CM patch propagates to the
# mounted /etc/trino/catalog volume without replacing the pod, but trino loads catalogs ONLY
# at process startup, and `rollout restart` proved unreliable at replacing the pod. Deleting
# guarantees a fresh start that loads all catalogs.
kc -n "$NAMESPACE" delete pod -l component=coordinator --wait=false >/dev/null 2>&1
kc -n "$NAMESPACE" delete pod -l component=worker --wait=false >/dev/null 2>&1
kc -n "$NAMESPACE" rollout status deploy pm61trino-coordinator --timeout=180s | tail -1
echo "DONE. Verify with 07-verify.sh (SHOW CATALOGS count from the coordinator startup log + password.db user count)."
