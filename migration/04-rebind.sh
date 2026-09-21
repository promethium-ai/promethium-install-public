#!/usr/bin/env bash
# Phase 4 — postgres EBS re-bind: preserve the tenant's postgres data across the wipe by
# retaining its EBS volume and re-binding it under the umbrella's bitnami PVC name. Patches
# ALL stateful PVs to Retain FIRST (before any delete), then renames the postgres PVC to
# data-promethium-postgres-postgresql-0 so the umbrella's postgres StatefulSet adopts the
# existing data. Auto-detects the postgres PV/vol/storageClass/size — tenant-agnostic.
# If the tenant's postgres already uses the bitnami PVC name, this is a safe no-op (still
# patches PVs to Retain). Data never moves; the vol is reattached in place.
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
BITNAMI_PVC=data-promethium-postgres-postgresql-0

say "patch all stateful PVs -> Retain (data safety, BEFORE any delete)"
for pvc in $(kc -n "$NAMESPACE" get pvc -o name 2>/dev/null | sed 's|.*/||'); do
  pv=$(kc -n "$NAMESPACE" get pvc "$pvc" -o jsonpath='{.spec.volumeName}' 2>/dev/null)
  [ -n "$pv" ] && kc patch pv "$pv" -p '{"spec":{"persistentVolumeReclaimPolicy":"Retain"}}' >/dev/null && echo "  $pvc ($pv) -> Retain"
done

PGPVC=$(kc -n "$NAMESPACE" get pvc -o name 2>/dev/null | sed 's|.*/||' | grep -iE 'postgres' | grep -v "$BITNAMI_PVC" | head -1)
[ -n "$PGPVC" ] || { echo "no legacy postgres PVC found (already re-bound under the bitnami name?) — nothing to do."; exit 0; }
PGPV=$(kc -n "$NAMESPACE" get pvc "$PGPVC" -o jsonpath='{.spec.volumeName}')
SC=$(kc get pv "$PGPV" -o jsonpath='{.spec.storageClassName}'); SZ=$(kc get pv "$PGPV" -o jsonpath='{.spec.capacity.storage}')
VOL=$(kc get pv "$PGPV" -o jsonpath='{.spec.csi.volumeHandle}')
say "legacy postgres: PVC=$PGPVC PV=$PGPV vol=$VOL sc=$SC size=$SZ"

say "delete legacy postgres sts + PVC (EBS retained)"
for sts in $(kc -n "$NAMESPACE" get sts -o name 2>/dev/null | sed 's|.*/||' | grep -i postgres); do kc -n "$NAMESPACE" delete sts "$sts" --wait=true --timeout=120s; done
kc -n "$NAMESPACE" delete pvc "$PGPVC" --wait=false
for i in $(seq 1 12); do [ "$(kc get pv "$PGPV" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Released" ] && break; sleep 5; done

say "strip claimRef + re-bind under the bitnami name"
kc patch pv "$PGPV" --type=json -p='[{"op":"remove","path":"/spec/claimRef"}]' >/dev/null; sleep 3
cat <<YAML | kc apply -f - >/dev/null
apiVersion: v1
kind: PersistentVolumeClaim
metadata: { name: $BITNAMI_PVC, namespace: $NAMESPACE }
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: $SC
  resources: { requests: { storage: $SZ } }
  volumeName: $PGPV
YAML
for i in $(seq 1 6); do [ "$(kc -n "$NAMESPACE" get pvc "$BITNAMI_PVC" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Bound" ] && break; sleep 3; done
echo "  $BITNAMI_PVC -> $(kc -n "$NAMESPACE" get pvc "$BITNAMI_PVC" -o jsonpath='{.status.phase}') on $PGPV (vol $VOL)"
echo "DONE. postgres data re-bound under the umbrella PVC name; the umbrella will adopt it."
