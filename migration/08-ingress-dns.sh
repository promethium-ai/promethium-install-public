#!/usr/bin/env bash
# Phase 8 — external access. The umbrella only makes NodePort services; ingress + DNS are
# tf-owned. The wipe (05) KEEPS ingresses, so a full-legacy-tf tenant's trino/redash/nginx
# ingresses survive on the `promethium-ingress` ALB with their DNS intact — leave them alone.
# The ONLY gap is the net-added trino-stream host (legacy tf never made it). This script:
#   - if the legacy ingresses survived: add ONLY a trino-stream ingress to the SAME
#     promethium-ingress group + UPSERT ONLY the trino-stream DNS record.
#   - if they were deleted: recreate all four on promethium-ingress + UPSERT all four records.
# ⚠ Never change a surviving ingress's group.name — that rebuilds the ALB (new hostname) and
#   forces you to re-point every DNS record for no benefit.
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"
GROUP=promethium-ingress
# host -> service:port
HOSTS_TRINO="${TENANT}-trino.${DOMAIN}";          SVC_TRINO="pm61trino:8080"
HOSTS_NGINX="${TENANT}-nginx.${DOMAIN}";          SVC_NGINX="nginx:80"
HOSTS_REDASH="${TENANT}-redash.${DOMAIN}";        SVC_REDASH="redash:80"
HOSTS_STREAM="${TENANT}-trino-stream.${DOMAIN}";  SVC_STREAM="promethium-trino-stream:80"

mk_ingress(){ # $1=name $2=host $3=svc:port [$4=healthcheck-path]
  local name="$1" host="$2" svc="${3%%:*}" port="${3##*:}" hc="${4:-}"
  cat <<YAML | kc apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/group.name: ${GROUP}
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: instance
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443},{"HTTP":80}]'
    alb.ingress.kubernetes.io/success-codes: "200-399"
$( [ -n "$hc" ] && echo "    alb.ingress.kubernetes.io/healthcheck-path: ${hc}" )
spec:
  rules:
    - host: ${host}
      http: { paths: [ { path: /, pathType: Prefix, backend: { service: { name: ${svc}, port: { number: ${port} } } } } ] }
YAML
  echo "  applied ingress ${name} (${host} -> ${3}) on group ${GROUP}"
}

upsert_dns(){ # $1=host $2=alb-hostname
  aws route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" --change-batch "{
    \"Changes\":[{\"Action\":\"UPSERT\",\"ResourceRecordSet\":{\"Name\":\"$1\",\"Type\":\"CNAME\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"$2\"}]}}]}" >/dev/null \
    && echo "  DNS $1 -> $2"
}

SURVIVED=$(kc -n "$NAMESPACE" get ingress trino-ingress -o jsonpath='{.metadata.annotations.alb\.ingress\.kubernetes\.io/group\.name}' 2>/dev/null || true)

if [ "$SURVIVED" = "$GROUP" ]; then
  say "legacy ingresses survived on ${GROUP} — net-add trino-stream ONLY"
  kc -n "$NAMESPACE" get ingress trino-stream-ingress >/dev/null 2>&1 || mk_ingress trino-stream-ingress "$HOSTS_STREAM" "$SVC_STREAM"
  for i in $(seq 1 30); do ALB=$(kc -n "$NAMESPACE" get ingress trino-ingress -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null); [ -n "$ALB" ] && break; sleep 3; done
  echo "  promethium-ingress ALB = ${ALB}"
  upsert_dns "$HOSTS_STREAM" "$ALB"
  echo "DONE. trino/nginx/redash DNS untouched (still valid); only trino-stream added."
else
  say "legacy ingresses NOT present — recreate all four on ${GROUP}"
  mk_ingress trino-ingress        "$HOSTS_TRINO"  "$SVC_TRINO"  /ui/login.html
  mk_ingress redash-ingress       "$HOSTS_REDASH" "$SVC_REDASH"
  mk_ingress nginx-ingress        "$HOSTS_NGINX"  "$SVC_NGINX"
  mk_ingress trino-stream-ingress "$HOSTS_STREAM" "$SVC_STREAM"
  for i in $(seq 1 40); do ALB=$(kc -n "$NAMESPACE" get ingress trino-ingress -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null); [ -n "$ALB" ] && break; sleep 3; done
  echo "  promethium-ingress ALB = ${ALB}"
  for h in "$HOSTS_TRINO" "$HOSTS_NGINX" "$HOSTS_REDASH" "$HOSTS_STREAM"; do upsert_dns "$h" "$ALB"; done
  echo "DONE. all four hosts point at ${ALB}."
fi
echo "⚠ Never create the bare ${TENANT}.${DOMAIN} record — it overrides the *.${DOMAIN} CloudFront app-login frontend."
