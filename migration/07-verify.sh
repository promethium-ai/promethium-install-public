#!/usr/bin/env bash
# Phase 7 — verify the migration preserved everything. Compares against the baseline you
# recorded from 03-backup.sh. All read-only.
. "$(cd "$(dirname "$0")" && pwd)/lib.sh"

COORD=$(kc -n "$NAMESPACE" get pods --no-headers 2>/dev/null | grep pm61trino-coordinator | awk '{print $1}' | head -1)

say "trino catalogs LOADED at startup (auth-free proof, from the coordinator log)"
LOADED=$(kc -n "$NAMESPACE" logs "$COORD" -c pm61trino-coordinator 2>/dev/null | grep -icE 'Added catalog')
echo "  loaded catalogs: ${LOADED}   (must equal your backup 'catalogs=' baseline)"
kc -n "$NAMESPACE" logs "$COORD" -c pm61trino-coordinator 2>/dev/null | grep -iE 'error|could not' | grep -iE 'catalog|connector' | head -3 || true

say "trino users in the running password.db"
USERS=$(kc -n "$NAMESPACE" exec "$COORD" -c pm61trino-coordinator -- sh -c 'grep -c : /etc/trino/password.db' 2>/dev/null)
echo "  users: ${USERS}   (must equal your backup 'users=' baseline)"

say "ExternalSecrets + app health"
kc -n "$NAMESPACE" get externalsecret -o json 2>/dev/null | python3 -c 'import json,sys; [print("  %-38s %s"%(e["metadata"]["name"], (e.get("status",{}).get("conditions") or [{}])[-1].get("reason","?"))) for e in json.load(sys.stdin).get("items",[])]'
kch -n argocd get application "${TENANT}-${ENV}-ie" -o jsonpath='  app: sync={.status.sync.status} health={.status.health.status}' 2>/dev/null; echo

say "postgres data (on the re-bound EBS volume)"
kc -n "$NAMESPACE" exec sts/promethium-postgres-postgresql -- bash -c 'PGPASSWORD=$POSTGRES_PASSWORD psql -U postgres -d promethiumdb -tAc "SELECT '\''users='\''||count(*) FROM users UNION ALL SELECT '\''dashboards='\''||count(*) FROM dashboards;"' 2>/dev/null | sed 's/^/  /'

say "external reachability (valid cert + serves)"
python3 -c "
import ssl,http.client,socket
try:
  c=http.client.HTTPSConnection('${TENANT}-trino.${DOMAIN}',443,timeout=15,context=ssl.create_default_context())
  c.request('GET','/ui/login.html'); r=c.getresponse()
  san=[v for k,v in (c.sock.getpeercert().get('subjectAltName') or ()) if k=='DNS']
  print('  https://${TENANT}-trino.${DOMAIN} -> HTTP',r.status,'| cert',san[:1],'VALID')
except ssl.SSLCertVerificationError as e: print('  cert verify FAILED:',e)
except (socket.timeout,socket.gaierror,OSError) as e: print('  not reachable yet:',type(e).__name__,'(DNS still propagating, or run 08-ingress-dns.sh)')
" 2>&1 | tail -2
echo
echo "PASS when: loaded catalogs == baseline, users == baseline, ExternalSecrets SecretSynced,"
echo "app Synced/Healthy, postgres rows >= baseline, external HTTPS 200. Then do the app-user login test."
