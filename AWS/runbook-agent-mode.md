# Promethium Intelligent Edge — Model A′ (argocd-agent) customer-account install runbook

Fewest-commands install of IE into a **customer AWS account** where the spoke argocd-agent dials OUT
to the Promethium hub (no inbound, hub holds no customer credential). The workload is the
intelligent-edge OCI umbrella pulled from the Promethium ECR (734, us-west-1).

## Accounts / topology
- **Customer account** — the spoke: EKS (private cluster, internal ALB), the deploy role, operational
  roles, tfstate bucket, jumpbox. Example test account: `646322277713` (qa-sandbox, reused for spins).
- **Hub / control-plane** — `734236616923` (dev/qa) or `308611924187` (preview/prod): argocd-agent
  principal, SaaS/DNS roles, and **the ECR registry (ALWAYS 734, us-west-1)**.
- Agent principal DNS: `argocd-hub.<env>.promethium.ai:443` (task #13 rename from `argocdagent.<env>`; dev cut over).

## Cross-account boundary (why agent enroll is a 3-part split — by design, not a bug)
- The customer can reach only their own account + the hub agent endpoint. They **cannot** touch the hub cluster.
- So the mTLS cert is **issued by Promethium** against the hub and handed to the customer out-of-band
  (via the customer's own tfstate S3 bucket). `deploy.sh` Steps 8–9 assume one operator holds both
  accounts; a real customer split is: customer runs prereqs+deploy(+spoke agent install); Promethium
  issues the cert.

---

## 0. One-time per-customer-ACCOUNT setup (Promethium-side, 734 creds)
Needed **once per customer account** (NOT per tenant). For a **reused** account (e.g. 646 across spins)
these PERSIST and need no repeat. **Not yet automated — tracked as codify D (S4 `onboard-customer-account`).**

1. **734 ECR repo policies** — grant the customer account pull on the IE chart + image repos. Account-wildcard
   shape keyed on the refresher role name so re-spins/new tenants in the same account are covered:
   ```json
   { "Sid":"Pull<acct>SpokeRefreshers","Effect":"Allow",
     "Principal":{"AWS":"arn:aws:iam::<CUST_ACCT>:root"},
     "Action":["ecr:GetDownloadUrlForLayer","ecr:BatchGetImage","ecr:BatchCheckLayerAvailability"],
     "Condition":{"ArnLike":{"aws:PrincipalArn":"arn:aws:iam::<CUST_ACCT>:role/promethium-*-argocd-ecr-refresher"}}}
   ```
   Apply (merge-safe) to `charts/intelligent-edge` + all IE image repos (`services/ie/*`, `promethium/*`,
   `iac/docker/promethium-*`). See the merge-loop in the fcspin1 handoff §"Step B".
2. **734 saas-role trust** — add the customer's deploy role ARN to `promethium-terraform-saas-assume-role`
   trust `InternalDevAccountAccess` (jq-append, preserves existing). Referenced BY ARN → a same-name
   re-spin needs no repeat. (Retired entirely by **S2 hub-side DNS**.)

---

## 1. Install (customer-side, customer creds)
On a jumpbox inside the customer VPC (private cluster is only reachable in-VPC):
```bash
# 1a. roles + network + jumpbox + tfstate (idempotent; deploys the 4 local CFTs)
./AWS/scripts/prereqs.sh <company> <env> [--vpc-id … --subnet-ids …]
# 1b. cluster + infra + tenant registration + (agent enroll)
./AWS/scripts/deploy.sh  <company> <env>          # internal LB is the DEFAULT
```
`deploy.sh` stages: cluster → SG-ingress+kubeconfig → full apply (module.aws then everything) → tenant
registration → (Steps 8–9 agent enroll). Guards baked in: **Step 5b** aborts early if the operational
stack lacks `ArgocdEcrRefresherRoleArn`; **Step 9/9b** verify the OCI pull cred + auto-seed the image-pull
secret. Use `--skip-agent` to stop after infra.

## 2. Agent enroll — the 3-part split (if not running deploy.sh end-to-end)
- **Part A (Promethium, 734 hub creds):** `scripts/issue-and-export-agent-cert.sh --tenant <co> --env <env>
  --hub promethium-saas-backend --region us-east-1 --out /tmp/bundle-<co>` (needs `argocd-agentctl` v0.9.0;
  waits for the hub cert-manager secret `<co>-agent-client-tls`).
- **Part B (bridge):** `aws s3 cp --recursive /tmp/bundle-<co> s3://<tfstate-bucket>/_<co>-bundle/`.
- **Part C (customer jumpbox):** pull the bundle, then `AWS/agent/install-agent.sh --config <env-file>
  --bundle <dir> --context <spoke>` (env-file: TENANT, PRINCIPAL_ADDRESS=argocd-hub.<env>.promethium.ai,
  PORT=443, UMBRELLA_SOURCE=oci, ECR_REFRESHER_ROLE_ARN=…-argocd-ecr-refresher, ECR_REGION=us-west-1,
  ECR_REGISTRY=734236616923.dkr.ecr.us-west-1.amazonaws.com, CHART_NS=charts).

## 3. Validate (in-VPC — internal LB, NEVER a public browser)
```bash
kubectl -n intelligentedge get pods            # ~21 Running once the hub Application lands
```
Headless SHOW CATALOGS (browser can't reach the internal ALB): mint a Cognito IdToken for the app-login
client, then in-pod:
```bash
kubectl -n intelligentedge exec deploy/pm61trino-coordinator -- \
  curl -s http://localhost:8080/v1/statement -X POST -d 'SHOW CATALOGS' \
  -H "X-Forwarded-Proto: https" -H "Authorization: Bearer <IdToken>" -H "X-Trino-User: <email>"
# poll nextUri IN-POD, rewriting https://localhost → http://localhost each hop (forwarded-proto quirk)
```

## 4. Teardown (customer account; workflow can't run there → LOCAL from the jumpbox)
1. `kubectl -n argocd scale deploy/argocd-agent-agent --replicas=0` + strip ExternalSecret finalizers in intelligentedge.
2. `terraform destroy -refresh=false` (plain refresh hangs on the k8s/helm providers). SaaS/Cognito revert
   fires automatically via `tenant_revert_on_destroy`.
3. `terraform state rm` any helm/namespace "context deadline exceeded" hangers; the cluster delete nukes them.
4. GuardDuty-managed VPC endpoint + its SG block the network-stack VPC delete → `delete-vpc-endpoints`
   then `delete-security-group` first.
5. CFT delete order: roles/install → jumpbox → network (after the GuardDuty EP+SG) → tfstate-bootstrap LAST
   (empty the versioned bucket incl `_<co>-bundle/` — the tenant private key — first).
6. Stale S3-native state lock from an abandoned plan → `terraform force-unlock -force <id>`. Only ONE machine
   may write state (jumpbox vs Mac = 412 PreconditionFailed).

---

## 5. Troubleshooting — the known walls (all codified unless noted)
| Symptom | Cause | Fix / status |
|---|---|---|
| `CreateNodegroup … Failed to validate SLR … iam:GetRole` | deploy role GetRole scope excluded the `aws-service-role/*` SLR path | foundation.yaml `IAMGetRoleForEKS` includes `role/aws-service-role/*` — ✅ codified (H) |
| cert_manager `…saas-assume-role cannot be assumed` | deploy role had no sts:AssumeRole on the hub saas-role (+ 734 trust) | foundation.yaml `assume-hub-saas-role` (env-aware) — ✅ codified (J); 734 trust = §0.2 |
| autoscaler/LB/CSI pod CrashLoop on `AssumeRoleWithWebIdentity 403` | addons rolled out before iam_irsa_trust patched the role trust | `aws_eks_addons depends_on modify_iam_oidc_role_trust_policy` — ✅ codified (F). One-off: `rollout restart` the pod |
| ingress "Still creating" forever; LBC `no subnet with tag kubernetes.io/role/elb` | ingress rendered `internet-facing` on a private spoke | `loadbalancer_type` default = `internal` — ✅ codified (G) |
| OCI chart pull `basic credential not found` / `403 …no resource-based policy` | refresher role a ghost (BYO skips module.iam_oidc) / 734 repo policy missing | refresher = 9th operational role — ✅ codified (A); 734 grant = §0.1 |
| pods `ImagePullBackOff` on 734 images (`aws-ecr-docker-creds` missing) | image-pull secret not minted; postgres SA has none | deploy.sh Step 9b auto-seeds + patches ns default SA — ✅ codified (B-demo). Durable 6h refresh = B-durable (TODO) |
| trino `HIVE_METASTORE_ERROR` | trino Glue IRSA "ghost role" (wrong name in BYO) | operational role renamed to the umbrella-derived `promethium-<env>-<co>-trino-oidc-role` — ✅ codified (Opt-2) |
| trino-stream `/query` 401 client-credentials | marketplace client-creds secret empty | Marketplace-only path (CLIENT_CREDENTIALS_SETUP.md) — not needed for SHOW CATALOGS |

## 6. Codify + roadmap
Install-hardening codify (A–K): mostly landed — see the fcspin1 handoff + `[[fewest-commands-install-build]]`.
Remaining install-hardening: B-durable, C (umbrella global.imagePullSecrets + republish), D (S4 §0 automation), K.
Strategic roadmap after that: **S2 hub-side DNS** (retires §0.2 + J), task #13 hub DNS rename, tenant-file
TF-direct-commit, spoke GitHub-egress kill, argocd-agent 1.0, multi-env QA/Preview/Prod, Azure, registry-writer.
