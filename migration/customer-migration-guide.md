# Promethium Intelligent Edge — Migration Guide

This guide covers migrating your Promethium Intelligent Edge deployment onto Promethium's
managed deployment platform. **Your data — catalogs, users, and database — is preserved
throughout, and everything stays in your own AWS account.**

---

## TL;DR

- **What:** move your Intelligent Edge deployment onto Promethium's managed platform. Your workloads keep running in **your** AWS account — only *deployment control* moves to Promethium.
- **Your data is preserved** — catalogs, users, and the database all survive. Nothing is copied out of your account.
- **Downtime:** one short maintenance window during cutover (plan up to ~1 hour; often less).
- **What we ask:** a machine that can reach your cluster, temporary cluster-admin (revoked after), and **one** narrowly-scoped AWS IAM role, your existing roles, including trino's data-access role, are reused as-is. No credentials or secrets ever leave your account.
- **Two ways to run it:** self-serve (you run it, we guide) or Promethium-assisted (you run it live over screen share, we guide in real time). Both preserve your data identically.
- **Reversible:** the migration is non-destructive; if the new setup can't stabilize, Promethium recovers forward, no data loss.

## How the migration works

The migration swaps *how* your deployment is managed without disturbing *where* it runs or *what data* it holds:

1. **Capture & prepare** (no downtime) - you read your current settings, create one scoped access role, and take a safe in-cluster backup of your catalog and user layer.
2. **Preserve your database** - your database's storage volume is kept and re-bound to the new deployment **in place**; the data is never copied out or recreated.
3. **Cutover** (the maintenance window) — the old application components are removed and the managed version is deployed in their place, then your catalog and user layer is restored.
4. **Connect** - your cluster opens a single **outbound-only** connection to Promethium's platform: nothing inbound is opened, Promethium holds no credential into your cluster, and you can sever it anytime (severing stops *future* managed deployments; your running application and data keep working).
5. **Verify** - you confirm your catalogs, users, and data are all present and the application is reachable.

Throughout your Promethium object and database storage are untouched - so there is **no re-crawl and no data rebuild**.

---

## How this migration can run

Two options

**A. Self-serve.** You run every step on your side; a Promethium engineer is on a call to guide
you and to perform the platform-side steps (in Promethium's own account).

**B. Promethium-assisted (live screen share).** You run every step yourself while sharing your
screen, and a Promethium engineer guides you in real time.

Both options are **customer-driven** - you run every command, your credentials and data never
leave your account, and the only artifact Promethium provides is the outbound connection
certificate for Step 7.

---

## What this asks of you (at a glance)

These fall to **you** on both paths — self-serve (async guidance) or Promethium-assisted (live
screen share). Promethium never runs them and never accesses your account.

| Ask | Detail | Notes |
|-----|--------|-------|
| A working machine | can reach the cluster API (a bastion/jump host if the API is private) | you likely already have one |
| **Cluster-admin** | on the IE cluster, for the migration | **time-boxed to the window; revoke after** |
| **AWS IAM scope** | create **one** scoped role (an image-puller for deployment images) — your existing roles, including trino's data-access role, are reused | a **scoped least-privilege policy is provided** (`migration-operator-policy.json`) — not standing admin; fits locked-down / SCP-restricted orgs |
| Run ~6 scripts | numbered, provided by Promethium | Steps 1–4 don't affect the running app; one step removes the old app |
| A maintenance window | app briefly offline during cutover | plan up to ~1 hour; often less — scales with data size |

None of this requires handing Promethium your credentials or secrets — see *Data & security*.

---

## Data & security

- Your **credentials, secrets, and data stay in your AWS account and cluster** the whole time —
  Promethium never receives them.
- Your application keeps running **in your own account**; only deployment *control* moves to
  Promethium's platform.
- The database backup (Step 4) is made **inside your cluster** — nothing is copied out.
- The platform connection (Step 7) is **outbound-only** from your cluster: nothing inbound is
  opened, Promethium holds no credential into your cluster, and you can sever it anytime.

---

## Who does what

| Phase | You (your account) | Promethium (its own account) |
|-------|--------------------|------------------------------|
| Pre-flight | capture, prerequisites, backup on your cluster | control-plane setup on Promethium's side |
| Cutover | rebind, remove old app, connect, restore | issues your connection certificate; deploys the app via the platform |
| Access needed | cluster-admin + one scoped AWS IAM role | **none** into your account (both paths) |

*(On the assisted path you still run the "You" column yourself — a Promethium engineer guides you
live over screen share.)*

---

## Downtime

Your Intelligent Edge application is briefly unavailable during the cutover (Steps 5–9). Plan a
maintenance window and do those steps together with your Promethium contact. *(Expected duration:
typically under ~1 hour for a modest tenant; larger datasets extend it — Promethium confirms your
window in advance.)*

Work top to bottom. Don't start the cutover (Step 5 onward) until Sections 1–2 and Steps 1–4 are
complete.

---

## 1. Access requirements

Confirm all of the following **before** you begin.

**a. A machine that can reach your cluster.**
If your cluster's API is private (not reachable from the internet), use a host inside the
cluster's network (for example, a bastion/jump host in the same VPC).
- Verify: `kubectl get ns` returns your namespaces (not a timeout).

**b. Administrator access to the cluster.**
- Verify: `kubectl auth can-i '*' '*' --all-namespaces` → expect `yes`.
- This is needed only for the migration and can be **time-boxed to the window and revoked after**.
- If `no`/error: ask your cluster owner to grant it, or contact Promethium.

**c. AWS permissions in your account**, in the region your cluster runs in — enough to:
- create and attach a policy to **one** narrowly-scoped IAM role,
- read your KMS key(s) and describe EKS, SQS, and KMS,
- adjust your node group's minimum size (raised before cutover so the new app has nodes to land on).

*(Keeping and re-attaching your database volume is done via `kubectl` and the EBS CSI driver — it
needs no AWS EC2 permission on your user.)*
- Verify: `aws sts get-caller-identity` shows your expected account.
- **What this creates - one small, scoped role in your account** (least-privilege, no standing admin):
  - an **image-puller**: lets the platform fetch the application container images.

  Everything else is reused as-is. Your existing database volume is kept and
  re-attached in place — never copied or recreated.
- **The permissions *you* need to run the migration are a ready-to-apply, scoped least-privilege
  policy** — `migration-operator-policy.json` in the package (substitute your
  account / region / env / tenant). You don't hand-craft these;
- **See the exact policy before you run Step 3:** the role's trust and permission documents are
  generated by the migration package's shared library — `lib.sh` (`gen_trust` = the trust policy,
  `gen_perms_refresher` = the image-puller's ECR scope), and applied by `02-prereq.sh`. Review it to
  confirm the least-privilege scope. *(The legacy path also uses `gen_perms_eso`, for the
  secrets-reader's Secrets Manager scope.)*

**d. Required tools** on that machine: `kubectl`, `aws`, `helm`, `jq`, `python3`. Install them on an
Amazon Linux 2023 bastion (adjust the package manager/URLs for a different OS):
```bash
sudo dnf install -y jq python3 unzip tar gzip
# AWS CLI v2
curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q -o /tmp/awscliv2.zip -d /tmp && sudo /tmp/aws/install --update
# kubectl (upstream stable)
curl -sSLo /tmp/kubectl "https://dl.k8s.io/release/$(curl -sSL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -m 0755 /tmp/kubectl /usr/local/bin/kubectl
# Helm 3
curl -sSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```
- Point `kubectl` at your cluster: `aws eks update-kubeconfig --name <your-cluster> --region <your-region>`
- Verify: `for t in kubectl aws helm jq python3; do command -v $t || echo "$t MISSING"; done`

**e. Cluster capacity for the window.**
The cutover removes the old app and lets the platform redeploy it — that needs worker nodes ready.
- Don't run the migration with the cluster scaled to zero. If your node group can scale to zero or
  sits at its minimum, **raise the minimum before Step 5** so the new deployment has somewhere to land.
- Verify: `kubectl get nodes` shows `Ready` nodes.

**If anything above is missing, stop and contact Promethium before starting.** Do not begin with
partial access.

---

## 2. Getting the migration script

Promethium delivers the scripts as a **pinned public GitHub Release** — a plain HTTPS download at a
version **tag** your contact names (no access token, no internal-repo clone). You only need this
package: **do not** clone Promethium's internal repositories or put Promethium credentials on your
machine.

On the machine from Section 1, download and extract it (the tag pins the version — HTTPS from the
public release page, so no separate checksum is needed):
```bash
TAG=<tag Promethium gives you>          # e.g. migration-v1.0.0
curl -fsSL -o migration.tar.gz \
  "https://github.com/promethium-ai/promethium-install-public/releases/download/${TAG}/migration.tar.gz"
tar -xzf migration.tar.gz && cd migration
ls        # numbered migration steps + a shared library file
```

---

## 3. Migration steps

Run these in order, from the machine in Section 1. **Steps 1–4 are safe and do not affect your
running system.** Steps 5–9 are the cutover (downtime) — do them with your Promethium contact.

**Step 1 — Prepare the configuration**
- Do: copy the provided template `migration.env.example` to `migration.env` and fill in your
  environment's values — tenant name, AWS account, region, namespace. Promethium provides the
  exact values (plus the Route53 zone id and container-registry account). Your `migration.env`
  also sets `EXTERNAL_SECRETS=false` and `CREATE_ECR_REFRESHER_ROLE=true` — the standard settings
  behind the one-role IAM ask in Section 1c; Promethium provides these the same way as the rest of
  the file.
- Why: the scripts read your specifics from this file.
- Confirm: the file exists and shows your values.

**Step 2 — Capture your current setup** — `./01-capture-identity.sh`
- Do: run it. It only reads information (no changes).
- Why: configures the new deployment to match your current one exactly — including the IAM role
  your existing trino connection already uses, which the platform reuses rather than recreating.
- Confirm: it prints real values (not "not found"). Keep the output.

**Step 3 — Install prerequisites** — `./02-prereq.sh`
- Do: run it. It creates **one** scoped access role **in your account** (for pulling deployment
  images) and carries your existing repository access credentials forward automatically. Your
  existing data-access role (trino, Glue/S3) is reused as-is — nothing else new is created.
- Why: the new deployment system needs this one role in place on your side; everything else about
  your account's IAM stays as it is today.
- Impact: none to your running application.
- Confirm: it ends with a `DONE.` line and prints the name of the access role it created.

**Step 4 — Back up** — `./03-backup.sh`
- Do: run it. It makes a backup **inside your cluster** — nothing leaves it.
- Why: safety, so your catalogs and users can be restored after cutover.
- Confirm: it prints a summary with your **catalog count** and **user count**.
  **Write these two numbers down** — you'll verify against them at the end.

> **→ Maintenance window begins. Your application is now briefly unavailable.**

**Step 5 — Protect and preserve the database** — `./04-rebind.sh`
- Do: run it. It removes the old database's pod and claim but **keeps the underlying storage
  volume**, re-attaching that same volume in place for the new deployment — the data is never
  copied or deleted.
- Why: your data is preserved — the same volume is reused, never copied or recreated.
- Confirm: the volume is kept and re-attached in place (the script reports success).

**Step 6 — Remove the old application** — `./05-wipe.sh`
- **This is the main destructive-looking step - but it is safe by design.** Your database,
  catalogs, stored data, settings, network access, and existing platform secrets are all **kept**;
  only the old application components are removed so the new deployment can install cleanly. Your
  database volume was kept and re-attached in place at Step 5, and the whole migration is
  recoverable (see §4).
- Do: run it (with your Promethium contact on the call).
- Confirm: the script reports what it kept and what it removed.

**Step 7 — Connect to Promethium's platform**
- **Promethium issues your cluster a connection certificate** (a "bundle"). Coordinate with your
  Promethium contact here.
- Do: run the one-line agent installer Promethium provides, pointing at that bundle.
- What it does: your cluster dials **outbound only** to Promethium's platform over TLS (443).
  **Nothing inbound is opened, and Promethium holds no credential into your cluster** - you can
  sever the connection at any time.
- Confirm: your Promethium contact confirms your cluster is connected.

**Step 8 — The new deployment installs automatically**
- Do: nothing — once connected, the application deploys and reconnects to your preserved database.
  This can take several minutes, and some components start before others.
- Confirm: `kubectl -n <your-namespace> get pods` shows the components starting and reaching
  `Running`. Promethium can also confirm progress on their side.
- Note: you may see the `sqs-listener` component cycle through `CrashLoopBackOff` during this step
  — expected, and it clears up once Step 9 restores its configuration.
- **External access / DNS is handled by Promethium** from its own control-plane DNS — there is no
  DNS step on your side. (Your application's records already point at your cluster's load balancer
  and are preserved through the migration.)

**Step 9 — Restore catalogs and users** — `./06-restore.sh`
- Do: run it. It restores from the Step 4 backup — your catalogs and users, plus the
  Promethium-managed configuration keys that Step 8's `sqs-listener` was waiting on (this is what
  clears that `CrashLoopBackOff`). It also confirms your platform secrets from Step 6 came through
  intact.
- Confirm: it reports the restored catalog and user counts.

> **→ Maintenance window ends.**

---

## 4. Final validation

Before considering the migration complete, confirm **all** of the following:

1. **All components running:** `kubectl -n <your-namespace> get pods` — everything `Running`.
2. **Catalogs match:** the catalog count equals the number you wrote down in Step 4.
3. **Users match:** the user count equals Step 4.
4. **Login works:** sign in to the application as usual.
5. **Data works:** run a query to confirm your data is accessible.

*(Run `./07-verify.sh` to check items 1–3 automatically — it confirms the loaded catalog and user
counts match your Step 4 baseline, your platform secrets are present, and the application is
Synced/Healthy.)*

If all five pass, the migration is complete. **If any fail, contact Promethium before making
further changes** — the migration is designed to be recoverable (your data and storage are intact, and your database volume was kept in place at Step 5), and Promethium can help restore the previous state.

**Changing a secret after migration.** Promethium-managed configuration keeps updating itself
automatically.

---

## 5. Optional — remove the leftover legacy storage

Older deployments kept the job-runner's files on an **EFS filesystem**; the new deployment uses
**EBS** and re-downloads the job-runner's drivers automatically, so the old EFS is no longer used.
Once **Final validation passes**, this leftover filesystem can be removed so you don't keep paying
for idle storage.

- This cleanup is **optional and not time-sensitive** — your migration is already complete, and your
  data, database, and catalogs are unaffected by it either way.
- It applies **only if your deployment used EFS**; a deployment that was always on EBS has nothing
  to clean.
- **Coordinate the removal with your Promethium contact** — they confirm the job-runner is fully on
  the new EBS storage first (so nothing still in use is touched), then guide removal of the old
  filesystem.

---

*Questions or problems at any step: contact your Promethium representative. Do not skip a
confirmation check or proceed past a failed step on your own.*
