# Legacy → Model A′ tenant migration

This bundle is what you run to migrate your existing Intelligent Edge (IE) tenant onto
Promethium's managed "Model A′" deployment (argocd-agent + the Promethium umbrella chart),
**preserving all of your data and all of your Trino users**. Nothing is rebuilt from
scratch: the umbrella is installed alongside your running tenant, then the scripts below
carry over the pieces the umbrella doesn't recreate on its own (your Trino catalogs, your
Trino users, and your Postgres data).

## Before you start

- This is a **guided** migration. Your Promethium contact provides the full step-by-step
  migration guide for your environment — read that first. This bundle is its executable
  companion: the scripts it tells you to run, in the order it tells you to run them.
- If you're using an AI assistant (e.g. Claude) to help run this, point it at
  [`CLAUDE.md`](./CLAUDE.md) first — it lays out the non-negotiables (no secret ever
  touches disk, confirm before every destructive step, preserve everything).
- Copy [`migration.env.example`](./migration.env.example) to `migration.env` and fill it
  in for your tenant; every script sources it via `lib.sh`.
- You'll need: your AWS credentials for the tenant's account, `kubectl`/`helm`/`jq`/`python3`
  on your workstation, and a kube context for your tenant's cluster.

## Run order

The scripts are numbered in the order you run them. A few steps in the middle are a
**handoff to Promethium** — you wait for those, you don't run them yourself.

| # | Script | What it does |
|---|--------|---------------|
| 1 | `01-capture-identity.sh` | Reads your tenant's identity and infra IDs (read-only) and prints what to send to Promethium. |
| — | *(handoff)* | Send Promethium the printed output. **Promethium** registers your tenant against the new setup and tells you when to continue. |
| 2 | `02-prereq.sh` | Installs the prerequisite stack (External Secrets Operator + IAM roles) and proves it can reach your secrets. |
| 3 | `03-backup.sh` | Takes a secure **in-cluster** backup of your Trino catalogs, credentials, and users. Nothing leaves the cluster or touches disk. Record the counts it prints — you'll compare against them at the end. |
| 4 | `04-rebind.sh` | Re-binds your Postgres data so the new deployment adopts your existing volume instead of creating an empty one. |
| 5 | `05-wipe.sh` | Removes the legacy workloads so the new umbrella can deploy cleanly. Refuses to run unless step 3's backup exists. Your data volumes, service accounts, and ingresses are kept. |
| — | *(handoff)* | **Promethium** issues your agent's certificate and registers your cluster. You then install the agent (see `AWS/agent/` in this repo) with the bundle Promethium delivers you. Wait for the new application to show Synced/Healthy before continuing. |
| 6 | `06-restore.sh` | Restores your Trino catalogs and users into the newly-deployed Trino from the step-3 backup. |
| 7 | `08-ingress-dns.sh` | Adds any missing ingress route and DNS record. Run this **before** step 8 — verification checks external reachability. |
| 8 | `07-verify.sh` | Read-only checks that everything matches your step-3 baseline: catalogs, users, Postgres data, and external HTTPS access. |

## If your tenant runs in your own AWS account

If Promethium is migrating a tenant that lives in **your** AWS account, a few things are handled for
you — no extra action on your side beyond the run order above:

- **Container-image pull credentials are managed for you.** During the agent handoff, Promethium sets
  up and keeps refreshed the credentials your cluster uses to pull the Promethium images, and wires
  them to the workloads that need them. You don't create or rotate anything for this.
- **Your data stays protected; the built-in backup job may change.** The migration keeps your database
  on your existing (retained) data volume and a snapshot is taken before any destructive step. The
  legacy hourly backup job that shipped to Promethium-owned storage is paused, since your account's
  policies won't allow it — Promethium coordinates any replacement backup with you separately.
- **Verify from inside your network.** If your tenant is reached over a **private/internal** load
  balancer, run the final login + `SHOW CATALOGS` check (and any query test) from **inside your own
  VPC/VPN**. From outside it, results pages can look empty or stuck even when the migration succeeded —
  that's network reachability, not a failure.

## If a step fails

Stop, capture the script's output, and contact your Promethium representative — don't
improvise past a failure. The in-cluster backup from step 3 stays in place, so a failed
restore can be safely retried once the issue is understood.

## Source of truth

The scripts and [`CLAUDE.md`](./CLAUDE.md) are the source of truth for exactly what each
phase does — read the comments at the top of each script before running it. This README
is intentionally thin; it won't be kept in lockstep with every script detail.
