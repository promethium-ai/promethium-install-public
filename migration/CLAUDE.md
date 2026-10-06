# Assisting a Promethium IE tenant migration (customer side)

You are helping a Promethium **customer** migrate their legacy Intelligent Edge (IE) tenant to the managed "Model A′" setup, running the SPOKE-side steps in the customer's own AWS account. The scripts in this directory and `../../docs/customer-migration-guide.md` are the **source of truth** — follow them in order; do not invent steps or values.

## Non-negotiables
- **Preserve everything.** Zero data loss and zero Trino-user loss. Record the baseline the backup step prints (catalogs / users / creds) and confirm the verify step matches it before calling the migration done.
- **Secrets never touch disk.** The scripts pipe secret material through `file:///dev/stdin` and copy base64 as-is. Do not "improve" this by writing secrets to files.
- **Confirm before every destructive or outward step** — the wipe, the Postgres PVC delete, any IAM write, any DNS change. State what will happen and get an explicit yes.

## What you run vs. what Promethium runs
Customer-account (spoke) steps — you / the operator run these here: `01-capture` → author the tenant request → `02-prereq` → `03-backup` → `04-rebind` → nodegroup floor → `05-wipe` → install the agent → `06-restore` → `08-ingress-dns` → `07-verify`.

**Promethium (hub) steps — you do NOT run these; request them and wait:**
- issuing the agent's client-certificate bundle (minted on Promethium's hub once your tenant request lands), and
- registering your cluster with the hub.

These are a handoff to Promethium, not something to run or fake locally. The guide says exactly where they slot in.

## Boundaries
- Hand any AWS / git / Route53 command you lack credentials for to the operator as an exact command and wait for the result — don't guess.
- Never delete the cluster's Terraform-managed IAM roles.
- If a step fails, report the real error and where you are in the sequence; the in-cluster `migration-backup` namespace lets a failed restore be retried.
