# Promethium IE customer-account install — wrapper scripts

Collapses the customer-account Intelligent-Edge (Model A′ / agent) install to
**two commands**, and teardown to **one**. Everything after the CloudFormation
prerequisites — Terraform apply, agent enrollment (hub cert issuance + spoke
agent install) — is one script.

```
AWS/scripts/
├── deploy.sh                  the install
├── destroy.sh                  the teardown
├── lib-tenant.sh                shared helpers (sourced by both; not run directly)
├── check-role-drift.py            CI check: CFT operational roles vs the legacy TF module
├── role-drift-baseline.json        golden fixture check-role-drift.py compares against
└── README.md                      this file
```

Both scripts are DRAFTS — read them before running anything against a real
account. Neither has been executed; see the assumptions list below for
everything that needs a second pair of eyes.

## The flow

### Greenfield (Promethium creates the VPC too)

```bash
# 1. CloudFormation prerequisites (once per company)
aws cloudformation deploy --region us-east-1 \
  --template-file AWS/CFT/network.yaml \
  --stack-name promethium-network-acme \
  --parameter-overrides Environment=dev CompanyName=acme \
  && aws cloudformation deploy --region us-east-1 \
  --template-file AWS/CFT/foundation.yaml \
  --stack-name promethium-foundation-acme \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides Environment=dev CompanyName=acme \
  && aws cloudformation deploy --region us-east-1 \
  --template-file AWS/CFT/jumpbox.yaml \
  --stack-name promethium-jumpbox-acme \
  --parameter-overrides Environment=dev \
    VpcId=$(aws cloudformation describe-stacks --stack-name promethium-network-acme --query "Stacks[0].Outputs[?OutputKey=='VpcId'].OutputValue" --output text) \
    PrivateSubnet1Id=$(aws cloudformation describe-stacks --stack-name promethium-network-acme --query "Stacks[0].Outputs[?OutputKey=='Subnet1Id'].OutputValue" --output text) \
    UseExistingInstanceProfile=$(aws cloudformation describe-stacks --stack-name promethium-foundation-acme --query "Stacks[0].Outputs[?OutputKey=='InstanceProfileName'].OutputValue" --output text)

# Connect to the jumpbox (SSM Session Manager), then from there:

# 2. everything else
./deploy.sh acme dev
```

### BYO VPC (customer provides the VPC)

```bash
# 1. CloudFormation prerequisites (no network.yaml — the VPC is the customer's)
aws cloudformation deploy --region us-east-1 \
  --template-file AWS/CFT/foundation.yaml \
  --stack-name promethium-foundation-acme \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides Environment=dev CompanyName=acme \
  && aws cloudformation deploy --region us-east-1 \
  --template-file AWS/CFT/jumpbox.yaml \
  --stack-name promethium-jumpbox-acme \
  --parameter-overrides Environment=dev VpcId=vpc-xxxx PrivateSubnet1Id=subnet-xxxx \
    UseExistingInstanceProfile=$(aws cloudformation describe-stacks --stack-name promethium-foundation-acme --query "Stacks[0].Outputs[?OutputKey=='InstanceProfileName'].OutputValue" --output text)

# 2. everything else
./deploy.sh acme dev --vpc-id vpc-xxxx --subnet-ids subnet-a,subnet-b,subnet-c
```

`deploy.sh` tells the two cases apart itself: pass `--vpc-id`/`--subnet-ids` for
BYO, or leave them off and it reads `promethium-network-<company>`'s outputs.
`jumpbox.yaml` is optional in both cases — it's only *where you run
`deploy.sh` from*, not a dependency `deploy.sh` checks for. What it does
require: a host with the customer account's credentials and (once the cluster
exists) private network reach to its API.

### Destroy (one command)

```bash
./destroy.sh acme dev
```

Add flags to match whatever non-default flags `deploy.sh` was given (`--vpc-id`
for a BYO install, `--iac-ref`, etc. — `destroy.sh` re-renders the exact same
`terraform.tfvars` so that `terraform destroy` evaluates the same
configuration it applied). See `--help` on either script for the full flag
list.

**Do not run `destroy.sh` from the `promethium-jumpbox-<company>` instance
being torn down** — one of its steps deletes that jumpbox's own CloudFormation
stack, which would kill the script's own host mid-teardown. Run it from a
separate host (a standing ops bastion, or your own machine if it can reach the
cluster's API).

## What `deploy.sh` actually does

1. Resolve the VPC (BYO flags, or the `promethium-network-<company>` stack).
2. Resolve the `promethium-foundation-<company>` stack's outputs (deploy role,
   instance profile, the 8 operational role ARNs, the tfstate bucket).
3. Clone the `<company>` branch of `promethium-internal-ie-aws` and pin its
   `main.tf` module ref.
4. Render `terraform.tfvars` + `register-enable.auto.tfvars` + a partial
   `backend.tf`, mapping every value to the outputs above (see
   `lib-tenant.sh`'s `render_terraform_tfvars` — the field list mirrors the
   proven `cust646` BYO-VPC/BYO-IAM tfvars).
5. **Gate**: confirms the Promethium-side cross-account grants (S4) are
   already applied — see "onboard-customer-account" under Assumptions below.
   This is a manual confirmation, not an automated step; read why there.
6. `terraform init` with `-backend-config` (S3 native locking, no DynamoDB).
7. `terraform apply`, staged the same way `phase1-customer-infra.sh` did: the
   EKS cluster alone first, then an `aws ec2 authorize-security-group-ingress`
   opening the cluster's API to this host, then the rest of the infra +
   in-cluster prerequisites + tenant registration. This is **not** collapsed
   into one `terraform apply -auto-approve` — the cluster is private, and
   nothing (including Terraform's own kubernetes/helm providers, used later in
   the same apply) can reach its API until that security-group rule exists.
8. Agent enrollment, hub side: calls `promethium-internal-ie-aws`'s own
   `scripts/issue-and-export-agent-cert.sh` (waits for the mTLS cert,
   registers the agent on the principal, exports the bundle), then relays the
   bundle to `s3://<TfStateBucket>/_<company>-bundle/` (`destroy.sh` cleans
   this up later).
9. Agent enrollment, spoke side: renders `agent-install.env` and calls this
   repo's own `AWS/agent/install-agent.sh` (auto-confirming its y/N prompt,
   since this script runs end-to-end non-interactively).

## What `destroy.sh` actually does

1. Scale `argocd-agent-agent` to 0 (stop it re-syncing while we tear down).
2. Strip finalizers on every `ExternalSecret` in `intelligentedge`.
3. Re-render the same `terraform.tfvars` deploy.sh used, then
   `terraform destroy -refresh=false -auto-approve`, retrying up to 3 times
   with `terraform state rm` on any `helm_release`/`kubernetes_namespace`
   addresses still stuck between attempts (the EKS cluster deletion nukes
   the in-cluster content out from under them).
4. Delete the hub `Application` (`<company>-<environment>-ie`) and the
   `cluster-<company>` secret.
5. Remove `tenants/<environment>/<company>.yaml` from the gitops registry
   (default path `/Users/antoniopm61data/pm61data/gitops-tenants-registry`,
   branch `feature/argo-runner-appsets`), commit, push.
6. Best-effort cleanup of a legacy cross-account pattern in 734236616923 (see
   Assumptions — in the current architecture this step is normally a no-op).
7. If (and only if) `promethium-network-<company>` exists — i.e. we created
   the VPC — delete its GuardDuty VPC endpoint, wait for the ENIs to clear,
   delete that security group, then delete the jumpbox and network stacks. A
   BYO VPC is never touched.
8. Delete the foundation stack, then empty (all versions + delete markers,
   including `_<company>-bundle/`) and delete the tfstate bucket.
9. Print zero-trace verification: IAM roles / S3 buckets / CFT stacks /
   Cognito user pools matching the company name — all should come back empty.

## Role-drift check (`check-role-drift.py`)

Promethium creates the same 8 EKS/OIDC "operational" roles (EBS CSI driver,
EFS CSI driver, LB controller, cluster autoscaler, EKS cluster role, EKS
worker-node role, PG backup, Glue/Trino) two different ways:

- **In-account installs**: Terraform (`module.iam_oidc` + `module.iam` in
  `iac-terraform-install-redesign/aws/infrastructure`) creates the roles
  directly.
- **Customer-account (BYO) installs**: `AWS/CFT/foundation.yaml` creates the
  same 8 roles up front (with a dummy OIDC provider URL), and Terraform later
  patches just their trust policies to the real cluster once it exists (see
  the deploy role's `iam-operational-role-trust-mgmt` inline policy and
  `module.modify_iam_oidc_role_trust_policy` + `locals.tf`'s `role_config`).

Nothing keeps these two definitions in sync automatically — a permission
added to one and not the other is invisible until it breaks in the field.
`check-role-drift.py` parses `foundation.yaml`, extracts each of the 8
roles' trust subjects, direct service principals, attached managed-policy
ARNs, and inline-policy statement action/resource sets, and diffs them
against a hand-curated golden fixture, `role-drift-baseline.json`, derived
from the Terraform source.

### Running it

```bash
python3 AWS/scripts/check-role-drift.py            # default paths
python3 AWS/scripts/check-role-drift.py --verbose  # print a line per passing role too
```

No dependencies beyond the Python 3 standard library — deliberately: pyyaml
is not installed in this environment/CI, and a full YAML parser is more than
this needs. `foundation.yaml`'s role blocks are extracted with a small
indentation-aware line scanner rather than a general YAML library (see the
module docstring in the script for why this is safe: the trust/policy
documents CloudFormation embeds as `Fn::Sub` block-scalar strings are already
valid JSON before `${...}` substitution happens, since those tokens sit
inside quoted strings, so they're handed straight to `json.loads()`). If a
future change to `foundation.yaml` needs real YAML semantics the hand-rolled
scanner can't handle, reach for `pyyaml` explicitly (add it to a
`requirements.txt` next to the script) rather than extending the scanner
indefinitely — but note that a generic YAML load still wouldn't resolve
CloudFormation intrinsics (`!Sub`, `!If`, `!Ref`, `!GetAtt`); this script's
targeted extraction of the JSON-embedded and native-YAML statement shapes
would still be needed on top.

Exits non-zero if any role has unallowlisted drift. Prints a per-role
PASS/DRIFT table; each DRIFT line names the specific field (trust subject,
service principal, managed policy ARN, or statement) and shows expected vs.
found.

### When to run it

- Locally, after editing `AWS/CFT/foundation.yaml`'s operational-role
  resources, before opening a PR.
- In CI, on every PR that touches `AWS/CFT/foundation.yaml` (wire it in as a
  required check — it's fast and dependency-free).
- After a change lands in `iac-terraform-install-redesign`'s
  `module.iam_oidc`, `modules/iam`, or `locals.tf`'s `role_config` — this is
  when the *baseline* goes stale, not the CFT, and the check will start
  reporting false drift (or worse, miss real drift) until the baseline is
  regenerated.

### Regenerating the baseline

`role-drift-baseline.json` is **not** parsed from Terraform automatically —
it's a hand-curated fixture. Regenerate it by hand whenever
`iac-terraform-install-redesign`'s `aws/infrastructure/modules/iam_oidc/*.tf`,
`modules/iam/*.tf`, or `locals.tf`'s `role_config` change:

1. Re-read the changed `.tf` file(s) for the affected role(s).
2. Update that role's `trust_subjects` / `service_principals` /
   `managed_policy_arns` / `statements` in the JSON to match, normalizing
   region/account and KMS-key resources the same way the script does (see
   `_meta.normalization_applied_by_script` in the JSON, and the ALLOWLIST
   section in the script's docstring) — i.e. write the *already-normalized*
   form (`arn:aws:kms:*:*:key/*`, `*` for region/account) directly into the
   baseline rather than the raw Terraform variable reference.
3. Update that role's `source` citation (file:line) so the next person can
   re-verify by reading, not archaeology.
4. Run the script and confirm it's back to all-PASS.

### Telling a real gap from a stale baseline

If the script reports DRIFT, it means one of two things — figure out which
before "fixing" anything:

- **A real gap in `foundation.yaml`**: someone edited the CFT's operational
  roles without carrying the same change into the CFT from the TF side (or
  vice versa going forward). Fix `foundation.yaml`.
- **A stale baseline**: `iac-terraform-install-redesign` changed and nobody
  regenerated `role-drift-baseline.json` (see above). Fix the baseline, not
  the CFT.

When in doubt, go re-read the cited TF source lines for that role and
compare by hand — the baseline's `source` citations exist exactly so this is
never a guessing game.

**Known, deliberately out-of-scope caveat**: the baseline's
`_meta.known_caveats` documents one confirmed inconsistency *inside* the
Terraform reference itself (locals.tf's BYO trust-patch `role_config` for
`PGBackupServiceRole` is missing a `rasa` namespace entry that
`var.cronjob_namespaces`' own default includes) — that's a bug in the
trust-*patch* path, not a CFT-vs-TF drift, so this script doesn't and can't
catch it. Worth fixing separately in `iac-terraform-install-redesign`.

### What is deliberately NOT compared

- **`RoleName`** — the CFT and TF name these roles completely differently
  (`promethium-${Environment}-${CompanyName}-<role>` vs. TF's own
  convention); roles are matched by logical identity (which CloudFormation
  resource / Terraform resource), never by name string.
- **IAM `Condition` blocks** — e.g. the EFS policy's
  `aws:RequestTag/cluster-name` value, or the autoscaler policy's
  `k8s.io/cluster-autoscaler/<name>` tag condition. These are
  cluster-name/tag-scoped values that legitimately differ per install; only
  trust subjects/principals and each statement's action + resource sets are
  compared.

## Assumptions / TODO

Things guessed or deliberately not automated — read before relying on this:

- **onboard-customer-account (S4) is a confirmation gate, not an automated
  apply.** Its `customers` map is shared, persistent, multi-tenant state in
  734236616923; applying it from `deploy.sh`'s own fresh per-company checkout
  with `-var="customers={ <this company only> }"` would **replace the whole
  map** and silently revoke every other onboarded customer's ECR pull grant
  (`onboard-customer-account/main.tf`: "an ECR repository policy is a SINGLE
  document per repo"). `deploy.sh` prints what must already be true and asks
  for confirmation instead of running it. Someone needs to actually add this
  company's entry to that module's real state (edit its committed
  `terraform.tfvars`, don't pass an ad-hoc `-var`) and fold its
  `registry_resource_policy_json` output into the CDK-managed registry RestApi
  policy (`onboard-registry-writer`) before `deploy.sh` reaches Step 7 — the
  tenant-registration SigV4 POST inside `terraform apply` 403s without both.
  This is the single biggest thing worth a second look.

- **`argocd-ecr-cred-refresher` role location — I followed the newer/current
  code over the older scratchpad script.** The given `phase2-promethium-hub.sh`
  hand-creates this role (and a matching OIDC provider) *in 734236616923* and
  `phase3-customer-agent.sh` points `ECR_REFRESHER_ROLE_ARN` at 734
  accordingly. But `promethium-iac-terraform`
  (`aws/infrastructure/modules/iam_oidc/argocd-ecr-refresher-oidc.tf`) creates
  this role as same-account IRSA **in the customer's own account**
  (`promethium-<env>-<company>-argocd-ecr-refresher`, gated on
  `deploy_mode=agent`), and `onboard-customer-account/main.tf` derives the
  exact same customer-account ARN and grants it cross-account ECR pull via
  repository policies — and `AWS/agent/install-agent.sh`'s own README/example
  agree ("IRSA role... in YOUR account"). I built `deploy.sh`/`destroy.sh`
  around the customer-account version (Step 3's `terraform apply`/`destroy`
  creates/removes it automatically) and kept `destroy.sh`'s 734 cleanup as a
  best-effort safety net for the older pattern, in case any tenant still has
  one. If the pinned `--iac-ref` predates `argocd-ecr-refresher-oidc.tf`, this
  is wrong and the 734 hand-rolled path is the real one — worth confirming
  which ref is actually intended for new installs.

- **`--iac-ref` default (`feat/ie-carveout-dev2`)** is the only ref I have
  direct proof of working (the `cust646` branch pins it). It's a feature
  branch, not a release tag — production self-serve installs probably want a
  proper tag once install-redesign lands on `dev`/main.

- **`--registry-api-url` default** derives the per-environment stage as
  `https://ol77z8v5j2.execute-api.us-east-1.amazonaws.com/<environment>/onboarding/registry/tenants`.
  Only the `/dev/` path is confirmed (from `register-enable.auto.tfvars`);
  `/qa/`, `/preview/`, `/prod/` are inferred from the same API Gateway stage
  pattern, not verified.

- **`--operator-email` default (`support@promethium.ai`)**: the source file
  hardcodes a personal address (`antonio@promethium.ai`) — clearly a
  per-install value, not a constant. Pass `--operator-email` explicitly per
  install.

- **`ghcr_token`** is a required Terraform variable (no default) that isn't
  referenced anywhere in `main.tf`'s module blocks at the pinned ref (grepped
  the whole module tree — no hits). Both scripts export
  `TF_VAR_ghcr_token=unused` to satisfy Terraform without prompting. If a
  future ref actually wires this up, that placeholder will need to become a
  real secret.

- **`jumpbox_sg_id` discovery** self-detects via EC2 instance metadata
  (IMDSv2) on the assumption `deploy.sh`/`destroy.sh` run ON the jumpbox (or
  an equivalent EC2 instance). If run from somewhere without IMDS (a laptop,
  most CI runners), pass `--jumpbox-sg-id` explicitly — otherwise Step 7b's
  cluster-API security-group rule is skipped with a warning, and the rest of
  that `terraform apply` will likely hang.

- **Dual credential context, not resolved for you.** Agent enrollment needs
  Promethium's hub-account credentials (734236616923 for dev/qa,
  308611924187 for preview/prod) *in addition to* the customer-account
  credentials used for everything else. `--hub-profile` (`deploy.sh`) and
  `--ecr-account-profile` (`destroy.sh`) point at a named AWS CLI profile for
  those specific sub-steps; if unset, the scripts assume the ambient
  credentials already cover both (e.g. an operator identity with
  cross-account access configured outside these scripts). In practice this
  means the end-to-end flow is Promethium-operator-run, not literally
  customer-self-service, for the agent-enrollment half.

- **`register-enable.auto.tfvars` is overwritten, not merged.** Terraform
  loads `*.auto.tfvars` after `terraform.tfvars`, so if the tenant-registration
  keys were set in both files the auto.tfvars value would silently win
  regardless of what `deploy.sh` rendered into `terraform.tfvars`. Both
  scripts render those 5 keys into `register-enable.auto.tfvars` only (see
  `lib-tenant.sh`), to avoid that trap — noting it since it's an easy thing to
  reintroduce by editing one render function without the other.

- **`install-agent.sh`'s y/N prompt is auto-confirmed** (`printf 'y\n' |
  ...`) rather than re-implementing `phase3-customer-agent.sh`'s raw `kubectl`
  commands inline. Chose the existing, better-tested, already-shipped
  installer in this repo (idempotent, dry-run support, bundle validation,
  context-safety check) over duplicating its logic — but it means `deploy.sh`
  depends on `install-agent.sh`'s interactive contract not changing shape.

- **`--gitops-repo-path` default** points at a specific local path
  (`/Users/antoniopm61data/pm61data/gitops-tenants-registry`) as instructed —
  this is one person's machine, not portable. A shared install host needs its
  own clone and its own default.

- **Network/foundation/jumpbox CFT stacks are read, not created, by
  `deploy.sh`.** The "2 install commands" are (1) the CloudFormation
  prerequisites — however many `aws cloudformation deploy` calls your topology
  needs (network+foundation[+jumpbox] for greenfield, foundation[+jumpbox] for
  BYO-VPC) — and (2) `deploy.sh` itself. `deploy.sh` errors clearly if
  `promethium-foundation-<company>` doesn't exist yet, and (for the
  non-BYO-VPC path) if `promethium-network-<company>` doesn't either.

- **`destroy.sh`'s bucket-emptying and Cognito lookups need `jq`** (not
  previously a listed dependency of the CFT-only install) — added to
  `require_tools` in `lib-tenant.sh` alongside `aws`, `git`, `terraform`,
  `kubectl`, `envsubst`, `openssl`, `curl`, `sed`.

- Neither script has been run. Static-checked with `bash -n` (both pass); no
  `shellcheck` or `cfn-lint` available in this environment to run further.
