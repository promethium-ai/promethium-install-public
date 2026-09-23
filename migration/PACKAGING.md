# Packaging notes (internal — how this bundle gets here and how to release it)

This file documents how `migration/` in this **public** repo relates to its private
source, and how to cut a release. It is not customer-facing (unlike `README.md` in this
same directory), but it ships in the repo since it's harmless to a customer and useful to
whoever maintains the bundle next.

## v1: manually-synced copy (current state)

Today, `migration/` here is a **manually synced, curated copy** of the private
[`gitops-tenants-registry`](https://github.com/promethium-ai) repo's
`scripts/migration/` directory, which remains the actual source of truth and where the
scripts are authored, tested, and evolved. There is no automation keeping the two in
sync — a human copies files over by hand, on a schedule of "before each release."

### Exact curated file set (copy these, verbatim, and nothing else)

```
01-capture-identity.sh
02-prereq.sh
03-backup.sh
04-rebind.sh
05-wipe.sh
06-restore.sh
07-verify.sh
08-ingress-dns.sh
lib.sh
migration.env.example
CLAUDE.md
```

`README.md`, `scrub-check.sh`, and this file (`PACKAGING.md`) are **not** synced from the
private repo — they're authored directly here, for the public audience, and don't exist
in that form on the private side.

### Explicit exclude list (never copy these — they are operator-only or sensitive)

- `migration.*.env` (e.g. `migration.<tenant>.env`) — real tenant configs, one per
  migration ever run; these can carry account/cluster specifics for a real tenant.
- `migration.env` — whatever the private repo's working copy currently has filled in.
- `agent-install.env` — a working operator config, not a template.
- `preflight-tenants.sh` — operator batch-scheduling tool, not part of a single
  customer's migration.
- `track-source-health.sh` — operator monitoring tool.
- `nginx-fallback/` — operator-only fallback assets.
- the private repo's own `README.md` — written for a Promethium operator (references
  internal repos, internal runbooks, and the hub-side steps); this bundle's `README.md`
  is a from-scratch replacement for a customer audience.

### Doing the sync by hand

1. In a checkout of the private `gitops-tenants-registry` repo, `cd scripts/migration`.
2. Copy exactly the file set above into this repo's `migration/` directory, overwriting
   what's there. Do not hand-edit the copied files as part of the sync — if a script
   needs to change for the public bundle, that change belongs in the private source
   first, then gets copied over, so the two never silently diverge in content.
3. Run `./migration/scrub-check.sh` in **this** repo and resolve every hit before going
   further — see the "Patterns it flags" note in that script's header. Never sanitize by
   auto-editing; fix the actual line in the private source and re-sync.
4. Review the diff like any other change to a public repo (this is still just a working
   tree until it's committed and PR'd — nothing here is pushed automatically).
5. Commit, open a PR, get it reviewed. This repo is public — treat every line as
   published the moment it merges.

## Cutting a release

Once `migration/` on the target branch is the version you want to ship:

1. Go to this repo's **Actions** tab → **Migration bundle release** →
   **Run workflow** (or `gh workflow run migration-release.yml -f version=migration-vX.Y.Z`).
2. Supply a `version`, e.g. `migration-v1.0.0`.
3. The workflow (`.github/workflows/migration-release.yml`):
   - checks out the repo,
   - runs `migration/scrub-check.sh` and **fails the run** if it finds any internal
     literal (belt-and-suspenders on top of step 3 above — catches anything a human
     missed before merge),
   - tars up `migration/` into `migration-<version>.tar.gz`,
   - creates a GitHub Release tagged `<version>` on this repo, attaches the tarball, and
     auto-generates release notes from the commits since the last release.
4. Point customers at the release's tarball, not at a raw clone of this repo, so they get
   a pinned, scrub-checked snapshot.

## Future: automate the sync (not yet built)

v1's manual copy step is the weakest link — it relies on a human remembering to re-sync
and re-scrub before every release, and the two copies can drift silently in between. The
intended fix is to remove the manual copy entirely and make the **private repo the only
place these files are edited**:

- Add a build-time step (in the release workflow above, or a separate private-side
  workflow) that checks out `gitops-tenants-registry` at release time — via a
  short-lived, narrowly-scoped credential (e.g. a GitHub App installation token limited
  to read `scripts/migration/**`), not a long-lived PAT sitting in this public repo's
  secrets.
- Copy the same curated file set out of that checkout into `migration/` here
  automatically, run `scrub-check.sh` against the result, and only then proceed to
  tarball + release (or open a PR here for review instead of committing directly).
- This turns `gitops-tenants-registry/scripts/migration/` into the single source of
  truth; this repo's `migration/` becomes a generated artifact, not a hand-maintained
  copy, and the "did someone forget to re-sync" failure mode goes away.

Until that exists, the manual process above is what to follow.
