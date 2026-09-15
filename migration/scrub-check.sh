#!/usr/bin/env bash
# scrub-check.sh — internal-leakage gate for the migration/ bundle before it ships in this
# PUBLIC repo. Greps every file in this directory for Promethium-internal literals.
#
# The forbidden literals are NOT hardcoded in this script — hardcoding them here would
# publish, in this public repo, exactly what we are trying to keep out of it. They are
# supplied at scan time via env, which the release workflow fills from repo-level Actions
# variables:
#   SCRUB_ACCOUNTS  — space-separated internal AWS account IDs to forbid
#   SCRUB_HOSTS     — space-separated internal host/name substrings to forbid
# A local or customer copy with neither set has nothing account/host-specific to scan for
# and only checks the structural patterns below (it's effectively inert for them).
#
# Exit 0 = clean. Exit 1 = one or more hits, printed grouped by pattern. Nothing is
# auto-edited: a human fixes the flagged source file(s) by hand and re-runs.
#
# NOTE: lib.sh legitimately uses ${ACCOUNT}/${REGION}/${ECR_ACCOUNT} as shell template
# variables filled from migration.env — those are fine and never match (the patterns look
# for literal values, never the variable names).
#
# Used by: .github/workflows/migration-release.yml (fails the release build on any hit).
set -uo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SELF="$(basename "${BASH_SOURCE[0]}")"

# Build the check list from env. Each entry is "label|extended-regex-pattern".
CHECKS=()
for a in ${SCRUB_ACCOUNTS:-}; do
  CHECKS+=("internal account id|${a}")
done
if [ -n "${SCRUB_ACCOUNTS:-}" ]; then
  alt="$(printf '%s|' ${SCRUB_ACCOUNTS})"; alt="${alt%|}"
  CHECKS+=("ARN scoped to an internal account|arn:aws:[a-zA-Z0-9_-]*:[a-zA-Z0-9_-]*:(${alt}):")
fi
for h in ${SCRUB_HOSTS:-}; do
  CHECKS+=("internal host/name ${h}|${h}")
done
# Structural patterns that reveal no specific internal value — safe to keep literal:
CHECKS+=("execute-api gateway id|[a-z0-9]{10}\.execute-api")
CHECKS+=("kube-context host (.eksctl.io)|\.eksctl\.io")

if [ -z "${SCRUB_ACCOUNTS:-}${SCRUB_HOSTS:-}" ]; then
  echo "scrub-check: SCRUB_ACCOUNTS/SCRUB_HOSTS not set — checking only the structural"
  echo "            patterns. CI sets these from repo variables; a local run without them"
  echo "            is a PARTIAL check."
  echo
fi

FOUND=0
echo "scrub-check: scanning ${BUNDLE_DIR} (excluding ${SELF}) ..."
echo

for entry in "${CHECKS[@]}"; do
  label="${entry%%|*}"
  pattern="${entry#*|}"
  # -r recursive  -n line numbers  -H filenames  -I skip binaries  -E extended regex
  # --exclude keeps this script from matching its own pattern text.
  hits="$(grep -rnHIE --exclude="${SELF}" -- "${pattern}" "${BUNDLE_DIR}" 2>/dev/null || true)"
  if [ -n "${hits}" ]; then
    FOUND=1
    echo "FAIL [${label}]"
    echo "${hits}" | sed 's/^/    /'
    echo
  fi
done

if [ "${FOUND}" -eq 0 ]; then
  echo "PASS — no internal literals found under ${BUNDLE_DIR}"
  exit 0
fi

echo "scrub-check FAILED — internal literal(s) found above."
echo "Fix the source file(s) by hand (do not auto-sanitize) and re-run before releasing."
exit 1
