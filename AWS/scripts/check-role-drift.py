#!/usr/bin/env python3
"""
check-role-drift.py — fail CI if the BYO Foundation CFT's 8 operational IAM
roles diverge from what the legacy in-account Terraform module produces.

WHY
---
Promethium creates the same 8 EKS/OIDC "operational" roles two different
ways:

  1. In-account installs: Terraform (module.iam_oidc + module.iam in
     iac-terraform-install-redesign/aws/infrastructure) creates the roles
     directly.
  2. Customer-account (BYO) installs: AWS/CFT/foundation.yaml creates the
     roles up front (with a dummy OIDC provider), and Terraform later patches
     just their trust policies to the real cluster
     (module.modify_iam_oidc_role_trust_policy + locals.tf's role_config).

Nothing stops these two definitions from silently drifting apart — a
permission added to one and not the other is invisible until something
breaks in the field. This script parses foundation.yaml, extracts each of
the 8 roles' trust subjects / service principals / attached managed
policies / inline policy statements, and diffs them against a hand-curated
golden fixture (role-drift-baseline.json) derived from the Terraform source.

See AWS/scripts/README.md for when to run this and how to regenerate the
baseline.

DESIGN
------
No YAML library is used (pyyaml is not installed in CI and this avoids
adding a pip dependency — see README). foundation.yaml's role blocks are
extracted with a small indentation-aware line scanner (`get_block`,
`split_dash_items`, ...) that understands just enough of the YAML subset
CloudFormation templates actually use: block mappings, block sequences, and
literal block scalars (`|`). The trust/policy documents that are embedded as
`Fn::Sub: [| ... |, {vars}]` JSON strings are handled by lifting out the
literal block and feeding it straight to `json.loads()` — CloudFormation's
`${...}` substitution tokens sit inside quoted JSON strings, so the block is
already valid JSON before substitution happens.

The baseline is NOT derived at runtime from the .tf files — it's a static,
hand-curated fixture (see role-drift-baseline.json) that a human regenerates
by re-reading the Terraform source whenever it changes. Each role entry cites
its source file:line so that re-verification is a reading exercise, not an
archaeology one.

WHAT IS COMPARED
-----------------
Per role: OIDC trust subjects (the `:sub` values), direct service principals
(e.g. `glue.amazonaws.com`), the set of attached AWS-managed policy ARNs, and
each inline/attached policy statement's action set + resource set.
Conditions and RoleName are deliberately NOT compared (see README).

ALLOWLISTED (expected, normalized away, NOT reported as drift):
  1. Role NAME differences -- comparison is keyed by logical role, names are
     never read.
  2. KMS `Resource` -- CFT's `key/*` is treated as equivalent to any scoped
     TF key ARN/variable; both sides are collapsed to `key/*`.
  3. Region/account/partition placeholders (`${AWS::Region}` /
     `${AWS::AccountId}` vs Terraform's data-source equivalents) -- both
     sides are collapsed to `*`.
  4. Self-referential `iam:PassRole` -- GlueTrinoServiceRole passes ITSELF to
     glue.amazonaws.com; the resource ARN necessarily contains the role's own
     (allowlisted-per-#1) name, so it is collapsed to a `<SELF>` token. This
     is rule #1 applied to a Resource value instead of a RoleName property,
     not a new category of drift.

Everything else must match exactly.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_FOUNDATION = SCRIPT_DIR.parent / "CFT" / "foundation.yaml"
DEFAULT_BASELINE = SCRIPT_DIR / "role-drift-baseline.json"

# The 8 operational roles, in the order the task/README describes them.
ROLE_LOGICAL_IDS = [
    "EBSCSIDriverRole",
    "EFSCSIDriverRole",
    "LoadBalancerControllerRole",
    "ClusterAutoscalerRole",
    "EKSClusterRole",
    "EKSWorkerNodeRole",
    "PGBackupServiceRole",
    "GlueTrinoServiceRole",
]

# LoadBalancerControllerRole's inline permissions live on a SEPARATE
# `AWS::IAM::Policy` resource (`Roles: [!Ref LoadBalancerControllerRole]`),
# not in a `Policies:` block on the role itself. Every other role's
# statements are inline. This is the one hardcoded structural exception.
EXTRA_POLICY_RESOURCE = {
    "LoadBalancerControllerRole": "LoadBalancerControllerPolicy",
}


# ───────────────────────────── tiny YAML-subset scanner ─────────────────────

def read_lines(path: Path) -> list[str]:
    return path.read_text().splitlines()


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def find(lines: list[str], pred, start: int = 0):
    for i in range(start, len(lines)):
        if pred(lines[i]):
            return i
    return None


def get_block(lines: list[str], key_idx: int) -> list[str]:
    """lines[key_idx] is a 'Key:' (or 'Key: value') line. Return every
    subsequent line that is more indented than it (blank lines included),
    i.e. the nested block that is this key's value."""
    base = indent_of(lines[key_idx])
    out = []
    for line in lines[key_idx + 1:]:
        if line.strip() == "":
            out.append(line)
            continue
        if indent_of(line) <= base:
            break
        out.append(line)
    return out


def strip_tag_and_quotes(val: str) -> str:
    val = val.strip()
    m = re.match(r"^!\w+\s+(.*)$", val)
    if m:
        val = m.group(1).strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
        val = val[1:-1]
    return val


def split_dash_items(lines: list[str]) -> list[list[str]]:
    """Split a block sequence into per-item line groups. Each returned item's
    first line has its leading '- ' marker replaced with two spaces (not
    stripped down to the dash's own column) so that when the first line is
    itself a 'Key:' mapping key (e.g. '- Action: ...'), its indentation stays
    aligned with its sibling keys (Effect:/Resource:/Condition: etc. one
    level in) instead of sitting 2 columns shallower than them -- otherwise
    get_block() on that first key would treat its siblings as children."""
    marker_indent = None
    for l in lines:
        if l.strip():
            marker_indent = indent_of(l)
            break
    if marker_indent is None:
        return []
    items: list[list[str]] = []
    current: list[str] | None = None
    for line in lines:
        if not line.strip():
            if current is not None:
                current.append(line)
            continue
        if indent_of(line) == marker_indent and line.lstrip().startswith("- "):
            if current is not None:
                items.append(current)
            # Replace '- ' (2 chars) with '  ' (2 spaces) so a first-line
            # mapping key like 'Action:' lands at marker_indent + 2 -- the
            # same column its sibling keys (Effect:/Resource:/...) are
            # already at -- instead of marker_indent.
            prefix = line[:marker_indent] + "  "
            rest = line.lstrip()[2:]
            current = [prefix + rest]
        else:
            if current is not None:
                current.append(line)
    if current is not None:
        items.append(current)
    return items


def get_value_list(lines: list[str], key: str) -> list[str]:
    """Resolve a 'Key: ...' entry to a list of scalar strings, handling all
    three shapes foundation.yaml actually uses for Action/Resource/
    ManagedPolicyArns:
        Key: scalar                     -> [scalar]
        Key:\n  - a\n  - b               -> [a, b]
        Key: !If\n  - Cond\n  - T\n  - F -> [F]   (the no-override default;
                                                    same "compare by logical
                                                    role" reasoning as
                                                    RoleName overrides)
    """
    idx = find(lines, lambda l: re.match(rf"^\s*{re.escape(key)}\s*:", l))
    if idx is None:
        return []
    line = lines[idx]
    after = line.split(":", 1)[1].strip()
    if after == "!If":
        sub = get_block(lines, idx)
        branches = split_dash_items(sub)
        if len(branches) != 3:
            raise ValueError(f"unexpected !If shape for {key}: {branches}")
        false_branch = branches[-1][0].strip()
        return [strip_tag_and_quotes(false_branch)]
    if after != "":
        return [strip_tag_and_quotes(after)]
    sub = get_block(lines, idx)
    out = []
    for item in split_dash_items(sub):
        out.append(strip_tag_and_quotes(item[0].strip()))
    return out


# ───────────────────────────── trust extraction ─────────────────────────────

def extract_fn_sub_literal_json(lines: list[str]) -> dict:
    """`lines` is the value-block of an 'Fn::Sub:' key:
        - |
          { ...literal JSON, valid even with ${...} tokens inside strings... }
        - SomeVar: whatever
    Returns the parsed JSON dict of the literal block.
    """
    fnsub_idx = find(lines, lambda l: l.strip() == "Fn::Sub:")
    body = get_block(lines, fnsub_idx)
    items = split_dash_items(body)
    literal_item = items[0]
    first = literal_item[0].strip()
    if first != "|":
        raise ValueError(f"expected literal block scalar '|', got: {first!r}")
    json_lines = literal_item[1:]
    non_blank = [l for l in json_lines if l.strip()]
    if not non_blank:
        raise ValueError("empty Fn::Sub literal block")
    first_indent = min(indent_of(l) for l in non_blank)
    text = "\n".join(l[first_indent:] if len(l) > first_indent else l.strip()
                      for l in json_lines)
    return json.loads(text)


def trust_from_json_doc(doc: dict) -> tuple[set[str], set[str]]:
    subjects: set[str] = set()
    principals: set[str] = set()
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        if "Service" in principal:
            svc = principal["Service"]
            principals.update([svc] if isinstance(svc, str) else svc)
        if "Federated" in principal:
            cond = stmt.get("Condition", {}).get("StringEquals", {})
            for k, v in cond.items():
                if k.endswith(":sub"):
                    subjects.update([v] if isinstance(v, str) else v)
    return subjects, principals


def trust_from_plain_yaml(lines: list[str]) -> tuple[set[str], set[str]]:
    """Handles the two roles (EKSClusterRole, EKSWorkerNodeRole) whose
    AssumeRolePolicyDocument is native YAML with a single Service-principal
    statement and no OIDC/federation at all."""
    subjects: set[str] = set()
    principals: set[str] = set()
    for line in lines:
        m = re.match(r"\s*Service:\s*(\S+)\s*$", line)
        if m:
            principals.add(strip_tag_and_quotes(m.group(1)))
    return subjects, principals


def extract_trust(props: list[str]) -> tuple[set[str], set[str]]:
    idx = find(props, lambda l: l.strip() == "AssumeRolePolicyDocument:")
    if idx is None:
        raise ValueError("AssumeRolePolicyDocument not found")
    block = get_block(props, idx)
    if find(block, lambda l: l.strip() == "Fn::Sub:") is not None:
        doc = extract_fn_sub_literal_json(block)
        return trust_from_json_doc(doc)
    return trust_from_plain_yaml(block)


# ───────────────────────────── statement extraction ─────────────────────────

def parse_statement_item(item_lines: list[str]) -> dict:
    actions = get_value_list(item_lines, "Action")
    resources = get_value_list(item_lines, "Resource")
    return {"actions": actions, "resources": resources}


def parse_policy_document(lines: list[str]) -> list[dict]:
    """`lines` is a PolicyDocument's value-block. Handles both shapes used in
    foundation.yaml: native YAML `Statement:` list, and (ClusterAutoscalerPolicy
    only) an `Fn::Sub:`-embedded JSON document."""
    if find(lines, lambda l: l.strip() == "Fn::Sub:") is not None:
        doc = extract_fn_sub_literal_json(lines)
        out = []
        for stmt in doc.get("Statement", []):
            action = stmt.get("Action", [])
            resource = stmt.get("Resource", [])
            out.append({
                "actions": [action] if isinstance(action, str) else list(action),
                "resources": [resource] if isinstance(resource, str) else list(resource),
            })
        return out

    stmt_idx = find(lines, lambda l: l.strip() == "Statement:")
    if stmt_idx is None:
        raise ValueError("PolicyDocument has neither Fn::Sub: nor Statement:")
    block = get_block(lines, stmt_idx)
    return [parse_statement_item(item) for item in split_dash_items(block)]


# ───────────────────────────── resource-block extraction ────────────────────

TOP_LEVEL_KEY_RE = re.compile(r"^  [A-Za-z0-9]+:\s*$")


def extract_resource_block(lines: list[str], logical_id: str) -> list[str]:
    start = None
    for i, line in enumerate(lines):
        if line == f"  {logical_id}:":
            start = i
            break
    if start is None:
        raise ValueError(f"resource '{logical_id}' not found")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line and not line[0].isspace():
            end = j
            break
        if TOP_LEVEL_KEY_RE.match(line):
            end = j
            break
    # dedent by 2 (everything here was indented 2 under "Resources:")
    return [l[2:] if l.startswith("  ") else l for l in lines[start + 1:end]]


def get_properties(resource_block: list[str]) -> list[str]:
    idx = find(resource_block, lambda l: l.strip() == "Properties:")
    if idx is None:
        raise ValueError("Properties: not found in resource block")
    return get_block(resource_block, idx)


def extract_role(lines: list[str], logical_id: str) -> dict:
    block = extract_resource_block(lines, logical_id)
    props = get_properties(block)

    subjects, principals = extract_trust(props)
    managed_policy_arns = get_value_list(props, "ManagedPolicyArns")

    statements: list[dict] = []
    policies_idx = find(props, lambda l: l.strip() == "Policies:")
    if policies_idx is not None:
        pol_block = get_block(props, policies_idx)
        for item in split_dash_items(pol_block):
            pd_idx = find(item, lambda l: l.strip() == "PolicyDocument:")
            if pd_idx is None:
                continue
            statements.extend(parse_policy_document(get_block(item, pd_idx)))

    if logical_id in EXTRA_POLICY_RESOURCE:
        extra_block = extract_resource_block(lines, EXTRA_POLICY_RESOURCE[logical_id])
        extra_props = get_properties(extra_block)
        pd_idx = find(extra_props, lambda l: l.strip() == "PolicyDocument:")
        statements.extend(parse_policy_document(get_block(extra_props, pd_idx)))

    return {
        "trust_subjects": sorted(subjects),
        "service_principals": sorted(principals),
        "managed_policy_arns": sorted(managed_policy_arns),
        "statements": [canonicalize_statement(s) for s in statements],
    }


# ───────────────────────────── normalization (allowlist) ────────────────────

def normalize_resource(resource: str) -> str:
    r = resource.strip()
    # Rule 3: region/account/partition placeholders -> wildcards.
    r = r.replace("${AWS::Region}", "*").replace("${AWS::AccountId}", "*")
    r = r.replace("${AWS::Partition}", "aws")
    r = re.sub(r"\$\{data\.aws_region\.[^}]+\}", "*", r)
    r = re.sub(r"\$\{data\.aws_caller_identity\.[^}]+\}", "*", r)
    # Rule 2: any KMS key/<...> collapses to key/* (customer-CFT convention).
    r = re.sub(r"(arn:aws:kms:[^:]*:[^:]*:)key/.+$", r"\1key/*", r)
    # Rule 4: GlueTrinoServiceRole's self-referential PassRole target -- same
    # "compare by logical role" idea as rule 1, applied to a Resource value.
    r = re.sub(r"^(arn:aws:iam::[^:]*:role/).*-trino-oidc-role$", r"\1<SELF>", r)
    return r


def canonicalize_statement(stmt: dict) -> dict:
    return {
        "actions": sorted(set(a.strip() for a in stmt["actions"])),
        "resources": sorted(set(normalize_resource(r) for r in stmt["resources"])),
    }


def statement_signature(stmt: dict) -> tuple:
    return (tuple(stmt["actions"]), tuple(stmt["resources"]))


# ───────────────────────────── comparison / reporting ────────────────────────

class RoleDiff:
    def __init__(self, role: str):
        self.role = role
        self.problems: list[str] = []

    def add(self, msg: str):
        self.problems.append(msg)

    @property
    def ok(self) -> bool:
        return not self.problems


def compare_sets(diff: RoleDiff, field: str, expected: list[str], found: list[str]):
    exp, fnd = set(expected), set(found)
    missing = sorted(exp - fnd)
    extra = sorted(fnd - exp)
    if missing:
        diff.add(f"{field}: missing (in baseline, not in foundation.yaml): {missing}")
    if extra:
        diff.add(f"{field}: unexpected (in foundation.yaml, not in baseline): {extra}")


def compare_statements(diff: RoleDiff, expected: list[dict], found: list[dict]):
    exp_norm = [canonicalize_statement(s) for s in expected]
    exp_counter = Counter(statement_signature(s) for s in exp_norm)
    found_counter = Counter(statement_signature(s) for s in found)
    missing = exp_counter - found_counter
    extra = found_counter - exp_counter
    for sig, count in missing.items():
        actions, resources = sig
        diff.add(
            f"statement missing x{count}: actions={list(actions)} "
            f"resources={list(resources)}"
        )
    for sig, count in extra.items():
        actions, resources = sig
        diff.add(
            f"statement unexpected x{count}: actions={list(actions)} "
            f"resources={list(resources)}"
        )


def compare_role(role: str, expected: dict, found: dict) -> RoleDiff:
    diff = RoleDiff(role)
    compare_sets(diff, "trust_subjects", expected["trust_subjects"], found["trust_subjects"])
    compare_sets(diff, "service_principals", expected["service_principals"], found["service_principals"])
    compare_sets(diff, "managed_policy_arns", expected["managed_policy_arns"], found["managed_policy_arns"])
    compare_statements(diff, expected["statements"], found["statements"])
    return diff


# ───────────────────────────── main ──────────────────────────────────────────

def main(argv: list[str]) -> int:
    foundation_path = DEFAULT_FOUNDATION
    baseline_path = DEFAULT_BASELINE
    verbose = False
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--foundation":
            foundation_path = Path(args.pop(0))
        elif a == "--baseline":
            baseline_path = Path(args.pop(0))
        elif a in ("-v", "--verbose"):
            verbose = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            print(f"unknown argument: {a}", file=sys.stderr)
            return 2

    baseline = json.loads(baseline_path.read_text())
    lines = read_lines(foundation_path)

    results: list[RoleDiff] = []
    exit_code = 0

    for role in ROLE_LOGICAL_IDS:
        expected = baseline["roles"].get(role)
        if expected is None:
            diff = RoleDiff(role)
            diff.add(f"no baseline entry for role {role!r} in {baseline_path}")
            results.append(diff)
            exit_code = 1
            continue
        try:
            found = extract_role(lines, role)
        except Exception as exc:  # noqa: BLE001 - surfaced as a per-role failure
            diff = RoleDiff(role)
            diff.add(f"PARSE ERROR while extracting from foundation.yaml: {exc!r}")
            results.append(diff)
            exit_code = 1
            continue
        diff = compare_role(role, expected, found)
        results.append(diff)
        if not diff.ok:
            exit_code = 1

    name_width = max(len(r.role) for r in results)
    print(f"{'ROLE':<{name_width}}  STATUS")
    print(f"{'-' * name_width}  ------")
    for diff in results:
        status = "PASS" if diff.ok else "DRIFT"
        print(f"{diff.role:<{name_width}}  {status}")
        if not diff.ok:
            for problem in diff.problems:
                print(f"    - {problem}")
        elif verbose:
            print("    (trust subjects, service principals, managed policy "
                  "ARNs, and statement action/resource sets all match the "
                  "baseline)")

    print()
    if exit_code == 0:
        print(f"OK: all {len(results)} operational roles match "
              f"{baseline_path.name}.")
    else:
        drifted = [d.role for d in results if not d.ok]
        print(f"DRIFT DETECTED in {len(drifted)}/{len(results)} role(s): "
              f"{', '.join(drifted)}")
        print("See AWS/scripts/README.md ('Role-drift check') for how to "
              "tell a real gap in foundation.yaml from a stale baseline.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
