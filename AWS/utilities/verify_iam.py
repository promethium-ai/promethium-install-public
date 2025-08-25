import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore
import yaml


@dataclass
class CheckResult:
    id: str
    status: str
    details: str
    meta: Dict[str, Any]


class Reporter:
    def __init__(self) -> None:
        self.checks: List[CheckResult] = []

    def add(self, id: str, status: str, details: str, meta: Optional[Dict[str, Any]] = None) -> None:
        self.checks.append(CheckResult(id=id, status=status, details=details, meta=meta or {}))

    def has_failures(self) -> bool:
        return any(c.status == "FAIL" for c in self.checks)

    def to_json(self) -> Dict[str, Any]:
        return {"checks": [asdict(c) for c in self.checks]}

    def print_text(self) -> None:
        for c in self.checks:
            print(f"[{c.status}] {c.id}: {c.details}")
        total = len(self.checks)
        fails = len([c for c in self.checks if c.status == "FAIL"])
        warns = len([c for c in self.checks if c.status == "WARN"])
        passes = total - fails - warns
        print("")
        print(f"Summary: {passes} passed, {warns} warnings, {fails} failed (total {total})")


def load_spec(path: str) -> Dict[str, Any]:
    with open(path, "r") as f:
        if path.endswith(".json"):
            return json.load(f)
        return yaml.safe_load(f)


def iam_client(region: str, profile: Optional[str]) -> Any:
    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)
    return session.client("iam")


def sts_client(region: str, profile: Optional[str]) -> Any:
    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)
    return session.client("sts")


def get_role_name_from_arn(arn_or_name: str) -> str:
    if arn_or_name.startswith("arn:"):
        return arn_or_name.split("/")[-1]
    return arn_or_name


def get_instance_profile_name(val: str) -> str:
    if val.startswith("arn:"):
        return val.split("/")[-1]
    return val


def fetch_role(iam: Any, arn_or_name: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    name = get_role_name_from_arn(arn_or_name)
    try:
        resp = iam.get_role(RoleName=name)
        return resp.get("Role"), None
    except botocore.exceptions.ClientError as e:
        return None, str(e)


def list_attached_policy_names(iam: Any, role_name: str) -> List[str]:
    names: List[str] = []
    marker = None
    while True:
        if marker:
            resp = iam.list_attached_role_policies(RoleName=role_name, Marker=marker)
        else:
            resp = iam.list_attached_role_policies(RoleName=role_name)
        for p in resp.get("AttachedPolicies", []):
            names.append(p.get("PolicyName", ""))
        marker = resp.get("Marker")
        if not resp.get("IsTruncated"):
            break
    return names
def list_attached_policies(iam: Any, role_name: str) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    marker = None
    while True:
        if marker:
            resp = iam.list_attached_role_policies(RoleName=role_name, Marker=marker)
        else:
            resp = iam.list_attached_role_policies(RoleName=role_name)
        for p in resp.get("AttachedPolicies", []):
            items.append({"PolicyName": p.get("PolicyName", ""), "PolicyArn": p.get("PolicyArn", "")})
        marker = resp.get("Marker")
        if not resp.get("IsTruncated"):
            break
    return items

def get_managed_policy_doc(iam: Any, policy_arn: str) -> Dict[str, Any]:
    try:
        pol = iam.get_policy(PolicyArn=policy_arn).get("Policy", {})
        ver_id = pol.get("DefaultVersionId")
        if not ver_id:
            return {}
        ver = iam.get_policy_version(PolicyArn=policy_arn, VersionId=ver_id).get("PolicyVersion", {})
        doc = ver.get("Document", {})
        return doc if isinstance(doc, dict) else json.loads(doc)
    except Exception:
        return {}



def list_inline_policy_docs(iam: Any, role_name: str) -> Dict[str, Dict[str, Any]]:
    docs: Dict[str, Dict[str, Any]] = {}
    marker = None
    while True:
        if marker:
            resp = iam.list_role_policies(RoleName=role_name, Marker=marker)
        else:
            resp = iam.list_role_policies(RoleName=role_name)
        for name in resp.get("PolicyNames", []):
            p = iam.get_role_policy(RoleName=role_name, PolicyName=name)
            docs[name] = p.get("PolicyDocument", {})
        marker = resp.get("Marker")
        if not resp.get("IsTruncated"):
            break
    return docs
MANAGE_ONLY_EXCLUDE = {
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PutRolePolicy",
    "iam:CreateInstanceProfile",
    "iam:AddRoleToInstanceProfile",
}

def filter_manage_only(actions: List[str]) -> List[str]:
    return [a for a in actions if a not in MANAGE_ONLY_EXCLUDE]



def instance_profile_exists_for_role(iam: Any, role_name: str, profile_name: Optional[str]) -> bool:
    target = get_instance_profile_name(profile_name) if profile_name else role_name
    try:
        iam.get_instance_profile(InstanceProfileName=target)
        return True
    except botocore.exceptions.ClientError:
        return False


def trust_doc_principals(trust_doc: Dict[str, Any]) -> Dict[str, List[str]]:
    services: List[str] = []
    aws_arns: List[str] = []
    federated: List[str] = []
    for st in trust_doc.get("Statement", []):
        princ = st.get("Principal", {})
        for k, col in [("Service", services), ("AWS", aws_arns), ("Federated", federated)]:
            v = princ.get(k)
            if isinstance(v, str):
                col.append(v)
            elif isinstance(v, list):
                col.extend(v)
    return {"Service": services, "AWS": aws_arns, "Federated": federated}


def ensure_contains(actual_list: List[str], expected_list: List[str]) -> Tuple[bool, List[str]]:
    missing = [e for e in expected_list if e not in actual_list]
    return len(missing) == 0, missing


def simulate_actions(iam: Any, role_arn: str, actions: List[str]) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    try:
        resp = iam.simulate_principal_policy(PolicySourceArn=role_arn, ActionNames=actions, ResourceArns=["*"])
    except botocore.exceptions.ClientError as e:
        return False, [], str(e)
    failures: List[Dict[str, Any]] = []
    for r in resp.get("EvaluationResults", []):
        decision = (r.get("EvalDecision") or "").lower()
        if decision != "allowed":
            failures.append({
                "action": r.get("EvalActionName"),
                "decision": r.get("EvalDecision"),
                "missing_context_values": r.get("MissingContextValues", []),
                "matched_statements": r.get("MatchedStatements", []),
                "permissions_boundary_decision_detail": r.get("PermissionsBoundaryDecisionDetail", {}),
                "organizations_decision_detail": r.get("OrganizationsDecisionDetail", {}),
                "resource_specific_results": r.get("ResourceSpecificResults", []),
            })
    return len(failures) == 0, failures, None


def normalize_template(s: str, vals: Dict[str, str]) -> str:
    out = s
    for k, v in vals.items():
        out = out.replace("{" + k + "}", v)
    return out


def validate_role_basic(iam: Any, reporter: Reporter, id_prefix: str, arn_or_name: Optional[str], expected_services: Optional[List[str]]) -> Optional[Dict[str, Any]]:
    if not arn_or_name:
        reporter.add(f"{id_prefix}.role_provided", "WARN", "Role ARN/Name not provided; skipping existence and trust checks", {})
        return None
    role, err = fetch_role(iam, arn_or_name)
    if not role:
        reporter.add(f"{id_prefix}.exists", "FAIL", "Role not found", {"input": arn_or_name, "error": err})
        return None
    reporter.add(f"{id_prefix}.exists", "PASS", "Role found", {"role_name": role.get("RoleName"), "arn": role.get("Arn")})
    if expected_services is not None:
        trust = role.get("AssumeRolePolicyDocument") or {}
        princs = trust_doc_principals(trust).get("Service", [])
        ok, missing = ensure_contains(princs, expected_services)
        if ok:
            reporter.add(f"{id_prefix}.trust", "PASS", "Trust policy service principals match", {"expected": expected_services, "actual": princs})
        else:
            reporter.add(f"{id_prefix}.trust", "FAIL", "Missing required trust service principals", {"missing": missing, "actual": princs})
    return role


def validate_attached_policies(iam: Any, reporter: Reporter, id_prefix: str, role_name: str, required_suffixes: List[str]) -> None:
    if not required_suffixes:
        return
    names = list_attached_policy_names(iam, role_name)
    missing: List[Dict[str, Any]] = []
    for suf in required_suffixes:
        found_name = next((n for n in names if n.endswith(suf)), None)
        if not found_name:
            missing.append({"required_suffix": suf})
    if missing:
        reporter.add(
            f"{id_prefix}.attached_policies",
            "FAIL",
            "Missing required attached managed policies by name suffix",
            {"required_suffixes": required_suffixes, "attached_policy_names": names, "missing": missing},
        )
    else:
        reporter.add(
            f"{id_prefix}.attached_policies",
            "PASS",
            "All required attached managed policies present",
            {"required_suffixes": required_suffixes, "attached_policy_names": names},
        )


def validate_inline_policy_contains(iam: Any, reporter: Reporter, id_prefix: str, role_name: str, required_inline: List[Dict[str, Any]]) -> None:
    if not required_inline:
        return
    inline_docs = list_inline_policy_docs(iam, role_name)
    inline_names = list(inline_docs.keys())
    attached_items = list_attached_policies(iam, role_name)
    attached_names = [p.get("PolicyName", "") for p in attached_items]
    for req in required_inline:
        name_pattern = req.get("name_contains")
        actions_req: set = set(req.get("actions", []))
        accept_managed = req.get("accept_managed", True)

        inline_match_name = None
        inline_doc = None
        for nm, doc in inline_docs.items():
            if name_pattern is None or (nm and name_pattern in nm):
                inline_match_name = nm
                inline_doc = doc
                break

        def evaluate_actions(policy_doc: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
            found: set = set()
            stmts = policy_doc.get("Statement", [])
            stmts_list = stmts if isinstance(stmts, list) else [stmts]
            for st in stmts_list:
                acts = st.get("Action")
                if not acts:
                    continue
                acts_list = [acts] if isinstance(acts, str) else acts
                for a in acts_list:
                    if isinstance(a, str) and a.endswith("*"):
                        prefix = a[:-1]
                        for ra in actions_req:
                            if isinstance(ra, str) and ra.startswith(prefix):
                                found.add(ra)
                    else:
                        if a in actions_req:
                            found.add(a)
                        else:
                            for ra in actions_req:
                                if isinstance(ra, str) and ra.endswith("*") and a.startswith(ra[:-1]):
                                    found.add(ra)
            missing_list = sorted(list(actions_req - found))
            present_list = sorted(list(found))
            return len(missing_list) == 0, missing_list, present_list

        if inline_match_name and inline_doc is not None:
            ok, missing, present = evaluate_actions(inline_doc)
            if ok:
                reporter.add(
                    f"{id_prefix}.inline.{inline_match_name}",
                    "PASS",
                    "Inline policy includes required actions",
                    {"policy_name": inline_match_name, "checked_actions": sorted(list(actions_req))},
                )
            else:
                reporter.add(
                    f"{id_prefix}.inline.{inline_match_name}",
                    "FAIL",
                    "Inline policy missing required actions",
                    {"policy_name": inline_match_name, "missing_actions": missing, "present_actions": present},
                )
            continue

        managed_match = None
        if accept_managed:
            for p in attached_items:
                pn = p.get("PolicyName") or ""
                if name_pattern is None or (pn and name_pattern in pn):
                    managed_match = p
                    break
        if managed_match:
            pol_doc = get_managed_policy_doc(iam, managed_match.get("PolicyArn", ""))
            ok, missing, present = evaluate_actions(pol_doc)
            if ok:
                reporter.add(
                    f"{id_prefix}.managed.{managed_match.get('PolicyName','policy')}",
                    "PASS",
                    "Managed policy includes required actions",
                    {"policy_name": managed_match.get("PolicyName"), "policy_arn": managed_match.get("PolicyArn"), "checked_actions": sorted(list(actions_req))},
                )
            else:
                reporter.add(
                    f"{id_prefix}.managed.{managed_match.get('PolicyName','policy')}",
                    "FAIL",
                    "Managed policy missing required actions",
                    {"policy_name": managed_match.get("PolicyName"), "policy_arn": managed_match.get("PolicyArn"), "missing_actions": missing, "present_actions": present},
                )
            continue

        reporter.add(
            f"{id_prefix}.inline.{name_pattern or 'policy'}",
            "FAIL",
            "Inline policy not found matching name pattern",
            {"looked_for": name_pattern, "available_inline_policies": inline_names, "attached_managed_policies": attached_names},
        )

def validate_policy_actions_by_suffixes(iam: Any, reporter: Reporter, id_prefix: str, role_name: str, suffixes: List[str], required_actions: List[str], forbidden_actions: Optional[List[str]] = None) -> None:
    suffixes = suffixes or []
    actions_req = set(required_actions or [])
    forb_set = set(forbidden_actions or [])
    if not suffixes or not actions_req:
        return
    inline_docs = list_inline_policy_docs(iam, role_name)
    inline_names = sorted(list(inline_docs.keys()))
    attached_items = list_attached_policies(iam, role_name)
    attached_names = sorted([p.get("PolicyName") or "" for p in attached_items])

    def evaluate_actions(policy_doc: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        found: set = set()
        stmts = policy_doc.get("Statement", [])
        stmts_list = stmts if isinstance(stmts, list) else [stmts]
        for st in stmts_list:
            acts = st.get("Action")
            if not acts:
                continue
            acts_list = [acts] if isinstance(acts, str) else acts
            for a in acts_list:
                if isinstance(a, str) and a.endswith("*"):
                    prefix = a[:-1]
                    for ra in actions_req:
                        if isinstance(ra, str) and ra.startswith(prefix):
                            found.add(ra)
                else:
                    if a in actions_req:
                        found.add(a)
                    else:
                        for ra in actions_req:
                            if isinstance(ra, str) and ra.endswith("*") and a.startswith(ra[:-1]):
                                found.add(ra)
        missing_list = sorted(list(actions_req - found))
        present_list = sorted(list(found))
        return len(missing_list) == 0, missing_list, present_list

    def collect_actions(policy_doc: Dict[str, Any]) -> set:
        collected: set = set()
        stmts = policy_doc.get("Statement", [])
        stmts_list = stmts if isinstance(stmts, list) else [stmts]
        for st in stmts_list:
            acts = st.get("Action")
            if not acts:
                continue
            acts_list = [acts] if isinstance(acts, str) else acts
            for a in acts_list:
                if isinstance(a, str):
                    collected.add(a)
        return collected

    def detect_forbidden(policy_doc: Dict[str, Any]) -> List[str]:
        if not forb_set:
            return []
        all_actions = collect_actions(policy_doc)
        present: set = set()
        for fa in forb_set:
            if not isinstance(fa, str):
                continue
            if fa in all_actions:
                present.add(fa)
                continue
            if fa.endswith("*"):
                pref = fa[:-1]
                if any(x.startswith(pref) for x in all_actions):
                    present.add(fa)
                continue
            for act in all_actions:
                if act.endswith("*"):
                    pref2 = act[:-1]
                    if fa.startswith(pref2):
                        present.add(fa)
        return sorted(list(present))

    for suf in suffixes:
        inline_match_name = None
        inline_doc = None
        for nm, doc in inline_docs.items():
            if suf in nm:
                inline_match_name = nm
                inline_doc = doc
                break
        if inline_match_name and inline_doc is not None:
            ok, missing, present = evaluate_actions(inline_doc)
            if ok:
                reporter.add(f"{id_prefix}.inline.{inline_match_name}", "PASS", "Inline policy includes required actions", {"policy_name": inline_match_name, "checked_actions": sorted(list(actions_req))})
            else:
                reporter.add(f"{id_prefix}.inline.{inline_match_name}", "FAIL", "Inline policy missing required actions", {"policy_name": inline_match_name, "missing_actions": missing, "present_actions": present})
            if forb_set:
                present_forb = detect_forbidden(inline_doc)
                if present_forb:
                    reporter.add(
                        f"{id_prefix}.forbidden.inline.{inline_match_name}",
                        "WARN",
                        "Policy includes forbidden actions",
                        {"policy_name": inline_match_name, "forbidden_present": present_forb, "forbidden_expected": sorted(list(forb_set)), "suffix": suf},
                    )
            continue

        managed_match = None
        for p in attached_items:
            pn = p.get("PolicyName") or ""
            if suf in pn:
                managed_match = p
                break
        if managed_match:
            pol_doc = get_managed_policy_doc(iam, managed_match.get("PolicyArn", ""))
            ok, missing, present = evaluate_actions(pol_doc)
            if ok:
                reporter.add(f"{id_prefix}.managed.{managed_match.get('PolicyName','policy')}", "PASS", "Managed policy includes required actions", {"policy_name": managed_match.get("PolicyName"), "policy_arn": managed_match.get("PolicyArn"), "checked_actions": sorted(list(actions_req))})
            else:
                reporter.add(f"{id_prefix}.managed.{managed_match.get('PolicyName','policy')}", "FAIL", "Managed policy missing required actions", {"policy_name": managed_match.get("PolicyName"), "policy_arn": managed_match.get("PolicyArn"), "missing_actions": missing, "present_actions": present})
            if forb_set:
                present_forb = detect_forbidden(pol_doc)
                if present_forb:
                    reporter.add(
                        f"{id_prefix}.forbidden.managed.{managed_match.get('PolicyName','policy')}",
                        "WARN",
                        "Policy includes forbidden actions",
                        {"policy_name": managed_match.get("PolicyName"), "policy_arn": managed_match.get("PolicyArn"), "forbidden_present": present_forb, "forbidden_expected": sorted(list(forb_set)), "suffix": suf},
                    )
            continue

        reporter.add(
            f"{id_prefix}.policy.{suf}",
            "FAIL",
            "Policy not found matching name pattern",
            {"looked_for": suf, "available_inline_policies": inline_names, "attached_managed_policies": attached_names},
        )

def validate_instance_profile(iam: Any, reporter: Reporter, id_prefix: str, role_name: str, require: bool, profile_name: Optional[str]) -> None:
    if not require:
        return
    ok = instance_profile_exists_for_role(iam, role_name, profile_name)
    if ok:
        reporter.add(f"{id_prefix}.instance_profile", "PASS", "Instance profile exists", {"role_name": role_name, "profile_name": profile_name or role_name})
    else:
        reporter.add(f"{id_prefix}.instance_profile", "FAIL", "Instance profile not found", {"role_name": role_name, "profile_name": profile_name or role_name})


def validate_federated_trust(reporter: Reporter, id_prefix: str, role: Dict[str, Any], expected_federated: bool, expected_oidc_arn_contains: Optional[str], expected_subject_contains: Optional[str]) -> None:
    trust = role.get("AssumeRolePolicyDocument") or {}
    princ = trust_doc_principals(trust)
    feds = princ.get("Federated", [])
    has_fed = len(feds) > 0
    if expected_federated and not has_fed:
        reporter.add(f"{id_prefix}.trust_federated", "FAIL", "Trust policy missing Federated principal", {"actual_principals": princ})
        return
    if not expected_federated:
        return
    ok = True
    details: Dict[str, Any] = {"federated": feds}
    if expected_oidc_arn_contains:
        ok = any(expected_oidc_arn_contains in x for x in feds)
        if not ok:
            reporter.add(f"{id_prefix}.trust_oidc_provider", "FAIL", "Federated principal does not reference expected OIDC provider", details)
            return
    if expected_subject_contains:
        cond_ok = False
        for st in trust.get("Statement", []):
            cond = st.get("Condition", {})
            for ctype in ["StringEquals", "StringLike"]:
                inner = cond.get(ctype, {})
                for k, v in inner.items():
                    vv = v if isinstance(v, list) else [v]
                    if expected_subject_contains in k or any(expected_subject_contains in s for s in vv if isinstance(s, str)):
                        cond_ok = True
        if not cond_ok:
            reporter.add(f"{id_prefix}.trust_oidc_subject", "WARN", "Trust policy does not include expected OIDC subject condition", {})
            return
    reporter.add(f"{id_prefix}.trust_federated", "PASS", "Federated trust validated", details)


def main() -> None:
    parser = argparse.ArgumentParser(prog="verify_iam", description="Validate required IAM roles and policies for Promethium IE")
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--profile", default=None)
    parser.add_argument("--spec", default=os.path.join(os.path.dirname(__file__), "..", "specs", "iam_requirements.yaml"))
    parser.add_argument("--output-json", default="verify_iam_report.json")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--skip-simulate", action="store_true")
    parser.add_argument("--simulate-installer", choices=["true", "false"], default=None)
    parser.add_argument("--oidc-issuer-url", default=None)
    parser.add_argument("--iam-role-create", choices=["true", "false"], required=True)
    parser.add_argument("--aws-iam-oidc-enabled", choices=["true", "false"], required=True)
    parser.add_argument("--jumpbox-enabled", choices=["true", "false"], required=True)
    parser.add_argument("--terraform-assume-role-arn", dest="terraform_role", default=None)
    parser.add_argument("--cluster-role-arn", default=None)
    parser.add_argument("--worker-role-arn", default=None)
    parser.add_argument("--jumpbox-instance-profile-name", dest="jumpbox_profile", default=None)
    parser.add_argument("--aws-lb-controller-role-arn", dest="lb_role", default=None)
    parser.add_argument("--aws-eks-autoscaler-role-arn", dest="autoscaler_role", default=None)
    parser.add_argument("--aws-efs-driver-role-arn", dest="efs_role", default=None)
    parser.add_argument("--aws-ebs-driver-role-arn", dest="ebs_role", default=None)
    parser.add_argument("--pgbackup-cronjob-role-arn", dest="pgbackup_role", default=None)
    parser.add_argument("--trino-oidc-role-arn", dest="trino_role", default=None)
    args = parser.parse_args()

    spec = load_spec(args.spec)
    vals = {"account_id": args.account_id, "region": args.region}
    reporter = Reporter()

    try:
        sts = sts_client(args.region, args.profile)
        ident = sts.get_caller_identity()
        reporter.add("auth.identity", "PASS", "Using AWS identity", {"account": ident.get("Account"), "arn": ident.get("Arn")})
    except Exception as e:
        reporter.add("auth.identity", "FAIL", "Unable to call sts:GetCallerIdentity", {"error": str(e)})
        print(json.dumps(reporter.to_json(), indent=2))
        reporter.print_text()
        sys.exit(2)

    iam = iam_client(args.region, args.profile)

    if args.terraform_role:
        role, err = fetch_role(iam, args.terraform_role)

        if role:
            reporter.add("installer.exists", "PASS", "Installer role found", {"role_name": role.get("RoleName"), "arn": role.get("Arn")})
            simulate_cfg = spec.get("installer", {}).get("simulate_actions", [])
            simulate_installer = None
            if args.simulate_installer is not None:
                simulate_installer = args.simulate_installer == "true"
            else:
                simulate_installer = (args.iam_role_create == "true")
            if simulate_cfg:
                if args.skip_simulate:
                    reporter.add(
                        "installer.simulate",
                        "WARN",
                        "Skipped permission simulation (--skip-simulate set)",
                        {"iam_role_create_mode": args.iam_role_create},
                    )
                elif simulate_installer:
                    used_actions = simulate_cfg
                    if args.iam_role_create == "false":
                        used_actions = filter_manage_only(simulate_cfg)
                    ok, failures, sim_err = simulate_actions(iam, role.get("Arn", ""), used_actions)
                    if sim_err:
                        reporter.add("installer.simulate", "WARN", "Simulation could not be performed", {"error": sim_err})
                    elif ok:
                        details = {"tested_actions": used_actions}
                        if args.iam_role_create == "false":
                            details["mode"] = "customer-managed manage-only"
                        reporter.add("installer.simulate", "PASS", "Installer has required permissions", details)
                    else:
                        msg = "Installer missing required permissions for specific actions"
                        details = {"failed": failures, "tested_actions": used_actions}
                        if args.iam_role_create == "false":
                            details["mode"] = "customer-managed manage-only"
                        reporter.add("installer.simulate", "FAIL", msg, details)
                else:
                    details = {"iam_role_create_mode": args.iam_role_create, "hint": "Enable with --simulate-installer true"}
                    msg = "Skipped permission simulation (customer-managed mode default)" if args.iam_role_create == "false" else "Skipped permission simulation (user disabled simulate-installer)"
                    reporter.add("installer.simulate", "WARN", msg, details)
        else:
            reporter.add("installer.exists", "FAIL", "Installer role not found", {"input": args.terraform_role, "error": err})
    else:
        reporter.add("installer.provided", "WARN", "Installer role not provided", {})

    iam_create = args.iam_role_create == "true"
    if not iam_create:
        if args.cluster_role_arn:
            role = validate_role_basic(iam, reporter, "eks.cluster", args.cluster_role_arn, spec.get("eks", {}).get("cluster", {}).get("trust_principals"))
            if role:
                validate_attached_policies(iam, reporter, "eks.cluster", role.get("RoleName", ""), spec.get("eks", {}).get("cluster", {}).get("required_attached_suffixes", []))
        else:
            reporter.add("eks.cluster.provided", "WARN", "Cluster role ARN not provided", {})
        if args.worker_role_arn:
            role = validate_role_basic(iam, reporter, "eks.worker", args.worker_role_arn, spec.get("eks", {}).get("worker", {}).get("trust_principals"))
            if role:
                worker_spec = spec.get("eks", {}).get("worker", {}) or {}
                if "actions" in worker_spec and "required_attached_suffixes" in worker_spec:
                    validate_policy_actions_by_suffixes(
                        iam,
                        reporter,
                        "eks.worker",
                        role.get("RoleName", ""),
                        worker_spec.get("required_attached_suffixes", []),
                        worker_spec.get("actions", []),
                        worker_spec.get("forbidden_actions", []),
                    )
                if "required_inline" in worker_spec:
                    validate_inline_policy_contains(iam, reporter, "eks.worker", role.get("RoleName", ""), worker_spec.get("required_inline", []))
        else:
            reporter.add("eks.worker.provided", "WARN", "Worker role ARN not provided", {})
    else:
        reporter.add("eks.mode", "PASS", "Terraform-managed IAM roles mode", {})

    if args.jumpbox_enabled == "true":
        if args.iam_role_create == "false" and args.jumpbox_profile:
            j_profile_name = args.jumpbox_profile
            rn = get_instance_profile_name(j_profile_name)
            ok = instance_profile_exists_for_role(iam, rn, j_profile_name)
            if ok:
                reporter.add("jumpbox.instance_profile", "PASS", "Jumpbox instance profile exists", {"name": rn})
            else:
                reporter.add("jumpbox.instance_profile", "FAIL", "Jumpbox instance profile not found", {"name": rn})
        else:
            reporter.add("jumpbox.mode", "PASS", "Terraform-managed or not required", {})

    oidc_enabled = args.aws_iam_oidc_enabled == "true"
    if not oidc_enabled:
        oidc = spec.get("oidc", {})
        prov_arn_contains = None
        if args.oidc_issuer_url:
            prov_arn_contains = f"oidc-provider/{args.oidc_issuer_url.strip().replace('https://','')}"
        for key, arn_val in [
            ("lbcontroller", args.lb_role),
            ("autoscaler", args.autoscaler_role),
            ("efs_csi_driver", args.efs_role),
            ("ebs_csi_driver", args.ebs_role),
            ("pgbackup", args.pgbackup_role),
            ("trino", args.trino_role),
        ]:
            if not arn_val:
                reporter.add(f"oidc.{key}.provided", "WARN", "Role ARN not provided", {})
                continue
            role = validate_role_basic(iam, reporter, f"oidc.{key}", arn_val, None)
            if not role:
                continue
            exp = oidc.get("roles", {}).get(key, {})
            validate_attached_policies(iam, reporter, f"oidc.{key}", role.get("RoleName", ""), exp.get("required_attached_suffixes", []))
            validate_inline_policy_contains(iam, reporter, f"oidc.{key}", role.get("RoleName", ""), exp.get("required_inline", []))
            validate_federated_trust(reporter, f"oidc.{key}", role, True, prov_arn_contains, exp.get("expected_subject_contains"))
    else:
        reporter.add("oidc.mode", "PASS", "Terraform-managed OIDC roles mode", {})

    with open(args.output_json, "w") as f:
        json.dump(reporter.to_json(), f, indent=2)
    reporter.print_text()
    if args.strict and reporter.has_failures():
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
