#!/usr/bin/env python3
#
# This script checks IAM permissions for Promethium IE installation.
# It simulates the policies for a given IAM role/user/group and checks if the required actions
# are allowed on the specified resources.

import argparse
import json
import os
import re
import subprocess
import sys
import time
from urllib import response
import boto3

base_dir = os.path.dirname(os.path.abspath(__file__))
debug = False

def debug_print(*args):
    if debug:
        print(*args)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Check IAM permissions for Promethium IE installation.\n\n"
                    "Example:\n"
                    "  python promethium_iam_check.py arn:aws:iam::734236616923:role/promethium-terraform-aws-provider-ie-role dev us-east-1 all",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("arn", help="IAM role/user/group ARN")
    parser.add_argument("region", help="AWS region")
    parser.add_argument("policy", help="'all', a file path, or '*' for all policies")
    parser.add_argument("--profile", help="AWS profile name (optional)")
    parser.add_argument("--group", action="store_true", help="Group wide action check (instead of granular)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    return parser.parse_args()

def validate_arn(arn):
    m = re.match(r"^arn:aws:iam::[0-9]{12}:(role|user|group)/", arn)
    if not m:
        print(f"Invalid ARN format: {arn}")
        sys.exit(1)
    return arn

def get_account_id(arn):
    m = re.match(r"^arn:aws:iam::[0-9]{12}:(role|user|group)/", arn)
    if not m:
            print(f"Invalid ARN format: {arn}")
            sys.exit(1)
    return m.group(1)

def validate_region(region):
    if not re.match(r"^[a-z]{2}-[a-z]+-[0-9]$", region):
        print(f"Invalid region: {region}")
        sys.exit(1)
    return region

def find_policy_files(policy):
    if policy in ("*", "all"):
        target_dir = os.path.join(base_dir, '../iam_policy_templates')
        pattern = r"^promethium-terraform-.*\.json$"
        skip_pattern = r"^promethium-terraform-install-role-.*\.json$"
        files = []
        for root, _, filenames in os.walk(target_dir):
            debug_print(f"Searching in directory: {root}")
            for filename in filenames:
                full_path = os.path.join(root, filename)
                if re.match(pattern, filename) and not re.match(skip_pattern, filename):
                    files.append(full_path)
        return files
    else:
        return [policy]

def load_json_file(path):
    with open(path) as f:
        try:
            return json.load(f)
        except Exception as e:
            print(f"Invalid JSON in policy file: {path}: {e}")
            sys.exit(2)

def run_aws_simulate(profile, region, role_arn, action, resource, context_entries=None):
    '''
    Call CLI: aws iam simulate-principal-policy
    '''
    cmd = [
        "aws", "iam", "simulate-principal-policy",
        "--profile", profile,
        "--region", region,
        "--policy-source-arn", role_arn,
        "--action-names", action,
        "--resource-arns", resource,
        "--output", "json"
    ]
    if context_entries:
        for entry in context_entries:
            cmd.extend(["--context-entries", entry])
    debug_print("Executing command:", ' '.join(cmd))

    retry = 2  # Number of retries for the command
    while True:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        retry -= 1
        if retry > 0:
            print(f"WARNING: failed aws iam command; {result.returncode} ; retrying: {' '.join(cmd)}")
            time.sleep(3)
        else:
            print(f"ERROR: failed aws iam command: {result.returncode}")
            sys.exit(5)

def run_aws_simulate_boto3(profile, region, role_arn, actions, resource, context_entries=None):
    '''
    Call SDK: simulate IAM policy using boto3.
    '''
    cmd = [
        "aws", "iam", "simulate-principal-policy",
        "--profile", profile if profile else '',
        "--region", region,
        "--policy-source-arn", role_arn,
        "--action-names", ''.join(actions),
        "--resource-arns", resource,
        "--output", "json"
    ]
    debug_print(f"SIMULATE COMMAND: {' '.join(cmd)}")

    print(f"Simulating policy for profile: {profile} in region: {region} for role: {role_arn} with actions: {actions} and resource: {resource}")

    session = boto3.Session() if profile is None else boto3.Session(profile_name=profile)
    client = session.client("iam", region_name=region)

    params = {
        "PolicySourceArn": role_arn,
        "ActionNames": actions,
        "ResourceArns": [resource]
    }
    if context_entries:
        # context_entries should be a list of dicts with keys: ContextKeyName, ContextKeyValues, ContextKeyType
        params["ContextEntries"] = context_entries


    attempts = 3  # Number of attempts for the API call
    while True:
        debug_print("Calling boto3 simulate_principal_policy with params:", params)
        attempts -= 1
        try:
            response = client.simulate_principal_policy(**params)
            code = response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0)
            if code >= 200 and code < 300: # success
                return response
            print(f"ERROR: boto3 simulate_principal_policy returned non-200 status: {code}")
            sys.exit(5)
        except Exception as e:
            if attempts > 0:
                print(f"WARNING: Rate limited. Retrying... {attempts} attempts left.")
                time.sleep((3 - attempts) * 2)  # Exponential backoff
                continue
            print(f"ERROR: Failed boto3 simulate_principal_policy: {e}")
            sys.exit(5)

def main():
    '''
    Main function to check IAM permissions for Promethium IE installation.
    '''
    args = parse_args()
    role_arn = validate_arn(args.arn)
    region = validate_region(args.region)
    policy = args.policy
    profile = args.profile
    group = args.group

    global debug
    debug = args.debug

    account_id = get_account_id(role_arn)
    print(f"Checking IAM permissions for role {role_arn}, account: {account_id}, region: {region}, policy: {policy}")
    print(f"Options: profile: {profile}, group: {group}, debug: {debug}")

    allowed = []
    denied = []
    tresults = []
    file_no = 0

    # for every policy file...
    files = find_policy_files(policy)
    debug_print(debug, f"Checking policy file(s): {files}")
    for file in files:
        file_no += 1
        tresults.append(f"File ({file_no}) {file}")
        print(f"Checking policy file: {os.path.relpath(file, base_dir)}")
        policy_json = load_json_file(file)
        statements = policy_json.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]
        statement_no = 0

        # for every statement in the file...
        for statement in statements:
            statement_no += 1
            sid = statement.get("Sid", "")
            tresults.append(f"  Statement ({statement_no}) - {sid}")
            print(f"Statement: {statement_no}: {json.dumps(statement)}")
            if statement.get("Effect") != "Allow":
                print(f"Invalid effect: {statement.get('Effect')} skipping")
                continue

            resources = statement.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            if not resources:
                print(f"No resources found in statement: {statement}")
                sys.exit(4)
            print(f"Resources: {resources}")
            resource_no = 0

            # Handle context-entries if needed (for conditions)
            context_entries = []
            if "Condition" in statement:
                cond = statement["Condition"]
                for op, cond_dict in cond.items():
                    for key, val in cond_dict.items():
                        ctype = "string"
                        if isinstance(val, list):
                            vals = val
                            if len(val) > 1:
                                ctype = "stringList"
                        else:
                            vals = [val]

                        context_entries.append({
                            "ContextKeyName": key,
                            "ContextKeyValues": vals,
                            "ContextKeyType": ctype
                        })

            # for every resource in the statement...
            for resource in resources:
                resource_no += 1
                resource = resource.replace("<region>", region).replace("<account_id>", account_id)
                tresults.append(f"    Resource ({resource_no}) - {resource}")
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if not actions:
                    print(f"No actions found in statement: {statement}")
                    sys.exit(3)

                if group:
                    # Run the AWS IAM policy simulation
                    response = run_aws_simulate_boto3(profile, region, role_arn, actions, resource, context_entries)
                    try:
                        jresults = response["EvaluationResults"][0]["EvalDecision"]
                    except Exception as e:
                        print(f"Error parsing AWS output: {e}\nOutput: {response}")
                        sys.exit(5)

                    debug_print(debug, jresults)
                    if jresults == "allowed":
                        debug_print(debug, f"Actions {actions} are allowed on {resource} by {role_arn}")
                        allowed.append(f"{actions} on {resource}")
                    else:
                        debug_print(debug, f"Actions {actions} is denied on {resource} by {role_arn}: {jresults}")
                        denied.append(f"{actions} on {resource}")
                    tresults.append(f"      Actions ({actions} - {jresults}")

                else:
                    # for every action in the statement...
                    print(f"Actions: {actions}")
                    action_no = 0
                    for action in actions:
                        action_no += 1
                        print(f"Checking action: {action_no} - {action}")
                        if not re.match(r"^[a-zA-Z0-9:_-]+$", action):
                            print(f"Invalid action: {action}")
                            sys.exit(2)

                        # Run the AWS IAM policy simulation
                        response = run_aws_simulate_boto3(profile, region, role_arn, [action], resource, context_entries)
                        try:
                            jresults = response["EvaluationResults"][0]["EvalDecision"]
                        except Exception as e:
                            print(f"Error parsing AWS output: {e}\nOutput: {response}")
                            sys.exit(5)

                        debug_print(debug, jresults)
                        if jresults == "allowed":
                            debug_print(debug, f"Action {action} is allowed on {resource} by {role_arn}")
                            allowed.append(f"{action} on {resource}")
                        else:
                            debug_print(debug, f"Action {action} is denied on {resource} by {role_arn}: {jresults}")
                            denied.append(f"{action} on {resource}")
                        tresults.append(f"      Action ({action_no}) - {action} - {jresults}")

    # Completed all files, statements, resources, and actions
    print("Results:")
    for t in tresults:
        print(t)
    print(f"Allowed actions ({len(allowed)}):")
    for a in allowed:
        print(f"  - {a}")
    print(f"Denied actions ({len(denied)}):")
    for a in denied:
        print(f"  - {a}")

    print(f"Summary: Tested {len(allowed) + len(denied)} actions, Allowed: {len(allowed)}, Denied: {len(denied)}")

if __name__ == "__main__":
    main()
