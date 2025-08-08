Creating Readme file

# Promethium IAM Check
The [promethium_iam_check.py](./utilities/promethium_iam_check.py) utility checks IAM permissions required for Promethium IE installation. It simulates the policies for a given IAM role, user, or group and checks if the required actions are allowed on the specified resources.

```
$ python ./utilities/promethium_iam_check.py <arn> <region> <policy> [--granular] [--debug]
    <arn> is the AWS IAM role, user, or group
    <region> is the AWS region
    <policy> is the specific IAM policy file (in json format) to test, or enter 'all' to test all policies in this repo.
    --policy : a specific IAM policy file (in json format) to check instead of all policies in repo
    --granular : option to runs the policy checker per action (instead of per group)
    --debug : enables debug output
```

Example: run it with iam role in us-east-1, on the eks json policy file in this repo, with granular (per table) output:

```
python ./utilities/promethium_iam_check.py \
  arn:aws:iam::734236616923:role/promethium-terraform-aws-provider-ie-role \
  us-east-1 \
  ./policies_dir/promethium-terraform-eks-policy.json \
  --granular
```

Example: run it with iam role in us-east-1, on every json policy file in this repo:

```
python ./utilities/promethium_iam_check.py \
  arn:aws:iam::734236616923:role/promethium-terraform-aws-provider-ie-role \
  us-east-1 \
  all
```