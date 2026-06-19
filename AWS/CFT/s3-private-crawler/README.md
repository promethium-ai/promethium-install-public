# Private S3 Access for Trino + Glue Crawlers (Same-Account and Cross-Account)

This guide configures Promethium to access S3 buckets privately — in the same AWS account as the IE deployment, or in a different account — using a gateway VPC endpoint and a Glue NETWORK connection.

The pattern guarantees:

1. S3 traffic stays on the AWS private network (no public internet hop).
2. Access is restricted by VPC, IAM principal, and bucket policy.
3. Promethium does not need elevated IAM permissions.

---

## Architecture

```
Trino (EKS pod, IRSA)  ─┐
                        ├──► VPC route table ──► S3 Gateway VPC Endpoint ──► Amazon S3
Glue Crawler (NETWORK)  ─┘
```

Same-account: the bucket is in the IE account.
Cross-account: the bucket lives in a *different* AWS account; the bucket policy in that account grants access to the IE account's role only when the request arrives via the IE account's VPCE.

---

## Prerequisites in the IE account

| Item | Notes |
|---|---|
| VPC ID | The VPC hosting the IE (EKS + Glue ENIs) |
| Private subnet IDs and AZs | At least one private subnet for the Glue connection's ENI |
| Route table IDs | The private route tables — the gateway endpoint will be attached to these |
| Security group | Must allow outbound 443 and have an inbound self-reference rule (Glue requires this) |
| IAM role for crawler runtime | Single role used by both Trino IRSA and Glue's crawler runtime (one role, two trust statements — see below) |

---

## Step 1 — Configure the crawler runtime IAM role

The role is assumed by:
- the Trino pod via IRSA (`sts:AssumeRoleWithWebIdentity`)
- Glue at crawler runtime (`sts:AssumeRole` for `glue.amazonaws.com`)

### Trust policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EksOidcIrsa",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<IE_ACCOUNT>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<OIDC_PROVIDER_ID>"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.<region>.amazonaws.com/id/<OIDC_PROVIDER_ID>:sub": "system:serviceaccount:intelligentedge:trino-sa"
        }
      }
    },
    {
      "Sid": "AllowGlueService",
      "Effect": "Allow",
      "Principal": { "Service": "glue.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

### Required permissions (in addition to the base Trino/Glue policy)

Attach an inline policy with the following statements. **Read the note on `ec2:CreateTags` below — it's the one that bites everyone.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowGetGlueConnection",
      "Effect": "Allow",
      "Action": ["glue:GetConnection", "glue:GetConnections"],
      "Resource": [
        "arn:aws:glue:<region>:<IE_ACCOUNT>:catalog",
        "arn:aws:glue:<region>:<IE_ACCOUNT>:connection/*"
      ]
    },
    {
      "Sid": "AllowPassRoleToGlue",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::<IE_ACCOUNT>:role/<crawler-role-name>",
      "Condition": { "StringEquals": { "iam:PassedToService": "glue.amazonaws.com" } }
    },
    {
      "Sid": "AllowGlueCrawlerLogging",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams",
        "logs:DescribeLogGroups"
      ],
      "Resource": [
        "arn:aws:logs:<region>:<IE_ACCOUNT>:log-group:/aws-glue/*",
        "arn:aws:logs:<region>:<IE_ACCOUNT>:log-group:/aws-glue/*:*",
        "arn:aws:logs:<region>:<IE_ACCOUNT>:log-group:/aws-glue/*:log-stream:*"
      ]
    },
    {
      "Sid": "AllowEc2DescribeForGlueNetworkConnection",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcAttribute",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowEc2EniLifecycleForGlue",
      "Effect": "Allow",
      "Action": ["ec2:CreateNetworkInterface", "ec2:DeleteNetworkInterface"],
      "Resource": "*"
    },
    {
      "Sid": "AllowEniTagging",
      "Effect": "Allow",
      "Action": ["ec2:CreateTags", "ec2:DeleteTags"],
      "Resource": "arn:aws:ec2:<region>:<IE_ACCOUNT>:network-interface/*"
    }
  ]
}
```

> **⚠ Critical: do NOT add a `Condition` block to `ec2:CreateTags`.** AWS docs sometimes recommend `"ec2:CreateAction": "CreateNetworkInterface"` as a security tightening, but Glue calls `CreateTags` as a **separate API call after the ENI is created** — the condition never matches and the tag fails. The crawler then surfaces the generic "Test connection failed for connection '...' and S3 Path '...'" with no useful diagnostics. (This is the single most common cause of unexplained Glue NETWORK-connection failures.)

---

## Step 2 — Deploy the VPC endpoint and Glue NETWORK connection

### Option A: CloudFormation

```bash
./AWS/utilities/install_vpc_endpoint.sh \
  --region us-east-1 \
  --stack-name promethium-s3-private-access \
  --template-file AWS/CFT/s3-private-crawler/promethium-vpc-s3-glue-connection.yaml \
  --parameters \
    VpcId=vpc-xxxxxxxxxxxxxxxxx \
    RouteTableIds=rtb-xxxxxxxxxxxxxxxxx \
    SubnetId=subnet-xxxxxxxxxxxxxxxxx \
    AvailabilityZone=us-east-1a \
    SecurityGroupIds=sg-xxxxxxxxxxxxxxxxx \
    AwsRegion=us-east-1 \
    AddEndpointPolicy=false \
    AllowedBucketArns='' \
    GlueConnectionName=promethium-glue-connection \
    GlueConnectionDescription="Glue network connection for Promethium crawler"
```

Capture the `S3GatewayEndpointId` from the outputs — you need it for the bucket policy.

### Option B: AWS Console

If the CFT can't run from your workstation, create the resources manually:

1. **VPC console → Endpoints → Create endpoint**
   - Service: `com.amazonaws.<region>.s3`, type **Gateway**
   - VPC: the IE VPC
   - Route tables: the private route table(s)
   - Policy: Full access (default)
2. **Glue console → Data Catalog → Connections → Create connection**
   - Connection type: **Network**
   - Name: `promethium-glue-connection`
   - VPC: the IE VPC
   - Subnet: a private subnet (note its AZ)
   - Security group: the one with self-reference + outbound 443

> **Pro tip — naming**: do not put spaces in the connection name. Spaces in Glue resource ARNs cause messy IAM resource conditions and audit confusion.

---

## Step 3 — S3 bucket policy

Apply this in the bucket-owning account (same as IE for same-account, or the data-owner account for cross-account):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowListBucketViaVpcEndpoint",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<IE_ACCOUNT>:role/<crawler-role-name>" },
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::<bucket>",
      "Condition": {
        "StringEquals": { "aws:SourceVpce": "<vpce-id-from-step-2>" }
      }
    },
    {
      "Sid": "AllowGetObjectViaVpcEndpoint",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<IE_ACCOUNT>:role/<crawler-role-name>" },
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": [
        "arn:aws:s3:::<bucket>",
        "arn:aws:s3:::<bucket>/*"
      ],
      "Condition": {
        "StringEquals": { "aws:SourceVpce": "<vpce-id-from-step-2>" }
      }
    }
  ]
}
```

Notes:

- **`s3:GetBucketLocation` is required** — Glue's S3 client looks up the bucket region before listing. Omitting this surfaces as the generic "Test connection failed."
- If you want to scope to a specific prefix, add `"StringLike": {"s3:prefix": ["<prefix>", "<prefix>/", "<prefix>/*"]}` to the ListBucket statement's `Condition`. Be aware Glue may issue a prefix-less ListBucket during pre-flight, so leaving the condition off (or including the literal prefix you'll crawl) is safest.
- For **cross-account** there is nothing extra to do beyond this policy — the VPCE ID is globally unique within AWS, so `aws:SourceVpce` works across account boundaries.

---

## Step 4 — Wire Promethium's `glue-crawler` deployment

```bash
kubectl set env deployment/glue-crawler -n intelligentedge \
  GLUE_USE_VPC_CONNECTION=true \
  GLUE_VPC_CONNECTION_NAME=promethium-glue-connection \
  GLUE_CRAWLER_ROLE=<crawler-role-name>

kubectl rollout status deployment/glue-crawler -n intelligentedge
```

> **⚠ Important**: `GLUE_CRAWLER_ROLE` must be the **role name** (no `arn:aws:iam:...:role/` prefix) of a role that actually exists in the account. Some Helm chart defaults reference a templated role name that may not be created — verify with `aws iam get-role --role-name <name>`.

---

## Step 5 — Validate

### Independent network/IAM probe (proves the plumbing works regardless of Glue):

```bash
kubectl run -n intelligentedge tmp-awscli --rm -it \
  --image=amazon/aws-cli:latest --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"trino-sa"}}' \
  -- s3 ls s3://<bucket>/<prefix>/ --region <region>
```

This list should succeed when bucket policy + IAM + VPCE routing are all correct. (The console's "Test Connection" feature is unreliable for NETWORK connections and routinely fails silently even when the path is fully functional — don't trust it as the sole validation.)

### Run a crawler

Trigger a crawl from the Promethium UI on the configured S3 source. Confirm:

```bash
CRAWLER=$(aws glue list-crawlers --region <region> --query 'CrawlerNames[0]' --output text)
aws glue get-crawler --region <region> --name "$CRAWLER" \
  --query 'Crawler.{State:State,LastCrawl:LastCrawl}' --output json
```

Want `Status: SUCCEEDED` and `TablesCrawled > 0`.

---

## Troubleshooting

### Generic "Test connection failed" — diagnose via CloudTrail

AWS Glue's connection-test path swallows real errors and reports the generic message regardless of root cause. The actual error is recorded in CloudTrail under the `GlueJobRunnerSession` identity. Query it directly:

```bash
aws cloudtrail lookup-events --region <region> \
  --start-time $(date -u -v-30M +%FT%TZ 2>/dev/null || date -u --date='30 minutes ago' +%FT%TZ) \
  --max-results 200 --output json \
  | jq '[.Events[] | .CloudTrailEvent | fromjson
         | select(.userIdentity.sessionContext.sessionIssuer.userName == "<crawler-role-name>"
                  and ((.userIdentity.arn // "") | contains("GlueJobRunnerSession")))
         | {time:.eventTime, event:.eventName, src:.eventSource,
            err:(.errorMessage // .errorCode // null),
            res:(.requestParameters.bucketName // .requestParameters.name // "")}]
       | sort_by(.time)'
```

Common errors and their fixes:

| Error | Fix |
|---|---|
| `glue:GetConnection on resource: arn:aws:glue:...:connection/<name>` | Add `glue:GetConnection` to the role's policy on `connection/*` |
| `iam:PassRole on resource: arn:aws:iam:...:role/<name>` | Add the `AllowPassRoleToGlue` statement to the role |
| `Service Principal: glue.amazonaws.com is not authorized to perform: ec2:Describe...` | Add the `AllowEc2DescribeForGlueNetworkConnection` statement |
| `ec2:CreateTags on resource: arn:aws:ec2:...:network-interface/...` | Add the unconditional `AllowEniTagging` statement (this is the recurring trap) |
| `logs:PutLogEvents on resource: arn:aws:logs:...:log-group:/aws-glue/...` | Add the `AllowGlueCrawlerLogging` statement |
| `Failed to call ec2:DescribeSubnets ... VPC Id not found for subnet ...` | The role lacks ENI describe perms; add `AllowEc2DescribeForGlueNetworkConnection` |
| S3 `AccessDenied` | Bucket policy missing the role principal, wrong VPCE ID, or missing `s3:GetBucketLocation` |

### "Test Connection failed" and CloudTrail is empty

The role's trust policy is missing `Service: glue.amazonaws.com` — Glue can't assume the role to start the test job, so no API calls are ever made. Update the trust policy (Step 1).

### Crawl hangs in STOPPING

Normal for NETWORK connections — ENI teardown adds 1–3 minutes after the actual crawl finishes. Wait until `State: READY`, then check `LastCrawl`.

---

## Tear down

```bash
./AWS/utilities/install_vpc_endpoint.sh \
  --region us-east-1 \
  --stack-name promethium-s3-private-access \
  --delete-stack
```

If you also created any resources by hand (console), delete them in the console.

---

## CloudFormation template

See `promethium-vpc-s3-glue-connection.yaml` in this folder. It provisions the gateway endpoint and the NETWORK connection.
