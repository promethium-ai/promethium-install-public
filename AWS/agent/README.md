# Promethium Intelligent-Edge — Model A′ agent install (customer self-serve)

This installs the **argocd-agent** stack onto **your** EKS cluster so Promethium
can deploy and manage the Intelligent-Edge workload on it — **without holding any
credential to your cluster and without any inbound access to it.** The agent
opens a single **outbound** mTLS connection to the Promethium hub; everything
flows over that one channel.

> This is the security-hardened ("Model A′") install. Compared to the legacy
> install, Promethium never receives a kubeconfig or token for your cluster, and
> your cluster's API is never exposed to us.

## What you run vs. what Promethium runs

| Step | Who | Where |
|------|-----|-------|
| Provision the EKS cluster + IAM (incl. the ECR-pull IRSA role) | You | Your account (install Terraform) |
| Register your tenant (SigV4 API) → tenant file authored | You → Promethium API | — |
| Issue your agent's mTLS cert + register it on the hub | Promethium | Promethium hub |
| **Deliver you a cert bundle** (out-of-band) | Promethium | — |
| **Install the agent** (`install-agent.sh`) | **You** | **Your cluster** |
| Generate the Application + deploy the umbrella | Promethium | Promethium hub → your agent |

You never touch the Promethium hub; Promethium never touches your cluster's API.

## Prerequisites

1. Your EKS cluster is up, and you have a `kubectl` context for it.
2. The install Terraform created, in **your** account, the IRSA role that lets
   the cluster pull the Promethium umbrella chart from ECR
   (`ECR_REFRESHER_ROLE_ARN`).
3. Tools on your workstation: `kubectl`, `aws` CLI, `envsubst` (gettext), `base64`.
4. From Promethium (delivered once, out-of-band — e.g. a secure file transfer):
   a **cert bundle** directory with `tls.crt`, `tls.key`, `ca.crt`. This is your
   agent's mTLS identity; treat it as a secret. It is per-cluster and revocable.

## Install

```bash
cp agent-install.env.example agent-install.env
$EDITOR agent-install.env          # fill in TENANT, ECR_REFRESHER_ROLE_ARN, etc.

# dry-run first (no changes) to review what will be applied + confirm the context:
./install-agent.sh --config agent-install.env --bundle ./bundle --context <your-kube-context> --dry-run

# then install:
./install-agent.sh --config agent-install.env --bundle ./bundle --context <your-kube-context>
```

The script confirms the target cluster before applying, is idempotent (safe to
re-run), and restarts the agent at the end so it dials out.

## What gets installed (all in the `argocd` namespace)

- the `argocd-agent` agent + a managed Argo data plane (repo-server, redis,
  application-controller) — **no `argocd-server`**;
- your mTLS client cert + the hub CA (from the bundle);
- (oci mode) an IRSA-authed CronJob that mints a short-lived ECR token into the
  Argo repository secret every 6h — **no GitHub credential**.

## Verify

```bash
kubectl -n argocd get pods | grep argocd-agent      # agent Running
kubectl -n intelligentedge get pods                 # your workload, once deployed
```

## Security notes

- Only **outbound** `:${PRINCIPAL_PORT}` to the hub principal is required; you can
  firewall all inbound to the cluster.
- Promethium holds **no** credential to this cluster; the cluster's own
  ServiceAccount applies the workload.
- Your agent identity is the mTLS cert in the bundle. To offboard or rotate,
  Promethium revokes that cert — one certificate, one tenant.
