# ✅ Promethium Intelligent Edge Installation (AWS)

Promethium utilizes a hybrid application architecture. 

Promethium Control Plane. The Promethium Control Plane is hosted and managed by Promethium. The scope of the control plane is; 

- Authentication
- Metadata
- Promethium’s agentic layer
- Application orchestration
- Application Telemetry

Promethium Data Plane (Intelligent Edge). The Promethium Data Plane is installed within the customers cloud provider as a private cluster. The data plane has connectivity to all data platforms. This ensures all data remains within the customers private network. Data exposed to an end user flows directly from the data plane to the users browser requiring all users to be part of the the customers private network. No data is exposed to the Promethium Control Plane. Customer is responsible for the management and monitoring of the Data Plane infrastructure. Promethium is responsible for the Application layer management and monitoring. The scope of the Data Plane is;

- Data Connections
- Metadata Discovery
- Federated Query
- Pipeline Orchestration
- Data APIs

This repository contains the artifacts your team needs to install the Promethium Intelligent Edge in your AWS environment. It is designed for security, consistency, and minimal operational overhead.

---

## 📋 1. Environment Prerequisites

| Item                    | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| AWS Account             | Identify the AWS account where the data plane will be deployed              |
| Region                  | Confirm AWS region for deployment (e.g., `us-east-1`)                       |
| Outbound Internet Access| Ensure EKS nodes have HTTPS access to Promethium Control Plane + image registry |
| DNS & Ingress           | Allow cloud-native ingress (ALB) creation and domain assignment         |

---

## 🔐 2. IAM Roles & Policies (Customer-Managed)

Create the following IAM roles and policies using Promethium-provided templates. Ensure roles are tagged (e.g., `Service=PromethiumIE`).

| Role Name             | Used By                    | Required Permissions                          | Notes                                  |
|-----------------------|-----------------------------|-----------------------------------------------|----------------------------------------|
| `PromethiumInstall`   | Install VM                  |                                               | Access required to install Promethium Intelligent Edge (IE)|
| `SnsSubscriberRole`   | SNS Receiver Pod (IRSA)     | `sns:Subscribe`, `sns:ReceiveMessage`         | Requires vendor-provided topic ARN     |
| `AlbControllerRole`   | Ingress Controller (IRSA)   | `elasticloadbalancing:*`, `ec2:Describe*`     | Required if ALB ingress is used        |
| `AppServiceRole`      | App Workloads (IRSA)        | App-specific (e.g., `s3:GetObject`)           | Only if app workloads access AWS APIs  |

---

## 📦 3. Cluster Inputs to Provide to [Vendor]

| Input                   | Example                         | Notes                                     |
|------------------------|----------------------------------|-------------------------------------------|
| EKS Cluster Name       | `acme-data-plane-cluster`        | Must match exactly                        |
| AWS Region             | `us-east-1`                      | Must match cluster region                 |
| IAM Role ARNs          | ARN of each IAM role above       | Required for pod IRSA configuration       |
| Customer Contact Email | `dataplatform@acme.com`          | For rollout and alerting                  |
| Public Ingress Domain  | `data.acme.com` *(optional)*     | Used if DNS routing is required           |

---

## 🧪 4. Post-Install Validation

| Task                                           | Owner         |
|------------------------------------------------|---------------|
| Confirm telemetry export to vendor             | [Vendor]      |
| Verify SNS message receipt from control plane  | [Vendor]      |
| Run smoke test workloads or queries            | Customer / [Vendor] |
| Validate GitOps rollback mechanism             | [Vendor]      |

---