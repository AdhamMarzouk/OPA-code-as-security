# Security-as-Code: Policy as Code with OPA + Terraform

> **Shift security left.** Enforce cloud infrastructure compliance *before* deployment using Open Policy Agent and Terraform plan analysis.

[![OPA Security Check](https://github.com/AdhamMarzouk/OPA-code-as-security/actions/workflows/security-check.yml/badge.svg)](https://github.com/AdhamMarzouk/OPA-code-as-security/actions/workflows/security-check.yml)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Security Policies Enforced](#security-policies-enforced)
4. [Repository Structure](#repository-structure)
5. [Prerequisites](#prerequisites)
6. [Setup Instructions](#setup-instructions)
7. [CI/CD Pipeline](#cicd-pipeline)
8. [Demo Walkthrough](#demo-walkthrough)
9. [Sample Compliance Report](#sample-compliance-report)
10. [References](#references)

---

## Overview

This project demonstrates a **Security-as-Code** pipeline that automatically validates AWS infrastructure (defined in Terraform) against security policies written in **Rego** (OPA's policy language) — before any resource is ever deployed.

**Key properties:**
- ✅ Zero AWS cost — `terraform plan` only, never `terraform apply`
- ✅ Automated enforcement on every push via GitHub Actions
- ✅ Clear, human-readable compliance reports
- ✅ 4 security policies covering S3, IAM, and networking

---

## Architecture

```
Developer pushes code
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│                   GitHub Actions CI Pipeline                │
│                                                             │
│  1. terraform init                                          │
│  2. terraform plan -out=tfplan   (reads plan intent)        │
│  3. terraform show -json tfplan  (exports plan as JSON)     │
│          │                                                  │
│          ▼                                                  │
│  4. python scripts/validate.py --plan plan.json             │
│          │                                                  │
│          ▼                                                  │
│  5. opa eval -d policies/ -i plan.json                      │
│      "data.terraform.security.deny"                         │
│          │                                                  │
│    ┌─────┴─────┐                                            │
│    │           │                                            │
│  Empty       Non-empty                                      │
│    │           │                                            │
│    ▼           ▼                                            │
│  PASS ✅    FAIL ❌ → Violation details in log + report     │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Policies Enforced

| # | Policy File | Resource Checked | What It Enforces |
|---|-------------|-----------------|------------------|
| 1 | `s3_encryption.rego` | `aws_s3_bucket` | Server-side encryption (AES256 or aws:kms) must be configured |
| 2 | `ssh_access.rego` | `aws_security_group` | Inbound SSH (TCP port 22) must not be open to `0.0.0.0/0` |
| 3 | `iam_wildcard.rego` | `aws_iam_policy` | Action field must not contain `"*"` in any Statement |
| 4 | `s3_public_access.rego` | `aws_s3_bucket_public_access_block` | All four public access block flags must be `true` |

All policies share the `package terraform.security` namespace and define a `deny` set. A non-empty `deny` set means violations were found.

---

## Repository Structure

```
OPA-code-as-security/
│
├── .github/
│   └── workflows/
│       └── security-check.yml        # CI/CD pipeline definition
│
├── terraform/
│   ├── providers.tf                  # AWS provider + Terraform version constraints
│   ├── main.tf                       # Compliant resources (all policies pass)
│   ├── non_compliant.tf              # Intentionally insecure resources (for demo)
│   └── variables.tf                  # Input variables (region, project name)
│
├── policies/
│   ├── s3_encryption.rego            # Policy 1: S3 SSE required
│   ├── ssh_access.rego               # Policy 2: No public SSH
│   ├── iam_wildcard.rego             # Policy 3: No wildcard IAM actions
│   └── s3_public_access.rego         # Policy 4: S3 public access block required
│
├── scripts/
│   └── validate.py                   # Pipeline glue script (OPA invocation + report)
│
├── reports/
│   └── .gitkeep                      # Reports directory (actual files are gitignored)
│
├── .gitignore
├── README.md
└── Security-as-Code_Project_Scope_and_Plan.md
```

---

## Prerequisites

Install all of the following tools and ensure each is on your `PATH`:

| Tool | Required Version | Install |
|------|-----------------|---------|
| **Terraform** | ≥ 1.5.0 | [terraform.io/downloads](https://developer.hashicorp.com/terraform/install) |
| **OPA CLI** | ≥ 0.60.0 | [openpolicyagent.org](https://www.openpolicyagent.org/docs/latest/#running-opa) |
| **Python** | ≥ 3.9 | [python.org](https://www.python.org/downloads/) |
| **AWS CLI** | Any | [aws.amazon.com/cli](https://aws.amazon.com/cli/) |
| **Git** | Any | [git-scm.com](https://git-scm.com/) |

Verify each is working:
```bash
terraform -version
opa version
python --version
aws --version
```

You also need a **personal AWS account** (free tier is sufficient). The pipeline never deploys resources — credentials are only used to generate a valid Terraform plan.

---

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/<YOUR_USERNAME>/OPA-code-as-security.git
cd OPA-code-as-security
```

### 2. Configure AWS Credentials

```bash
aws configure
# AWS Access Key ID:     <your-key-id>
# AWS Secret Access Key: <your-secret>
# Default region name:   us-east-1
# Default output format: json
```

> Credentials are read by `terraform plan` only. Nothing is ever deployed.

### 3. Add GitHub Secrets (for CI)

Navigate to your GitHub repository → **Settings → Secrets and variables → Actions** → **New repository secret** and add:

| Secret Name | Value |
|---|---|
| `AWS_ACCESS_KEY_ID` | Your AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | Your AWS secret access key |
| `AWS_DEFAULT_REGION` | e.g. `us-east-1` |

---

## CI/CD Pipeline

The pipeline is defined in `.github/workflows/security-check.yml`.

**Triggers:**
- Every `push` to `main`
- Every `pull_request` targeting `main`
- Manual dispatch

**Steps:**

| Step | Action |
|------|--------|
| 1. Checkout | Clone the repository |
| 2. Setup Python | Install Python 3.11 |
| 3. Setup Terraform | Install Terraform 1.5.7 |
| 4. Install OPA | Download OPA binary from GitHub releases |
| 5. Terraform Init | Initialise the Terraform AWS provider |
| 6. Generate Plan JSON | `terraform plan -out=tfplan && terraform show -json` |
| 7. OPA Evaluation | `python scripts/validate.py` — exits 1 on violations, always writes the report file |
| 8. Ensure Report Exists | Safety net (`if: always()`) — writes a formatted pipeline-error report if step 7 never ran (e.g. Terraform failed) |
| 9. Upload Report | Always uploads `compliance_report.txt` as a workflow artifact (retained 30 days) |

**Viewing Results:**
1. Go to your repository → **Actions**
2. Click the latest **OPA Security Policy Check** run
3. Expand the **Run OPA Security Policy Check** step to see the violation list
4. Click **Artifacts** → download `compliance-report-<run-number>` for the formatted report

---

## Demo Walkthrough

### Scenario 1 — Non-Compliant Push → Pipeline Fails

1. Ensure `terraform/non_compliant.tf` is present (it is by default)
2. Commit and push to `main`:
   ```bash
   git add .
   git commit -m "demo: add non-compliant resources"
   git push origin main
   ```
3. GitHub Actions triggers → the **Run OPA Security Policy Check** step fails
4. The log shows all 4 violation messages
5. Download the compliance report artifact — status shows `NON-COMPLIANT ❌`

### Scenario 2 — Fix Violations → Pipeline Passes

1. Remove the non-compliant resources:
   ```bash
   # Option A: Delete the file
   git rm terraform/non_compliant.tf

   # Option B: Keep for reference but rename so Terraform ignores it
   mv terraform/non_compliant.tf terraform/non_compliant.tf.disabled
   ```
2. Commit and push:
   ```bash
   git add .
   git commit -m "fix: remove non-compliant resources"
   git push origin main
   ```
3. GitHub Actions triggers → all steps turn green ✅
4. Download the compliance report — status shows `COMPLIANT ✅`

---

## Sample Compliance Report

Three possible outcomes are written to `reports/compliance_report.txt`:

**Non-compliant run:**
```
══════════════════════════════════════════════════════════════
  SECURITY-AS-CODE — COMPLIANCE REPORT
══════════════════════════════════════════════════════════════
  Timestamp   : 2026-04-19 10:42:31 UTC
  Plan File   : /home/runner/work/OPA-code-as-security/plan.json
  Policies    : data.terraform.security.deny
  Status      : NON-COMPLIANT  ❌
  Violations  : 4
══════════════════════════════════════════════════════════════

  POLICY VIOLATIONS FOUND
  ──────────────────────────────────────────────────────────────
  [01] DENY [IAM Wildcard] IAM policy 'wildcard' contains a wildcard (*) in an Action field...
  [02] DENY [S3 Encryption] Bucket 'no_encryption' does not have server-side encryption enabled...
  [03] DENY [S3 Public Access] Public access block 'not_blocked' has the following flags not set to true...
  [04] DENY [SSH Access] Security group 'public_ssh' allows SSH (port 22) from 0.0.0.0/0...

  ──────────────────────────────────────────────────────────────
  ⛔  ACTION REQUIRED: Resolve all violations before deployment.
      Fix the Terraform configuration and re-run the pipeline.

══════════════════════════════════════════════════════════════
```

**Compliant run:**
```
══════════════════════════════════════════════════════════════
  SECURITY-AS-CODE — COMPLIANCE REPORT
══════════════════════════════════════════════════════════════
  Timestamp   : 2026-04-19 10:55:12 UTC
  Plan File   : /home/runner/work/OPA-code-as-security/plan.json
  Policies    : data.terraform.security.deny
  Status      : COMPLIANT      ✅
  Violations  : 0
══════════════════════════════════════════════════════════════

  ✅  All security policies passed.
      Infrastructure configuration is compliant.
      Safe to proceed with deployment.

══════════════════════════════════════════════════════════════
```

**Pipeline error run** (e.g. OPA parse error, missing plan file):
```
══════════════════════════════════════════════════════════════
  SECURITY-AS-CODE — COMPLIANCE REPORT
══════════════════════════════════════════════════════════════
  Timestamp   : 2026-04-19 11:03:44 UTC
  Status      : PIPELINE ERROR  ⚠️
══════════════════════════════════════════════════════════════

  PIPELINE ERROR — OPA EVALUATION DID NOT COMPLETE
  ──────────────────────────────────────────────────────────────
  OPA exited with non-zero code: 2

  OPA stdout:
  1 error occurred: policies/iam_wildcard.rego:74: rego_parse_error: ...

  ──────────────────────────────────────────────────────────────
  ⚠️  Check the workflow logs for the failed step above.

══════════════════════════════════════════════════════════════
```

---

## References

| Resource | URL |
|----------|-----|
| OPA Documentation | https://www.openpolicyagent.org/docs/latest/ |
| Rego Policy Language | https://www.openpolicyagent.org/docs/latest/policy-language/ |
| OPA Playground | https://play.openpolicyagent.org/ |
| Terraform AWS Provider | https://registry.terraform.io/providers/hashicorp/aws/latest/docs |
| Terraform JSON Plan Format | https://developer.hashicorp.com/terraform/internals/json-format |
| GitHub Actions Docs | https://docs.github.com/en/actions |
| `setup-terraform` Action | https://github.com/hashicorp/setup-terraform |
