# Security-as-Code: Policy as Code Implementation

**Project Scope & Plan**

---

**Prepared by:** [Your Name]
**Course:** [Course Name & Code]
**Date:** [Submission Date]

---

## 1. Project Overview

This project implements a Security-as-Code pipeline using Open Policy Agent (OPA) to enforce security controls on cloud infrastructure defined in Terraform. The goal is to demonstrate how policy-as-code can intercept and validate infrastructure changes before deployment, shifting security left into the development workflow.

| Field | Detail |
|-------|--------|
| **Project Title** | Security-as-Code: Policy as Code Implementation |
| **Objective** | Implement policy-as-code using OPA to enforce security controls across AWS cloud infrastructure defined in Terraform |
| **Scope** | Proof-of-concept demo with working validation pipeline |
| **Timeline** | 7 days (1 week) |
| **Team Size** | Solo |

---

## 2. Problem Statement

Cloud infrastructure misconfigurations are one of the leading causes of security breaches. Common mistakes include unencrypted storage buckets, overly permissive network rules, and wildcard IAM policies. These issues often go undetected until after deployment, when the damage surface is already exposed.

Manual security reviews do not scale. They introduce delays, are inconsistent across teams, and depend on individual reviewer expertise. Security-as-Code addresses this by encoding security requirements as machine-readable policies that are automatically evaluated against every infrastructure change, providing consistent, repeatable compliance validation integrated directly into the deployment pipeline.

---

## 3. Technical Approach

### 3.1 Architecture Overview

The pipeline follows a straightforward evaluate-before-deploy pattern:

1. **Define infrastructure** in Terraform HCL (S3 buckets, security groups, IAM policies).
2. **Generate a plan** using `terraform plan -out=tfplan` and export to JSON.
3. **Evaluate the plan** against OPA/Rego security policies.
4. **Gate deployment:** compliant plans proceed; non-compliant plans are blocked with violation details.
5. **Automate via CI/CD** (GitHub Actions) to run on every push.

### 3.2 Tools & Technologies

| Tool | Role | Version / Notes |
|------|------|-----------------|
| **Terraform** | Infrastructure as Code (IaC) | v1.5+ (HCL syntax, AWS provider) |
| **OPA** | Policy engine / evaluation | Latest stable CLI |
| **Rego** | Policy definition language | OPA's native query language |
| **AWS** | Target cloud provider | Free-tier resources (S3, SG, IAM) |
| **Python** | Automation / glue scripts | 3.9+ (subprocess, JSON parsing) |
| **GitHub Actions** | CI/CD pipeline automation | Runs validation on every push |

### 3.3 Security Policies to Implement

| # | Policy | What It Checks | AWS Resource |
|---|--------|----------------|--------------|
| 1 | S3 encryption required | Denies S3 buckets without server-side encryption (AES256 or aws:kms) | `aws_s3_bucket` |
| 2 | No public SSH access | Denies security groups with port 22 open to 0.0.0.0/0 | `aws_security_group` |
| 3 | No wildcard IAM actions | Denies IAM policies containing "\*" in the Action field | `aws_iam_policy` |
| 4 | S3 public access blocked | Denies S3 buckets without the public access block configuration | `aws_s3_bucket_public_access_block` |

---

## 4. Project Plan — 7-Day Schedule

The plan is structured to front-load learning (Days 1–3) and back-load integration and polish (Days 4–7). No AWS resources are actually deployed; the pipeline evaluates Terraform plans before apply, keeping costs at zero.

| Day | Focus Area | Key Tasks | Est. Hours |
|-----|-----------|-----------|------------|
| **Day 1** | Setup + OPA Basics | Install OPA CLI, run OPA Playground tutorials, write first Rego rule, set up project repo structure | 2–3 hrs |
| **Day 2** | Terraform Configs | Write compliant + non-compliant versions of S3, security group, and IAM resources; generate plan JSON | 2–3 hrs |
| **Day 3** | Rego Policies (Core) | Write all 4 Rego policies; test each against plan.json using `opa eval`; debug and iterate | 3–4 hrs |
| **Day 4** | Pipeline Glue Script | Write Python/shell wrapper: terraform plan → JSON → opa eval → pass/fail report; test both paths | 2–3 hrs |
| **Day 5** | CI/CD Integration | Create GitHub Actions workflow; configure steps: checkout → init → plan → OPA eval → gate | 2–3 hrs |
| **Day 6** | Compliance Report + Polish | Build formatted compliance output (pass/fail summary table); write README; add inline comments to Rego files | 2–3 hrs |
| **Day 7** | Buffer + Demo Prep | Fix remaining issues; prepare demo flow (push bad code → CI fails → fix → CI passes); rehearse walkthrough | 1–2 hrs |

**Total estimated effort:** 14–22 hours across 7 days.

---

## 5. Deliverables

| # | Deliverable | Description |
|---|-------------|-------------|
| 1 | **Policy Definitions** | 4 Rego policy files (.rego) with inline documentation covering S3 encryption, SSH access, IAM wildcards, and public access blocks |
| 2 | **Terraform Configurations** | Compliant and non-compliant HCL files demonstrating each policy violation and its remediation |
| 3 | **CI/CD Pipeline** | GitHub Actions workflow (.yml) that runs the full validation pipeline on every push to the repository |
| 4 | **Compliance Report** | Automated pass/fail output generated by the pipeline showing which policies passed and which were violated |
| 5 | **Project Documentation** | README with setup instructions, architecture overview, and demo walkthrough; this scope document |

---

## 6. Repository Structure

```
security-as-code/
├── terraform/
│   ├── main.tf                  # Provider config + compliant resources
│   ├── non_compliant.tf         # Intentionally insecure resources
│   └── variables.tf             # Shared variables
├── policies/
│   ├── s3_encryption.rego       # S3 encryption policy
│   ├── ssh_access.rego          # SSH public access policy
│   ├── iam_wildcard.rego        # IAM wildcard action policy
│   └── s3_public_access.rego    # S3 public access block policy
├── scripts/
│   └── validate.py              # Pipeline glue script
├── .github/
│   └── workflows/
│       └── security-check.yml   # GitHub Actions pipeline
└── README.md
```

---

## 7. Risks & Mitigations

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Rego learning curve is steep | 🔴 High | Budget extra time on Day 3; use OPA Playground for rapid iteration; start with simple rules before complex logic |
| Terraform plan JSON structure is unfamiliar | 🟡 Medium | Generate a sample plan JSON on Day 2 and study its structure before writing policies |
| AWS credentials misconfigured in CI | 🟡 Medium | Use GitHub Secrets for AWS credentials; test locally first; pipeline only runs terraform plan, never apply |
| Scope creep (adding more policies) | 🟢 Low | Fix scope at 4 policies; additional policies are stretch goals only if Days 1–5 complete early |

---

## 8. Cost Considerations

This project is designed to incur zero AWS charges. The pipeline runs `terraform plan` only and never executes `terraform apply`. All policy evaluation happens locally via OPA CLI. GitHub Actions provides sufficient free-tier minutes for this scale. The only requirement is a personal AWS account with credentials configured for the Terraform AWS provider to generate a valid plan.

---

## 9. Success Criteria

The project is considered successful when the following conditions are met:

- All 4 OPA policies correctly identify non-compliant Terraform configurations
- All 4 OPA policies correctly pass compliant Terraform configurations
- The CI/CD pipeline automatically runs validation on every push to the repository
- A non-compliant push triggers a pipeline failure with clear violation details
- A compliant push results in a passing pipeline with a clean compliance report
- The project README provides sufficient documentation to reproduce the setup

---

## 10. Key References

- **OPA Documentation:** https://www.openpolicyagent.org/docs/latest/
- **Rego Policy Language:** https://www.openpolicyagent.org/docs/latest/policy-language/
- **OPA Playground:** https://play.openpolicyagent.org/
- **Terraform AWS Provider:** https://registry.terraform.io/providers/hashicorp/aws/latest/docs
- **Terraform JSON Output:** https://developer.hashicorp.com/terraform/internals/json-format
- **GitHub Actions Docs:** https://docs.github.com/en/actions
