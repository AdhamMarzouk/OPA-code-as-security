# policies/s3_public_access.rego
# ─────────────────────────────────────────────────────────────────────────────
# Policy 4: S3 Public Access Block Required
#
# Purpose:
#   Denies any aws_s3_bucket_public_access_block resource where at least
#   one of the four mandatory block flags is not explicitly set to true.
#
# Why this matters:
#   AWS S3 buckets can be made publicly accessible through ACLs or bucket
#   policies. The public access block is a safety net that overrides both,
#   preventing accidental data exposure even if an ACL or policy is
#   misconfigured. All four flags must be enabled together to fully close
#   the public access surface.
#
# The four flags that must ALL be true:
#   - block_public_acls       — Blocks new public ACLs and ignores existing ones
#   - block_public_policy     — Blocks new public bucket policies
#   - ignore_public_acls      — Ignores all public ACLs on the bucket
#   - restrict_public_buckets — Restricts public access via any policy
#
# Terraform resource checked: aws_s3_bucket_public_access_block
# ─────────────────────────────────────────────────────────────────────────────

package terraform.security

import future.keywords

# ─── Main Rule ────────────────────────────────────────────────────────────────
# Produces a denial message listing which specific flags are not set to true.

deny contains msg if {
    # Iterate over all planned resource changes
    resource := input.resource_changes[_]

    # Only evaluate S3 public access block resources
    resource.type == "aws_s3_bucket_public_access_block"

    # Only flag resources being created or updated
    modifying_action(resource.change.actions)

    config := resource.change.after

    # Collect the names of every flag that is NOT set to true
    # Using a set comprehension for clear, idiomatic Rego
    failed_flags := {flag |
        flag := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"][_]
        config[flag] != true
    }

    # Only deny if at least one flag failed
    count(failed_flags) > 0

    # Construct a descriptive message naming the specific failing flags
    msg := sprintf(
        "DENY [S3 Public Access] Public access block '%s' has the following flags not set to true: %v. All four flags (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets) must be true.",
        [resource.name, failed_flags]
    )
}

# ─── Helper: Modifying Actions ────────────────────────────────────────────────
# Returns true if the change actions include "create" or "update".

modifying_action(actions) if {
    actions[_] in {"create", "update"}
}
