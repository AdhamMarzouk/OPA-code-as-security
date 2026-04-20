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
