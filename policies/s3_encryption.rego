package terraform.security

import future.keywords

# ─── Main Rule ────────────────────────────────────────────────────────────────
# Deny any S3 bucket that lacks a matching SSE configuration resource.

deny contains msg if {
    # Iterate over all planned resource changes
    resource := input.resource_changes[_]

    # Only evaluate S3 bucket resources
    resource.type == "aws_s3_bucket"

    # Only flag resources being created or updated (not deleted/no-op)
    modifying_action(resource.change.actions)

    # No valid aws_s3_bucket_server_side_encryption_configuration exists
    # with the same Terraform resource name as this bucket
    not sse_config_exists(resource.name, input.resource_changes)

    # Construct a descriptive, actionable denial message
    msg := sprintf(
        "DENY [S3 Encryption] Bucket '%s' does not have a corresponding aws_s3_bucket_server_side_encryption_configuration resource. Create one named '%s' with sse_algorithm set to AES256 or aws:kms.",
        [resource.name, resource.name]
    )
}

# ─── Helper: SSE Config Exists ────────────────────────────────────────────────
# Returns true if there is an aws_s3_bucket_server_side_encryption_configuration
# resource in the plan that:
#   1. Has the same Terraform resource name as the bucket
#   2. Is being created or updated
#   3. Has a valid SSE algorithm (AES256 or aws:kms)

sse_config_exists(bucket_resource_name, all_changes) if {
    sse := all_changes[_]
    sse.type == "aws_s3_bucket_server_side_encryption_configuration"

    # Name match: sse resource name must equal the s3 bucket resource name
    sse.name == bucket_resource_name

    # Must be a modifying action (not a delete or no-op)
    modifying_action(sse.change.actions)

    # Must have a valid SSE algorithm configured
    algo := sse.change.after.rule[_].apply_server_side_encryption_by_default[_].sse_algorithm
    algo in {"AES256", "aws:kms"}
}

# ─── Helper: Modifying Actions ────────────────────────────────────────────────
# Returns true if the change actions include "create" or "update".
# Deletions and no-ops are excluded from policy evaluation.

modifying_action(actions) if {
    actions[_] in {"create", "update"}
}
