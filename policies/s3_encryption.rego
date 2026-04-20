# policies/s3_encryption.rego
# ─────────────────────────────────────────────────────────────────────────────
# Policy 1: S3 Encryption Required
#
# Purpose:
#   Denies any aws_s3_bucket resource that does not have server-side
#   encryption (SSE) configured with AES256 or aws:kms.
#
# Why this matters:
#   Unencrypted S3 buckets expose data at rest to anyone who gains
#   access to the underlying storage. AWS recommends SSE as a baseline
#   control for all buckets storing non-public data.
#
# Terraform resource checked: aws_s3_bucket
# ─────────────────────────────────────────────────────────────────────────────

package terraform.security

import future.keywords.contains
import future.keywords.if

# ─── Main Rule ────────────────────────────────────────────────────────────────
# Produces a denial message for every S3 bucket that lacks valid SSE config.

deny contains msg if {
    # Iterate over all planned resource changes
    resource := input.resource_changes[_]

    # Only evaluate S3 bucket resources
    resource.type == "aws_s3_bucket"

    # Only flag resources being created or updated (not deleted/no-op)
    modifying_action(resource.change.actions)

    # The bucket lacks a valid server-side encryption configuration
    not valid_sse(resource.change.after)

    # Construct a descriptive, actionable denial message
    msg := sprintf(
        "DENY [S3 Encryption] Bucket '%s' does not have server-side encryption enabled. Add a server_side_encryption_configuration block with sse_algorithm set to AES256 or aws:kms.",
        [resource.name]
    )
}

# ─── Helper: Valid SSE Configuration ─────────────────────────────────────────
# Returns true if the resource config contains a recognised SSE algorithm.
# Traverses the nested structure:
#   server_side_encryption_configuration[*]
#     .rule[*]
#       .apply_server_side_encryption_by_default[*]
#         .sse_algorithm

valid_sse(config) if {
    algo := config.server_side_encryption_configuration[_].rule[_].apply_server_side_encryption_by_default[_].sse_algorithm
    algo in {"AES256", "aws:kms"}
}

# ─── Helper: Modifying Actions ────────────────────────────────────────────────
# Returns true if the change actions include "create" or "update".
# Deletions and no-ops are excluded from policy evaluation.

modifying_action(actions) if {
    actions[_] in {"create", "update"}
}
