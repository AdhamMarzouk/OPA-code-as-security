# policies/s3_encryption.rego
# ─────────────────────────────────────────────────────────────────────────────
# Policy 1: S3 Encryption Required
#
# Purpose:
#   Denies any aws_s3_bucket resource that does not have a corresponding
#   aws_s3_bucket_server_side_encryption_configuration resource with a
#   valid algorithm (AES256 or aws:kms).
#
# Why this matters:
#   Unencrypted S3 buckets expose data at rest to anyone who gains
#   access to the underlying storage. AWS recommends SSE as a baseline
#   control for all buckets storing non-public data.
#
# AWS Provider v5 Note:
#   The inline server_side_encryption_configuration block inside
#   aws_s3_bucket is deprecated in AWS provider v5+. Encryption must
#   now be configured via the standalone resource:
#   aws_s3_bucket_server_side_encryption_configuration
#
# Correlation convention:
#   The policy matches buckets to their SSE config resources by
#   Terraform resource NAME (not the S3 bucket name). For example:
#     aws_s3_bucket.MY_NAME  →  aws_s3_bucket_server_side_encryption_configuration.MY_NAME
#   This is a deliberate naming convention enforced by this policy.
#
# Terraform resources checked:
#   aws_s3_bucket (primary — triggers the deny)
#   aws_s3_bucket_server_side_encryption_configuration (looked up to satisfy policy)
# ─────────────────────────────────────────────────────────────────────────────

package terraform.security

import future.keywords.contains
import future.keywords.if

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
