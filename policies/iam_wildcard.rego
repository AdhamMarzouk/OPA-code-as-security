# policies/iam_wildcard.rego
# ─────────────────────────────────────────────────────────────────────────────
# Policy 3: No Wildcard IAM Actions
#
# Purpose:
#   Denies any aws_iam_policy resource that includes "*" in any
#   Statement's Action field, regardless of whether Action is a
#   bare string or an array.
#
# Why this matters:
#   Wildcard IAM actions (Action: "*") grant the attached principal
#   unrestricted access to every AWS API across every service. This
#   directly violates the principle of least privilege and is a critical
#   finding in virtually every cloud security audit. Policies must
#   enumerate only the specific actions required for the task.
#
# Terraform resource checked: aws_iam_policy
# ─────────────────────────────────────────────────────────────────────────────

package terraform.security

import future.keywords

# ─── Main Rule ────────────────────────────────────────────────────────────────
# Produces a denial message for every IAM policy containing "*" in any
# Statement's Action field.
#
# Note on JSON decoding:
#   In a Terraform plan, the `policy` attribute of aws_iam_policy is stored
#   as a JSON-encoded *string* (not a nested object). We must call
#   json.unmarshal() to decode it before we can traverse its structure.

deny contains msg if {
    # Iterate over all planned resource changes
    resource := input.resource_changes[_]

    # Only evaluate IAM policy resources
    resource.type == "aws_iam_policy"

    # Only flag resources being created or updated
    modifying_action(resource.change.actions)

    # Decode the policy JSON string into an object
    policy_doc := json.unmarshal(resource.change.after.policy)

    # Iterate over each Statement in the policy document
    statement := policy_doc.Statement[_]

    # Check if this statement's Action contains a wildcard
    wildcard_action(statement.Action)

    # Construct a descriptive, actionable denial message
    msg := sprintf(
        "DENY [IAM Wildcard] IAM policy '%s' contains a wildcard (*) in an Action field. Replace with specific, least-privilege actions (e.g. s3:GetObject, ec2:DescribeInstances).",
        [resource.name]
    )
}

# ─── Helper: Wildcard Action (string form) ────────────────────────────────────
# Matches when Action is the bare string "*"
# e.g.  Action: "*"

wildcard_action(action) if {
    action == "*"
}

# ─── Helper: Wildcard Action (array form) ─────────────────────────────────────
# Matches when Action is an array containing "*" among other actions
# e.g.  Action: ["s3:GetObject", "*"]

wildcard_action(action) if {
    is_array(action)
    "*" in action
}

# ─── Helper: Modifying Actions ────────────────────────────────────────────────
# Returns true if the change actions include "create" or "update".

modifying_action(actions) if {
    actions[_] in {"create", "update"}
}
