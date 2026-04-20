package terraform.security

import future.keywords

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
