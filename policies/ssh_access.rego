# policies/ssh_access.rego
# ─────────────────────────────────────────────────────────────────────────────
# Policy 2: No Public SSH Access
#
# Purpose:
#   Denies any aws_security_group resource that permits inbound SSH
#   (TCP port 22) from any IPv4 address (0.0.0.0/0).
#
# Why this matters:
#   Exposing SSH to the public internet is one of the most common entry
#   points for attackers. Brute-force, credential stuffing, and zero-day
#   SSH exploits are trivially automated against open port 22. SSH access
#   should always be restricted to a known CIDR range (VPN, bastion host).
#
# Terraform resource checked: aws_security_group
# ─────────────────────────────────────────────────────────────────────────────

package terraform.security

import future.keywords.contains
import future.keywords.if

# ─── Main Rule ────────────────────────────────────────────────────────────────
# Produces a denial message for every security group that allows SSH
# from the entire internet (0.0.0.0/0).

deny contains msg if {
    # Iterate over all planned resource changes
    resource := input.resource_changes[_]

    # Only evaluate security group resources
    resource.type == "aws_security_group"

    # Only flag resources being created or updated
    modifying_action(resource.change.actions)

    # Iterate over each ingress rule in the security group
    ingress := resource.change.after.ingress[_]

    # Port 22 falls within the rule's port range
    # (handles rules like from_port=0, to_port=65535 as well as exact 22/22)
    ingress.from_port <= 22
    ingress.to_port   >= 22

    # The rule allows traffic from any IPv4 address
    "0.0.0.0/0" in ingress.cidr_blocks

    # Construct a descriptive, actionable denial message
    msg := sprintf(
        "DENY [SSH Access] Security group '%s' allows SSH (TCP port 22) from 0.0.0.0/0. Restrict the cidr_blocks to a known private range (e.g. 10.0.0.0/8 or your VPN CIDR).",
        [resource.name]
    )
}

# ─── Helper: Modifying Actions ────────────────────────────────────────────────
# Returns true if the change actions include "create" or "update".

modifying_action(actions) if {
    actions[_] in {"create", "update"}
}
