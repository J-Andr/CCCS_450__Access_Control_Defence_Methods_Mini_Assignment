package cccs450.authz

import rego.v1

default allow := false

non_empty_string(value) if {
	is_string(value)
	value != ""
}

valid_branch(value) if {
	value in {"MTL", "TOR"}
}

# --------------------------------------------------

# Teller: view an account in the same branch.

# --------------------------------------------------

allow if {
	input.subject.role == "teller"
	input.action == "view_account"
	input.resource.type == "account"

	non_empty_string(input.subject.id)
	valid_branch(input.subject.branch)
	valid_branch(input.resource.branch)
	non_empty_string(input.resource.owner_id)

	input.subject.branch == input.resource.branch
}

# --------------------------------------------------

# Teller: initiate a transfer.

# Conditions: same branch, MFA, amount <= 5000,

# and business hours 08:00 through 18:00 inclusive.

# --------------------------------------------------

allow if {
	input.subject.role == "teller"
	input.action == "initiate_transfer"
	input.resource.type == "transfer"

	non_empty_string(input.subject.id)
	valid_branch(input.subject.branch)
	valid_branch(input.resource.branch)
	non_empty_string(input.resource.owner_id)
	non_empty_string(input.resource.initiated_by)

	input.subject.mfa == true
	is_number(input.resource.amount)
	input.resource.amount >= 0
	input.resource.amount <= 5000

	is_number(input.context.hour)
	input.context.hour >= 8
	input.context.hour <= 18

	input.subject.branch == input.resource.branch
	input.resource.initiated_by == input.subject.id
}

# --------------------------------------------------

# Supervisor: view an account in the same branch.

# --------------------------------------------------

allow if {
	input.subject.role == "supervisor"
	input.action == "view_account"
	input.resource.type == "account"

	non_empty_string(input.subject.id)
	valid_branch(input.subject.branch)
	valid_branch(input.resource.branch)
	non_empty_string(input.resource.owner_id)

	input.subject.branch == input.resource.branch
}

# --------------------------------------------------

# Supervisor: approve a transfer in the same branch.

# MFA is mandatory. The initiator cannot approve it.

# --------------------------------------------------

allow if {
	input.subject.role == "supervisor"
	input.action == "approve_transfer"
	input.resource.type == "transfer"

	non_empty_string(input.subject.id)
	valid_branch(input.subject.branch)
	valid_branch(input.resource.branch)
	non_empty_string(input.resource.owner_id)
	non_empty_string(input.resource.initiated_by)

	input.subject.mfa == true
	is_number(input.resource.amount)
	input.resource.amount >= 0
	input.subject.branch == input.resource.branch

	input.subject.id != input.resource.initiated_by
}

# --------------------------------------------------

# Auditor: read audit logs across branches.

# --------------------------------------------------

allow if {
	input.subject.role == "auditor"
	input.action == "read_audit_log"
	input.resource.type == "audit_log"

	non_empty_string(input.subject.id)
	valid_branch(input.resource.branch)
}
