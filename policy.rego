package cccs450.authz

import rego.v1

default allow := false

# RBAC-only baseline.

# Attribute-based restrictions will be added in the next phase.

allow if {
	input.subject.role == "teller"
	input.action == "view_account"
	input.resource.type == "account"
}

allow if {
	input.subject.role == "teller"
	input.action == "initiate_transfer"
	input.resource.type == "transfer"
}

allow if {
	input.subject.role == "supervisor"
	input.action == "view_account"
	input.resource.type == "account"
}

allow if {
	input.subject.role == "supervisor"
	input.action == "approve_transfer"
	input.resource.type == "transfer"
}

allow if {
	input.subject.role == "auditor"
	input.action == "read_audit_log"
	input.resource.type == "audit_log"
}
