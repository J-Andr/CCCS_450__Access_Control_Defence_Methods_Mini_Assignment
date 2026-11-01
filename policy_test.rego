package cccs450.authz

import rego.v1

test_teller_can_view_same_branch_account if {
	allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
		},
		"action": "view_account",
		"resource": {
			"type": "account",
			"branch": "MTL",
			"owner_id": "customer77",
		},
		"context": {"hour": 14},
	}
}

test_teller_cannot_view_cross_branch_account if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
		},
		"action": "view_account",
		"resource": {
			"type": "account",
			"branch": "TOR",
			"owner_id": "customer88",
		},
		"context": {"hour": 14},
	}
}

test_teller_can_initiate_transfer_at_5000 if {
	allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": 5000,
		},
		"context": {"hour": 14},
	}
}

test_teller_cannot_initiate_transfer_over_5000 if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": 5001,
		},
		"context": {"hour": 14},
	}
}

test_teller_cannot_initiate_transfer_without_mfa if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
			"mfa": false,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": 2400,
		},
		"context": {"hour": 14},
	}
}

test_teller_cannot_initiate_transfer_outside_hours if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": 2400,
		},
		"context": {"hour": 7},
	}
}

test_teller_cannot_initiate_transfer_in_another_branch if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "TOR",
			"owner_id": "customer88",
			"initiated_by": "u101",
			"amount": 2400,
		},
		"context": {"hour": 14},
	}
}

test_teller_cannot_initiate_transfer_without_amount if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
		},
		"context": {"hour": 14},
	}
}

test_teller_cannot_initiate_transfer_with_string_amount if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "teller",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": "5000",
		},
		"context": {"hour": 14},
	}
}

test_supervisor_can_view_same_branch_account if {
	allow with input as {
		"subject": {
			"id": "u102",
			"role": "supervisor",
			"branch": "MTL",
		},
		"action": "view_account",
		"resource": {
			"type": "account",
			"branch": "MTL",
			"owner_id": "customer77",
		},
		"context": {"hour": 14},
	}
}

test_supervisor_cannot_view_cross_branch_account if {
	not allow with input as {
		"subject": {
			"id": "u102",
			"role": "supervisor",
			"branch": "MTL",
		},
		"action": "view_account",
		"resource": {
			"type": "account",
			"branch": "TOR",
			"owner_id": "customer88",
		},
		"context": {"hour": 14},
	}
}

test_supervisor_can_approve_another_users_transfer if {
	allow with input as {
		"subject": {
			"id": "u102",
			"role": "supervisor",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "approve_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": 2400,
		},
		"context": {"hour": 14},
	}
}

test_supervisor_cannot_approve_own_transfer if {
	not allow with input as {
		"subject": {
			"id": "u101",
			"role": "supervisor",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "approve_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": 2400,
		},
		"context": {"hour": 14},
	}
}

test_supervisor_cannot_approve_without_mfa if {
	not allow with input as {
		"subject": {
			"id": "u102",
			"role": "supervisor",
			"branch": "MTL",
			"mfa": false,
		},
		"action": "approve_transfer",
		"resource": {
			"type": "transfer",
			"branch": "MTL",
			"owner_id": "customer77",
			"initiated_by": "u101",
			"amount": 2400,
		},
		"context": {"hour": 14},
	}
}

test_auditor_can_read_cross_branch_audit_log if {
	allow with input as {
		"subject": {
			"id": "u103",
			"role": "auditor",
			"branch": "TOR",
			"mfa": true,
		},
		"action": "read_audit_log",
		"resource": {
			"type": "audit_log",
			"branch": "MTL",
		},
		"context": {"hour": 14},
	}
}

test_auditor_cannot_initiate_transfer if {
	not allow with input as {
		"subject": {
			"id": "u103",
			"role": "auditor",
			"branch": "TOR",
			"mfa": true,
		},
		"action": "initiate_transfer",
		"resource": {
			"type": "transfer",
			"branch": "TOR",
			"owner_id": "customer88",
			"initiated_by": "u103",
			"amount": 100,
		},
		"context": {"hour": 14},
	}
}

test_unknown_role_is_denied if {
	not allow with input as {
		"subject": {
			"id": "u999",
			"role": "manager",
			"branch": "MTL",
			"mfa": true,
		},
		"action": "view_account",
		"resource": {
			"type": "account",
			"branch": "MTL",
			"owner_id": "customer77",
		},
		"context": {"hour": 14},
	}
}
