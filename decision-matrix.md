# NorthBank Authorization Decision Matrix

| Subject | Action | Resource | Relevant attributes | Decision | Security reason |
|---|---|---|---|---|---|
| Teller | `view_account` | Account | Subject and account branches match; owner is present | Allow | Teller access is limited to the teller's branch. |
| Teller | `view_account` | Account | Branches differ | Deny | Prevents cross-branch account access. |
| Teller | `initiate_transfer` | Transfer | Same branch, MFA true, initiator is teller, amount 0–5,000, hour 8–18 | Allow | Enforces transaction limit, identity, branch, MFA, and business hours. |
| Teller | `initiate_transfer` | Transfer | Amount exceeds 5,000, or amount/hour/MFA/branch/initiator is missing or invalid | Deny | Invalid or out-of-policy transactions fail closed. |
| Supervisor | `view_account` | Account | Same branch; account owner is present | Allow | Supervisor account access is branch-scoped. |
| Supervisor | `view_account` | Account | Branches differ | Deny | Prevents cross-branch account access. |
| Supervisor | `approve_transfer` | Transfer | Same branch, MFA true, amount and initiator present, initiator differs from supervisor | Allow | Requires strong authentication and separation of duties. |
| Supervisor | `approve_transfer` | Transfer | Wrong branch, missing MFA/amount/initiator, or self-approval | Deny | Prevents unauthorized or self-approved transfers. |
| Auditor | `read_audit_log` | Audit log | Audit-log type and resource branch are present; branches may differ | Allow | Auditors may review logs across branches. |
| Auditor | Initiate, approve, modify, or delete | Transfer | Any branch or transaction attributes | Deny | Auditors have read-only audit access, not transaction authority. |
| Any other role or unmatched request | Any other action | Any other resource | Any attributes | Deny | Default-deny behavior grants no implicit permissions. |

## Attribute classification

- **Subject attributes:** `subject.id`, `subject.role`, `subject.branch`, and
  `subject.mfa` describe the requesting user.
- **Action:** `action` names the operation being requested, such as
  `view_account` or `initiate_transfer`.
- **Resource attributes:** `resource.type`, `resource.branch`,
  `resource.owner_id`, `resource.initiated_by`, and `resource.amount` describe
  the target account, transfer, or audit log.
- **Environment/context attributes:** `context.hour` describes the request
  time and is required for teller transfer initiation.

An attribute is required when the relevant authorization rule depends on it.
For example, missing amount or hour denies teller transfer initiation; missing
amount or initiator denies supervisor approval; a missing transfer amount does
not affect account viewing.
