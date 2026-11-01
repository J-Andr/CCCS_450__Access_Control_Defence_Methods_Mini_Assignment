# NorthBank Authorization Policy

This project implements the NorthBank transfer-service authorization assignment
using OPA and Rego v1.

## Files

- `policy.rego` — final hybrid RBAC/ABAC policy (`data.cccs450.authz.allow`).
- `policy_test.rego` — automated allow/deny and missing-data tests.
- `data.json` — fictional users and resources used as reference data.
- `inputs/caseNN/input.json` — standalone request fixtures for `opa eval`.
- `decision-matrix.md` — decision matrix and field classification.
- `AI-use.md` — disclosure of AI assistance.
- `evidence/opa-version.txt` — output of `opa version`.
- `evidence/opa-test-output.txt` — raw verbose output from the complete test run.

The request fixtures are in separate case directories because `opa test .`
recursively loads JSON files. Putting several request objects with the same
top-level keys in one directory makes OPA attempt to merge them as policy data,
which causes merge errors. Each fixture remains a complete request suitable for
use with `opa eval --input`.

## Run

From the project root:

```sh
opa version
opa fmt --write policy.rego policy_test.rego
opa test . -v
opa eval --data policy.rego \
  --input inputs/case01/input.json \
  'data.cccs450.authz.allow'
```

The test evidence and OPA version are recorded under `evidence/`.

## Authorization model

The policy uses explicit role/action/resource-type rules and denies by default.
Branch, MFA, transfer amount, business hours, resource ownership metadata, and
transfer initiator are checked where required for the requested action.
Missing or incorrectly typed required attributes make the corresponding allow
rule fail closed. Branch values must be `MTL` or `TOR`, and required string
identifiers cannot be empty. Teller-initiated transfers are limited to amounts
from $0 through $5,000, inclusive, during hours 08:00 through 18:00, inclusive.
Supervisor approvals require MFA, the same branch, a valid nonnegative transfer
amount, and a different initiator. Auditors can read audit logs across
branches; all other auditor actions are denied.

The action-specific requirements are intentional: for example, an account
view does not need a transfer amount or business hour, while a teller transfer
initiation does. A supervisor approval requires the transfer's amount and
initiator to be present, but not the business-hour context because the
assignment applies that condition only to teller initiation.

## Assignment evidence

The RBAC-only implementation is preserved in Git commit
`31e210a` (`Implement RBAC-only authorization baseline`). In that version,
permissions depend on role, action, and resource type alone:

| Role | Baseline permitted action | Baseline denied action |
|---|---|---|
| Teller | `view_account` / `account` | `approve_transfer` / `transfer` |
| Supervisor | `approve_transfer` / `transfer` | `initiate_transfer` / `transfer` |
| Auditor | `read_audit_log` / `audit_log` | `view_account` / `account` |

The evaluated baseline results are in
`evidence/rbac-baseline-results.txt`. For example, RBAC alone permits a teller
to view an account in another branch. The final hybrid policy denies that
request in `inputs/case02/input.json` because the subject branch (`MTL`)
differs from the resource branch (`TOR`).

The final test suite includes permitted and denied decisions for all roles,
branch and MFA denials, self-approval denial, the $5,000/$5,001 boundary,
invalid and missing attributes, and auditor transaction-action denials.
