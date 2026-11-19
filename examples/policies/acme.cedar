// Demo policy for tenant "acme" (scripts/seed_tenant.py loads this file).
//
// Cedar denies by default: anything not permitted below is denied.
// Annotations become obligations on an ALLOW; see docs/guide/policies.md.

// Analysts may query, but the result must have ssn and compensation masked.
@mask_fields("ssn,compensation")
@approval_required("false")
permit(principal, action == Action::"execute_query", resource)
when { principal.role == "Analyst" };

// Managers may make small transfers. Approval is required but the action is
// low risk, so it is approved automatically.
@approval_required("true")
@risk_tier("low")
permit(principal, action == Action::"transfer_funds", resource)
when { principal.role == "Manager" };

// Medium transfers go to the approval webhook.
@approval_required("true")
@risk_tier("medium")
permit(principal, action == Action::"transfer_medium_funds", resource)
when { principal.role == "Manager" };

// Large transfers go to the approval webhook too (the demo approver refuses them).
@approval_required("true")
@risk_tier("high")
permit(principal, action == Action::"transfer_large_funds", resource)
when { principal.role == "Manager" };
