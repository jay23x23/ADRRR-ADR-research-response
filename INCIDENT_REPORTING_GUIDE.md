# Incident reporting: keeping low risk visible

Detection, alert, case, and incident are related but different:

- **Detection:** analytic logic matched telemetry.
- **Alert:** the result, evidence, severity, confidence, and investigation guidance.
- **Case:** a tracked unit of analyst work with ownership, status, notes, and audit history.
- **Incident:** confirmed or sufficiently credible harmful activity requiring coordinated response.

This lab creates a case for every alert. That keeps low-risk findings from “working in the dark.” It does not call every alert an incident, because doing so would corrupt metrics and overwhelm response teams.

## Low-risk workflow

1. The P4 case enters the visible queue as `NEW - ANALYST REVIEW REQUIRED`.
2. An analyst accepts ownership and changes status to `IN REVIEW`.
3. The analyst completes the rule-specific checks and records evidence.
4. Related low-risk cases are linked or grouped. Repetition can increase cumulative risk.
5. If evidence supports compromise, escalate to an incident and preserve the originating case.
6. Otherwise close with a documented benign/false-positive/data-quality disposition and tuning recommendation.

## What this first implementation does not yet provide

JSON and Markdown files are suitable for learning and source control, but concurrent analysts need a transactional case store or platform. Real deployment should add authenticated users, RBAC, append-only history, notifications, assignments, comments, evidence attachments, case linking, SLA timers, immutable event references, and dashboards.

## Study the code

In `workready_siem.py`, follow this sequence:

1. `risk_details` — converts severity and confidence into an explainable priority.
2. `case_id` — hashes stable alert properties into a repeatable identifier; it is an identifier, not a security signature.
3. `incident_records` — creates one visible case per alert without filtering P4.
4. `markdown_report` — produces a shift-readable queue with required follow-up.
5. `main` — writes alerts, structured cases, and the report as separate artifacts.

Ask about any line and we can trace the input, decision, and output together.
