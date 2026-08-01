# Work-ready SIEM study path

Keep `workready_siem.py` open in the right pane and use this sequence. Ask about any visible line number; line numbers may shift as we improve the code, so include the line text when possible.

## 1. Data engineering foundations

Study `utc`, `leaf`, `entropy`, and `private_ip`. You should be able to explain why timestamps need a timezone, why Windows paths need normalization, why entropy is only a heuristic, and why parsing should fail visibly when required fields are absent.

Then study `Event.from_dict`. Trace one line from `advanced_sample_events.jsonl` through JSON parsing into an `Event`. Identify envelope fields versus type-specific `details` and preserved `raw` evidence.

Exercise: add an `event_id` and `ingested_at` field without losing backward compatibility.

## 2. Detection engineering foundations

Study `Alert` and `DetectionEngine.alert`. Distinguish:

- Severity: potential business/technical impact if the behavior is malicious.
- Confidence: strength and specificity of the available evidence.
- ATT&CK mapping: behavioral classification, not proof or severity.
- Evidence: what caused the match.
- Investigation: next evidence to collect.

Exercise: add an `analytic_version` and a list of `data_sources` to every alert.

## 3. Stateless endpoint rules

Study `process_event`, `process_access`, `file_event`, and `registry_event`. These evaluate one event at a time. For every `if`, state:

1. Required telemetry.
2. Boolean condition.
3. Expected false positives.
4. Evidence needed for disposition.
5. Narrow tuning keys that preserve malicious coverage.

Exercise: add a rule for `rundll32.exe` loading a DLL from a user-writable directory. Do not alert on the filename alone.

## 4. Stateful identity correlation

Study `authentication`. The `deque` stores failures temporarily. The loop removes failures outside the configured window. A subsequent success can then correlate with the remaining failures.

Understand why grouping by `host|user|source_ip` answers a different question from grouping only by user or only by source IP. Password spraying commonly requires a separate analytic grouped by source IP across many users.

Exercise: implement password spraying using distinct failed usernames per source IP.

## 5. Network statistics

Study `network`. Beaconing uses intervals between consecutive connections, their mean, and relative jitter. Low jitter is suggestive but not malicious by itself. Exfiltration uses a volume threshold, while lateral movement combines internal addressing, protocol port, and source-host role.

Exercise: replace the single exfiltration event threshold with cumulative bytes per `(host, destination)` over one hour.

## 6. DNS analytics

Study `dns` and `entropy`. The analytic requires both volume and an encoded-looking label to improve specificity. Production code should use the Public Suffix List instead of guessing that the final two labels form the registered domain.

Exercise: add unique-subdomain ratio and TXT-query frequency, then test legitimate CDN-like names.

## 7. Validation and operations

Study `test_workready_siem.py`. Tests should cover matches, non-matches, threshold boundaries, time-window expiry, malformed input, and common benign cases. A detection is not finished when it matches one malicious sample; it needs documented data requirements, validation datasets, tuning, versioning, monitoring, and an owner.

For a real deployment, add:

- Sensor deployment and health monitoring
- Source-specific parsers and schema validation
- Durable queues and storage
- Role-based access and audit trails
- Secrets handling and encryption
- Deduplication, suppression, risk scoring, and cases
- Detection-as-code review and CI
- Metrics: event lag, parser failure, rule executions, alert volume, precision, and time to disposition
- Retention, privacy, and legal controls

## Interview-level explanation

“I built a stateful Python detection lab using a normalized event envelope. It correlates bounded authentication, network, and DNS histories and also evaluates stateless endpoint behaviors. Alerts separate severity from confidence, preserve raw evidence, map to ATT&CK, and provide investigation guidance. I understand that real deployment additionally needs source-specific parsing, enrichment, durable state, field mappings, tuning, RBAC, case management, and operational monitoring.”
