# Executable alert system: detailed guide

## What the application does

Argus is a local defensive engineering lab with one web control plane. It does not replace an enterprise SIEM, EDR, message queue, data lake, case platform, IAM system, or SOAR approval system.

Its pipeline is:

1. **Acquire:** read local Defender alerts or retrieve read-only alerts from Defender for Endpoint, CrowdStrike, or SentinelOne.
2. **Preserve:** retain the original vendor payload inside the normalized record.
3. **Normalize:** map timestamp, source, vendor ID, title, severity, status, host, user, ATT&CK identifiers and raw evidence.
4. **Catalogue:** download the official Sigma repository and preserve all rule fields in JSON.
5. **Filter:** select rules applicable to Windows 11, Windows Server, Linux Mint, Ubuntu, or Ubuntu Server.
6. **Validate:** accept a rule as locally executable only if its detection uses the documented evaluator subset.
7. **Execute:** apply validated rules to normalized JSON events; a match retains the triggering event and five linked response codes.
8. **Correlate:** join EDR alerts to identity, email, firewall/network, cloud, VPN or badge activity inside a bounded window when a user, host or IP also matches.
9. **Prioritize:** separate severity (potential impact) from confidence (strength of evidence) and create visible cases.
10. **Respond:** display five environment-specific response workflows with inspection, system impact, approval, verification and rollback guidance. Commands never execute automatically.
11. **Retain:** keep normalized alerts and correlations longer, accept raw endpoint telemetry only from an explicit critical-host allowlist, and purge expired data.

## Why there were originally 19 alerts

`workready_siem.py` contains 19 hand-written analytics. These demonstrate stateful authentication/network/DNS correlation and stateless endpoint checks. They are directly readable teaching rules, but they are not intended to represent complete platform coverage.

The new declarative layer adds scale without pretending every Sigma feature is supported. `executable_rule_builder.py` asks for 100 validated rules for each target:

- Windows 11: 100 alerts and 500 environment-specific responses.
- Windows Server: 100 alerts and 500 server-aware responses.
- Ubuntu: 100 alerts and 500 Linux responses.

If the current Sigma export does not contain 100 compatible rules for a target, the build fails with the real validated count. It never generates meaningless duplicates to satisfy the requirement.

## Supported local rule syntax

`declarative_engine.py` supports:

- case-insensitive direct and dotted-field lookup;
- exact equality and `*`/`?` wildcards;
- `contains`, `startswith`, `endswith`, `exists`, `all`, and `windash` modifiers;
- mapping selections and lists of mappings/keywords;
- `and`, `or`, `not`, and parentheses;
- `1 of selection_*`, `all of filter_*`, `1 of them`, and `all of them`.

It rejects regular expressions, aggregations, event-count thresholds, correlation rules, unsupported modifiers and unknown selections. Regular expressions are excluded because Python's standard engine has no timeout and unsafe patterns can cause CPU denial of service. Those rules remain searchable catalogue entries but are not added to the executable count.

This supported subset matters because Sigma is a detection interchange specification, not a universal event-execution runtime. Field mappings and log sources must still match the normalized input.

## Building the 100-rule targets

In the web interface:

1. Open **Sigma catalogue**.
2. Choose the environment and refresh/build the catalogue.
3. Open **100-rule builds**.
4. Build Windows 11, Windows Server, and Ubuntu separately.
5. Review `data/executable/<environment>_rejected_rules.json` instead of ignoring unsupported rules.

Each successful target produces:

- `<environment>_executable_rules.json` — exactly 100 validated detection definitions;
- `<environment>_executable_solutions.json` — exactly 500 linked response workflows;
- `<environment>_rejected_rules.json` — exclusions and their reasons.

## Creating a custom alert

Open **Create alert** and provide:

- title and description;
- operating system;
- severity and event category;
- detection JSON using the supported syntax;
- exactly five non-empty response descriptions.

The backend validates the detection before saving it. Codes use independent OS namespaces:

- `USR-W11-00001` — Windows 11;
- `USR-WSV-00001` — Windows Server;
- `USR-LMT-00001` — Linux Mint;
- `USR-UBU-00001` — Ubuntu;
- `USR-UBS-00001` — Ubuntu Server.

The allocator scans the existing store and increments until it finds an unused code. Saving uses a temporary file followed by replacement to reduce partial-write risk. Every custom response receives a derivative code such as `USR-UBU-00001-UBUNTU-S01` and remains `auto_execute: false`.

## Example detection

```json
{
  "selection": {
    "Image|endswith": "powershell.exe",
    "CommandLine|contains": "-enc"
  },
  "approved_parent": {
    "ParentImage|endswith": "approved-agent.exe"
  },
  "condition": "selection and not approved_parent"
}
```

The rule matches only when both fields in `selection` match and the approved-parent filter does not match. The field names must exist in the incoming normalized event. A detection that expects `Image` cannot match an event that only supplies `process.executable` unless the parser maps or duplicates that field.

## Files to study in order

1. `declarative_engine.py` — field matching, modifiers and Boolean parsing.
2. `executable_rule_builder.py` — validation, minimum count and response selection.
3. `custom_rule_store.py` — code allocation, validation and atomic saving.
4. `sigma_catalog_builder.py` — OS filtering and response command generation.
5. `vendor_connectors.py` — read-only vendor acquisition and normalization.
6. `cross_source_siem.py` — storage gate and cross-source correlation.
7. `siem_app.py` — one web API coordinating all subsystems.
8. `ui/index.html` — the local administrative interface.

## Production limitations

- The local web service has no multi-user login or RBAC and must remain bound to `127.0.0.1`.
- SQLite is a learning store, not an enterprise-scale event platform.
- Custom rules need peer review, unit tests, benign and malicious validation datasets, ownership, versioning, tuning and deployment approval.
- Sigma field mappings differ by collector and SIEM backend.
- Response commands are examples requiring exact placeholders, privileges, maintenance authority, evidence preservation and rollback preparation.
- API connectors require tenant-specific test validation, rate-limit handling, monitoring and managed secret storage.
- A production system needs durable queues, idempotent checkpoints, high availability, encryption, backups, RBAC, audit trails, case workflows, privacy controls and operational metrics.
