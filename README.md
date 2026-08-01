# EDRRR — secure local SIEM portfolio edition

This repository is a sanitized, tested portfolio edition. Start with
[PORTFOLIO.md](PORTFOLIO.md) for the architecture, demonstrated capabilities,
security boundaries and validation commands. Read [SECURITY.md](SECURITY.md)
before importing any data or configuring an EDR connector.

This project teaches the core SIEM pipeline: **collect → parse → normalize → enrich → detect → alert → investigate**. It processes exported events; it does not install an endpoint agent or silently monitor a machine.

## One-command unified application

After installing the listed dependencies once, start the complete local interface with one command:

```powershell
python siem_app.py
```

Or from PowerShell:

```powershell
.\start-siem.ps1
```

On Ubuntu/Mint:

```bash
bash start-siem.sh
```

The browser opens at `http://127.0.0.1:8765`. Stop any older `connector_setup.py` process first because the unified application replaces it and uses the same local port.

If Sigma catalogue building fails:

1. Stop the app.
2. Run `python -m pip install -r requirements.txt` to install PyYAML.
3. Restart with `python siem_app.py`.
4. Open **Stored data** and select **Download and load all alerts + solutions**.

The downloader tries Git first and falls back to the official SigmaHQ branch snapshot. Snapshot extraction rejects traversal paths and oversized archives. YAML dates and other non-native JSON scalar objects are converted to text, empty exports are rejected, provenance is written to `.sigma-source.json`, and the previous working JSON is preserved if conversion fails.

The unified interface provides:

- live, non-hard-coded counts;
- secure EDR connector setup and testing;
- EDR import, catalogue candidate matching, storage, and correlation;
- Sigma synchronization, complete export, environment compilation, and five responses per rule;
- alert and response browsing;
- custom JSONL analysis and case creation;
- case and correlation browsing;
- retention and safety guidance.
- validated 100-alert executable builds for Windows 11, Windows Server, and Ubuntu;
- an in-app custom alert creator with automatic unused codes and five required responses.

Read `EXECUTABLE_RULE_GUIDE.md` for the complete architecture, supported rule syntax, build procedure, code-number allocation, limitations, and recommended source-reading order.

Read `SECURITY_REVIEW.md` before deployment. It documents fixed localhost, CSRF, SSRF, denial-of-service, sensitive-data, error-disclosure and auditability issues, confirms the absence of an intentional command-execution backdoor in the reviewed source, and lists architectural risks that remain unsuitable for production.

Counts distinguish unique alert IDs from environment deployments. A Sigma rule applicable to both Windows 11 and Windows Server is one unique definition but two deployments. Its response workflows are counted separately because their environment-specific commands and safety controls differ.

The advanced lab is `workready_siem.py`. It is deliberately more demanding than a single-rule demo, but it remains a learning correlation engine—not a replacement for the durable storage, access control, high availability, ingestion guarantees, case management, and audited deployment process of a production SIEM.

## Start

```powershell
python workready_siem.py advanced_sample_events.jsonl --environment windows_11 --config siem_config.json --output alerts.json --cases incident_cases.json --report incident_report.md --dashboard incident_dashboard.html --solutions solutions_catalog.json
python -m unittest -v test_workready_siem.py
python app.py analyze sample_events.jsonl --normalized normalized.json
python -m pip install -r requirements.txt
python app.py sigma-sync sigma
python app.py sigma-export sigma --output sigma-all-rules.json
python sigma_catalog_builder.py sigma-all-rules.json
```

When `--environment` is omitted, the catalogue builder asks the operator to choose `windows_11`, `linux_mint`, or `ubuntu`. For unattended use, pass it explicitly:

```powershell
python sigma_catalog_builder.py sigma-all-rules.json --environment windows_11
python sigma_catalog_builder.py sigma-all-rules.json --environment linux_mint
python sigma_catalog_builder.py sigma-all-rules.json --environment ubuntu
python sigma_catalog_builder.py sigma-all-rules.json --environment windows_server
python sigma_catalog_builder.py sigma-all-rules.json --environment ubuntu_server
```

It writes `environment_alerts.jsonl` and `environment_solutions.jsonl`. Each applicable Sigma rule becomes one stable alert definition, and each alert receives exactly five coded response workflows for the selected environment. The program prints the real counts. Five thousand solutions require at least 1,000 applicable source rules; the compiler never invents duplicate rules to reach the target.

The command catalogue is advisory. It does not execute commands. PowerShell containment examples use `-WhatIf` where supported. Bash lacks a universal preview switch, so every `sudo`, process signal, file move, account lock, or firewall change requires explicit review, authorization, placeholder expansion, dependency assessment, and rollback readiness.

## Endpoint-security connectors

`vendor_connectors.py` imports alerts read-only, retains the raw vendor record, normalizes common fields, and ranks candidate matches from the environment-specific alert catalogue. It never changes alert status or initiates vendor containment.

### Local connector setup screen

Install connector dependencies and start the localhost-only setup service:

```powershell
python -m pip install -r requirements-connectors.txt
python connector_setup.py
```

Open `http://127.0.0.1:8765`, choose the environment and EDR, enter the API details, and select **Test and save securely**. The page:

- binds only to the loopback interface;
- uses a per-run anti-CSRF token;
- sends `Cache-Control: no-store`;
- does not log requests;
- stores secret and connector values in the operating-system credential store through Python Keyring;
- writes only profile name, source, environment, and test time to `connector_profiles.json`;
- restores the previous credential values if connection testing fails.

Use a saved named profile with `--profile`, for example:

```powershell
python vendor_connectors.py --source crowdstrike --profile production-readonly --environment windows_server --catalog environment_alerts.jsonl
```

The local page is an administrative convenience, not a multi-user secrets platform. Production deployments should use the organization's managed secret store, authenticated administration, TLS, RBAC, audit logging, and connector workers isolated from the public web tier.

Install the optional Falcon connector dependency:

```powershell
python -m pip install -r requirements-connectors.txt
```

### Local Microsoft Defender Antivirus

Run on the Windows endpoint in a PowerShell session that can read the Defender Operational channel:

```powershell
python vendor_connectors.py --source local_defender --environment windows_11 --catalog environment_alerts.jsonl --hours 24
```

This uses `Get-WinEvent` against `Microsoft-Windows-Windows Defender/Operational`. It is local and read-only; it is not the Defender for Endpoint cloud API.

### Microsoft Defender for Endpoint

Create an application with the minimum read permission needed for the alerts API (normally `Alert.Read.All`, subject to the tenant's current API/role model), grant admin consent, and expose credentials only to the process:

```powershell
$env:MDE_TENANT_ID = '<tenant-id>'
$env:MDE_CLIENT_ID = '<application-id>'
$env:MDE_CLIENT_SECRET = '<secret-from-protected-store>'
python vendor_connectors.py --source mde --environment windows_server --catalog environment_alerts.jsonl --hours 24
```

Do not put the secret in source files, JSON configuration, command history, screenshots, or logs. Production should retrieve it from a managed secret store and rotate it.

### CrowdStrike Falcon

Create a Falcon API client with `Alerts: READ`; do not grant write or Real Time Response scopes to this importer:

```powershell
$env:FALCON_CLIENT_ID = '<client-id>'
$env:FALCON_CLIENT_SECRET = '<secret-from-protected-store>'
$env:FALCON_BASE_URL = 'https://api.crowdstrike.com'
python vendor_connectors.py --source crowdstrike --environment ubuntu_server --catalog environment_alerts.jsonl --hours 24
```

Set the correct regional Falcon base URL for the tenant. The connector uses FalconPy's combined Alerts endpoint and follows its `after` pagination token.

### SentinelOne Singularity

Use a read-only API token and the exact tenant console URL. API availability, RBAC, paths, and payloads can differ by Singularity release and tenant configuration, so the threats path is configurable:

```powershell
$env:S1_CONSOLE_URL = 'https://your-console.example'
$env:S1_API_TOKEN = '<read-only-token-from-protected-store>'
$env:S1_THREATS_PATH = '/web/api/v2.1/threats'
python vendor_connectors.py --source sentinelone --environment linux_mint --catalog environment_alerts.jsonl --hours 24
```

Validate the path against the API documentation built into the specific SentinelOne management console before use.

### Matching semantics

The matcher ranks up to five catalogue candidates using ATT&CK technique overlap and normalized title/description similarity. Output says `match_type: candidate`, includes a score and reasons, and preserves linked solution codes. It does not claim that a Sigma rule fired merely because a vendor alert resembles it. Exact correlation should additionally use vendor-native technique fields, observable values, process/file/network entities, timestamps, device identity, and the original Sigma detection condition.

Run offline tests:

```powershell
python -m unittest -v test_sigma_catalog_builder.py test_vendor_connectors.py
```

## Cross-source “chief investigator” correlation

`cross_source_siem.py` accepts normalized JSONL from EDR, identity, email, firewall/network, cloud, VPN, and badge sources. It correlates an EDR alert with non-EDR activity inside a configurable time window only when at least one entity also matches: host, user, source IP, destination IP, or a cross-direction IP relationship. Time proximity alone never creates a correlation.

Example:

```powershell
python cross_source_siem.py cross_source_sample.jsonl `
  --database siem_events.db `
  --window-minutes 5 `
  --critical-host dc01 `
  --critical-host payments-ubuntu-01 `
  --output correlations.json
```

The learning store uses SQLite with WAL mode and indexes on time, user, IP, and host. Default retention is:

- normalized alerts: 365 days;
- correlations: 730 days;
- raw telemetry from explicitly allowlisted critical hosts: 30 days;
- raw telemetry from all other hosts: rejected at ingestion.

These defaults demonstrate filtering and lifecycle controls; they are not universal compliance requirements. A real organization must set retention using legal, privacy, investigation, capacity, and contractual requirements. At enterprise scale, replace SQLite with durable queues, partitioned storage, access control, encryption, backups, replication, ingestion-lag monitoring, and tested recovery.

Run the correlation tests:

```powershell
python -m unittest -v test_cross_source_siem.py
```

## Server-specific response commands

`sigma_catalog_builder.py` now uses distinct overrides for `windows_server` and `ubuntu_server`:

- Windows Server checks services associated with a PID, established connections, scheduled-task/service account dependencies, cluster state where available, and firewall/management impact. Destructive examples remain `-WhatIf` previews.
- Ubuntu Server checks systemd reverse dependencies, unit restart behavior, listeners, SSH status, routes, journals, active sessions, and nftables state. Service stops and firewall changes explicitly require failover and remote-access validation.

Every generated server solution includes a `server_safety` instruction covering service role, failover, remote management, dependencies, active transactions, recovery ownership, and maintenance authority.

Open `workready_siem.py` beside the chat for the guided course. The major sections are: helpers, event schema, alert schema, configuration, engine state, event routing, endpoint analytics, identity analytics, network/DNS analytics, loading, and the command-line entry point.

## Advanced event contract

Every JSON Lines record requires `timestamp`, `event_type`, and `host`. `user` and `source` are strongly recommended. Type-specific evidence stays as additional fields.

Supported `event_type` values:

| Type | Key evidence | Example sources |
|---|---|---|
| `process` | executable, parent, command line, PID/GUID | Sysmon 1, Security 4688, Auditd exec |
| `process_access` | source/target process, access mask | Sysmon 10, EDR |
| `api_call` | source/target process, API | EDR/API telemetry |
| `file` | path, action, hash, writing process | Sysmon 11/23/26, FIM, EDR |
| `registry` | key, value, action, writing process | Sysmon 12/13/14, EDR |
| `authentication` | outcome, source IP, logon type, device, MFA | Windows 4624/4625, IdP |
| `group_change` | actor, target member, group, action | Windows 4728/4732/4756, IAM |
| `network` | source/destination, port, bytes, process | firewall, proxy, NetFlow, EDR |
| `dns` | query, record type, response, process | DNS server, resolver, EDR |

The engine expects normalized, timestamp-ordered JSONL. A production pipeline would give every event a stable ID, tenant, ingestion timestamp, schema version, parser version, and data-quality status, then store raw evidence immutably.

## Incident visibility and follow-up

Every alert produces two reporting artifacts:

- `incident_cases.json` is the structured case queue. Each case has a stable ID, status, owner, disposition, transparent risk score, response target, original alert, notes, and audit history.
- `incident_report.md` is the readable shift report. It includes every priority, including P4, and gives analysts explicit follow-up checkboxes.
- `solutions_catalog.json` relates every alert rule ID to exactly five coded response choices. For example, `CRED-001` maps to `CRED-001-S01` through `CRED-001-S05`.
- `incident_dashboard.html` is the read-only front end. Every detected case automatically displays its five matching solutions, security benefit, operational risk, usage criteria, approval requirement, and rollback plan.

Response codes are references, not executable commands. The dashboard deliberately has no “isolate,” “disable,” or “delete” button: containment remains a human-authorized action after evidence and dependency review.

The main SIEM also prompts for the monitored environment when `--environment` is omitted. The selected value is recorded in every case and displayed in the dashboard. Automated runs should always pass the environment explicitly so they never wait for interactive input.

The score combines potential impact (65%) and confidence (35%) to prioritize work. It must never be used as proof that activity is malicious. A low score means the available evidence supports a slower review target; it does not authorize silently deleting or suppressing the record.

Case lifecycle: `NEW` → `IN REVIEW` → `ESCALATED` or `CLOSED`. Closure requires a documented disposition (`TRUE POSITIVE`, `BENIGN POSITIVE`, `FALSE POSITIVE`, or `DATA-QUALITY ISSUE`), evidence reviewed, analyst identity, timestamps, and rationale. A production case-management platform should enforce these transitions and append-only audit history.

## Detection coverage

- Parent-child anomalies and execution from temporary paths
- Injection-related API calls and LSASS memory access
- Critical-path file changes and temporary executable creation
- Run/RunOnce-style registry persistence
- Failed logins followed by success, unusual hours, unexpected country/device, and interactive service-account use
- Privileged-group membership additions
- Regular outbound beacon-like timing, large outbound transfers, and workstation lateral protocols
- High-volume, long, high-entropy DNS labels

Thresholds are configuration, not universal truth. Establish them from historical telemetry, segment them by asset/user role, measure alert volume and precision, document exceptions, and periodically retest them.

## Production gaps to understand

- API names are usually EDR telemetry; Sysmon does not log every injection API call.
- Sysmon Event 10 shows process access, but access masks and call traces require careful product/version-specific interpretation.
- Geo anomalies require a maintained IP-geolocation source and VPN/proxy awareness.
- “New device” requires identity history; an empty baseline is not evidence of anomaly.
- Beacon detection needs enough time and connections; legitimate updaters also beacon regularly.
- Byte volume alone cannot prove exfiltration; direction, protocol, asset role, historical baseline, and data sensitivity matter.
- DNS entropy is a heuristic. CDNs, security products, and tracking domains can resemble tunnelling.
- Internal IP detection and registrable-domain extraction need enterprise network ranges and a Public Suffix List in production.

`sigma-sync` downloads the official `SigmaHQ/sigma` repository. `sigma-export` reads every `.yml` and `.yaml` document recursively—not only process-creation rules—and writes one JSON array containing each complete Sigma rule. It preserves detection logic, metadata, log source, tags, status, references, false positives, and other fields. An `_export` object adds the source filename, document number, and repository URL.

The resulting `sigma-all-rules.json` is a lossless catalogue, but it is not automatically a deployable rule package for every SIEM. Elastic, Splunk, Microsoft Sentinel, QRadar, and other platforms use different query languages, field mappings, APIs, and import formats. Production conversion should use pySigma and the backend for the chosen SIEM.

## Mechanics in operational terms

- A process asks the operating system to create another process. The creator is the **parent** and the new process is the **child**.
- `PID` identifies a currently running process, but the OS can reuse it later. `PPID` records the creator's PID.
- Correlate by host and time. Prefer Sysmon `ProcessGuid`, or an EDR entity ID, because a bare `(PID, PPID)` pair can become ambiguous.
- Windows Security Event 4688 needs Audit Process Creation. Command-line collection is a separate policy and can contain secrets, so access and retention need care.
- Sysmon Event 1 commonly provides image paths, command lines, hashes, parent fields, and GUIDs.
- Linux `auditd` may split one execution across `SYSCALL`, `EXECVE`, and related records sharing a serial/event ID. A production parser must join those records before normalization.

## What an analyst does with an alert

1. Validate the event source and timestamp.
2. Inspect the full command line, signer/hash reputation, user, integrity level, and executable path.
3. Walk backward to the parent and forward to siblings/children.
4. Compare against the host role and known software deployment activity.
5. Search the same hash, command line, user, domain, or destination across other hosts.
6. Record the evidence and disposition: true positive, benign positive, or data-quality problem.

Parent-child rules are clues, not verdicts. Office can legitimately launch helpers, and security products can create unusual ancestry. Tune exceptions narrowly using verified signer, path, hash, host role, and command-line context.

See `LEARNING_GUIDE.md` for a source walkthrough.
