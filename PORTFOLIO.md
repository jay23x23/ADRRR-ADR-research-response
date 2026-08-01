# EDRRR — EDR Research and Response

EDRRR is a local defensive-security portfolio project that demonstrates the
workflow from telemetry ingestion to normalized events, behavioural detections,
Sigma-subset evaluation, incident Cases and human-approved response guidance.

## Demonstrated capabilities

- Imports normalized JSONL, Windows XML/EVTX where platform tooling is available,
  Linux audit/auth logs and constrained ZIP uploads.
- Normalizes process, parent process, authentication, file, registry and network
  evidence into a common event shape.
- Evaluates built-in behavioural analytics and a deliberately limited executable
  Sigma subset.
- Imports Suricata, Wazuh and YARA alert results as Cases.
- Preserves unsupported Elastic, Sentinel and Splunk content as research-only,
  promoting only strict literal expressions the local evaluator can represent.
- Correlates endpoint, identity and network observations.
- Displays five response choices per catalogue alert, with benefits, risks,
  approvals, rollback and separate PowerShell/Bash copy controls.
- Never executes response commands automatically.

## Quick start

Windows:

```cmd
start-siem.cmd
```

Linux:

```bash
chmod +x start-siem.sh
./start-siem.sh
```

Open `http://127.0.0.1:8765/`. Use the included synthetic examples before
importing any other data.

## Portfolio data policy

The committed catalogue is a reduced demonstration set of 100 alerts per
environment. Runtime Cases, databases, imports, audit history and connector
profiles are excluded. The upstream Sigma repository is intentionally not
vendored; attribution and reproducible import functionality are retained.

## Engineering boundaries

This project demonstrates SIEM engineering concepts; it does not claim complete
Sigma compatibility, production-scale ingestion, autonomous containment,
certification or guaranteed detection coverage. A rule is marked executable only
after the local subset validator accepts its fields and condition syntax.

## Validation

Run:

```cmd
python portfolio_check.py
python -m unittest discover -v
```

The first command checks publication hygiene and critical security defaults. The
second exercises parsers, rule evaluation, connectors and response structures.

