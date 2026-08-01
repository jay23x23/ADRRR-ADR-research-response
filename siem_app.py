#!/usr/bin/env python3
"""One-command local SIEM web application."""

from __future__ import annotations

import json
import importlib.util
import hashlib
import os
import secrets
import sqlite3
import threading
import urllib.parse
import webbrowser
import zipfile
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from app import sync_sigma, write_sigma_json
from connector_setup import save as save_connector
from content_adapters import SUPPORTED_SOURCES as CONTENT_SOURCES, import_content
from custom_rule_store import create as create_custom_rule, load as load_custom_rules
from executable_rule_builder import TARGET_ENVIRONMENTS, build_executable, write_build
from external_executable_rules import load_promotable
from cross_source_siem import Store, UnifiedRecord, correlate
from declarative_engine import execute
from response_playbooks import DETECTABLE_RULE_IDS, recommendations, validate_playbooks
from raw_log_importer import import_file as import_raw_log_file
from security_controls import append_audit, public_error, redact
from sigma_catalog_builder import ENVIRONMENTS, compile_catalog, write_jsonl
from vendor_connectors import CrowdStrikeConnector, DefenderEndpointConnector, LocalDefenderConnector, LocalWindowsFirewallConnector, SentinelOneConnector, load_catalog, match_alert
from workready_siem import html_dashboard, incident_records, load_jsonl, markdown_report, run

ROOT = Path(__file__).resolve().parent
DATA, UI = ROOT / "data", ROOT / "ui"


def extract_uploaded_log_archive(archive: Path, source_type: str) -> str:
    """Safely extract exactly one compatible training/security log from a ZIP."""
    extensions = {"windows_evtx": {".evtx"}, "windows_xml": {".xml"},
                  "linux_audit": {".log", ".txt"}, "linux_auth": {".log", ".txt"},
                  "normalized_jsonl": {".jsonl", ".json"}}
    allowed = extensions.get(source_type, set())
    with zipfile.ZipFile(archive) as bundle:
        members = [item for item in bundle.infolist() if not item.is_dir()]
        if not members or len(members) > 20:
            raise ValueError("ZIP must contain between 1 and 20 files")
        if any(item.flag_bits & 1 for item in members):
            raise ValueError("Encrypted ZIP archives are not supported")
        if sum(item.file_size for item in members) > 100 * 1024 * 1024:
            raise ValueError("ZIP expands beyond the 100 MB limit")
        if any(item.compress_size and item.file_size / item.compress_size > 200 for item in members):
            raise ValueError("ZIP expansion ratio is unsafe")
        candidates = [item for item in members if Path(item.filename).suffix.lower() in allowed]
        if len(candidates) != 1:
            raise ValueError("ZIP must contain exactly one log compatible with the selected format")
        member = candidates[0]
        safe_member = Path(member.filename).name
        if not safe_member or safe_member in {".", ".."}:
            raise ValueError("ZIP contains an invalid log filename")
        extracted_name = safe_name(f"{archive.stem}-{safe_member}")
        destination = (RAW_LOGS / extracted_name).resolve()
        if destination.parent != RAW_LOGS.resolve():
            raise ValueError("ZIP extraction escaped the approved intake folder")
        temporary = destination.with_name(destination.name + ".extracting")
        with bundle.open(member) as source, temporary.open("wb") as target:
            remaining = member.file_size
            while remaining:
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk: break
                target.write(chunk); remaining -= len(chunk)
        if remaining:
            temporary.unlink(missing_ok=True)
            raise ValueError("ZIP member ended before its declared size")
        temporary.replace(destination)
        return extracted_name
CATALOGS, IMPORTS, OUTPUTS = DATA / "catalogs", DATA / "imports", DATA / "outputs"

BUILTIN_ALERT_TITLES = {
    "PROC-001": "Office spawned an interpreter", "PROC-002": "Web server spawned an interactive tool",
    "PROC-003": "Protected-name process has unexpected parent", "PROC-004": "User application launched a temporary executable",
    "MEM-001": "Potential process-injection API", "CRED-001": "Unapproved LSASS memory access",
    "FILE-001": "Critical path changed", "FILE-002": "Executable created in a temporary path",
    "REG-001": "Run-key persistence modified", "AUTH-001": "Failures followed by a successful login",
    "AUTH-002": "Login during unusual hours", "AUTH-003": "Login from an unexpected country",
    "AUTH-004": "Login from a new device", "AUTH-005": "Service account used interactively",
    "PRIV-001": "Member added to a privileged group", "NET-001": "Regular outbound connection pattern",
    "NET-002": "Large outbound transfer", "NET-003": "Workstation used a lateral-movement protocol",
    "DNS-001": "High-volume encoded-looking DNS queries",
}


def builtin_catalog(kind: str, environment: str) -> dict[str, Any]:
    """Always-available baseline; live EDR and Sigma enrich rather than unlock it."""
    alerts = [{
        "alert_rule_id": rule_id, "alert_code": rule_id, "title": BUILTIN_ALERT_TITLES[rule_id],
        "level": "high" if rule_id not in {"AUTH-002", "PROC-004", "NET-001", "NET-003"} else "medium",
        "environment": environment, "source": "EDRRR built-in behavioral analytics",
        "description": "Executable behavioral detection included with EDRRR; open a resulting case to review its evidence.",
        "solution_codes": [item["solution_code"] for item in recommendations(rule_id)],
    } for rule_id in sorted(BUILTIN_ALERT_TITLES)]
    solutions = [item for rule_id in sorted(BUILTIN_ALERT_TITLES) for item in recommendations(rule_id)]
    items = alerts if kind == "alerts" else solutions
    return {"total": len(items), "items": items, "catalogue_source": "built_in_baseline"}
DB_PATH, PROFILE_PATH = DATA / "siem_events.db", ROOT / "connector_profiles.json"
CUSTOM_RULES, EXECUTABLE = DATA / "custom_rules.json", DATA / "executable"
CONTENT_IMPORTS, CONTENT_CATALOG = DATA / "content_imports", DATA / "content_catalog"
OFFLINE_SIGMA = ROOT / "offline_sigma"
OFFLINE_ALERT_MASTER = DATA / "offline-alert-master.json"
OFFLINE_ALERT_SOLUTIONS = DATA / "alert-packs" / "complete-alerts-with-solutions.json"
RAW_LOGS = ROOT / "raw_logs"
HOST = "127.0.0.1"
try:
    PORT = int(os.environ.get("EDRRR_PORT", "8765"))
except ValueError as error:
    raise RuntimeError("EDRRR_PORT must be an integer between 1024 and 65535") from error
if not 1024 <= PORT <= 65535:
    raise RuntimeError("EDRRR_PORT must be between 1024 and 65535")
CSRF = secrets.token_urlsafe(32)
LOCK = threading.Lock()
AUDIT_PATH = DATA / "security-audit.jsonl"
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ALLOWED_ORIGINS = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
MAX_ANALYSIS_BYTES, MAX_ANALYSIS_EVENTS = 10_000_000, 10_000
for folder in (DATA, CATALOGS, IMPORTS, OUTPUTS, OFFLINE_SIGMA, RAW_LOGS, CONTENT_IMPORTS, CONTENT_CATALOG, EXECUTABLE):
    folder.mkdir(parents=True, exist_ok=True)


def jsonl_count(path: Path) -> int:
    return sum(bool(line.strip()) for line in path.read_text(encoding="utf-8-sig").splitlines()) if path.exists() else 0


def profiles() -> list[dict[str, Any]]:
    value = json.loads(PROFILE_PATH.read_text(encoding="utf-8")) if PROFILE_PATH.exists() else []
    return value if isinstance(value, list) else []


def db_counts() -> dict[str, int]:
    if not DB_PATH.exists():
        return {"stored_events": 0, "correlations": 0}
    connection = sqlite3.connect(DB_PATH)
    try:
        return {"stored_events": connection.execute("SELECT count(*) FROM events").fetchone()[0], "correlations": connection.execute("SELECT count(*) FROM correlations").fetchone()[0]}
    except sqlite3.DatabaseError:
        return {"stored_events": 0, "correlations": 0}
    finally:
        connection.close()


def status() -> dict[str, Any]:
    per_environment = {name: {"alerts": jsonl_count(CATALOGS / f"{name}_alerts.jsonl"), "responses": jsonl_count(CATALOGS / f"{name}_solutions.jsonl")} for name in ENVIRONMENTS}
    unique_sigma_ids: set[str] = set()
    for name in ENVIRONMENTS:
        path = CATALOGS / f"{name}_alerts.jsonl"
        if path.exists():
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                if line.strip():
                    unique_sigma_ids.add(str(json.loads(line).get("alert_rule_id")))
    custom_user_rules = load_custom_rules(CUSTOM_RULES)
    executable_counts = {name: len(json.loads((EXECUTABLE / f"{name}_executable_rules.json").read_text(encoding="utf-8"))) if (EXECUTABLE / f"{name}_executable_rules.json").exists() else 0 for name in TARGET_ENVIRONMENTS}
    return {
        "custom_alerts": len(DETECTABLE_RULE_IDS),
        "custom_responses": sum(len(recommendations(rule_id)) for rule_id in DETECTABLE_RULE_IDS),
        "generated_sigma_alerts": len(unique_sigma_ids),
        "generated_rule_deployments": sum(value["alerts"] for value in per_environment.values()),
        "generated_sigma_responses": sum(value["responses"] for value in per_environment.values()),
        "connector_profiles": len(profiles()), "environments": list(ENVIRONMENTS),
        "catalog_dependencies": {"pyyaml": importlib.util.find_spec("yaml") is not None, "sigma_json": (DATA / "sigma-all-rules.json").exists()},
        "user_created_alerts": len(custom_user_rules), "executable_per_target": executable_counts,
        "per_environment": per_environment, **db_counts(),
    }


def safe_name(value: str) -> str:
    if not value or any(not (char.isalnum() or char in "-_.") for char in value):
        raise ValueError("Invalid name")
    return value


def build_catalog(payload: dict[str, Any]) -> dict[str, Any]:
    if importlib.util.find_spec("yaml") is None:
        raise ValueError("PyYAML is missing. Stop the app, run: python -m pip install -r requirements.txt, then restart.")
    environment = payload["environment"]
    if environment not in ENVIRONMENTS:
        raise ValueError("Unsupported environment")
    sigma_root, sigma_json = ROOT / "sigma", DATA / "sigma-all-rules.json"
    if payload.get("refresh") or not sigma_json.exists():
        try: sigma_root = sync_sigma(sigma_root)
        except Exception as error: raise ValueError("Sigma download failed. Check internet access, TLS inspection/proxy policy, GitHub access, and available disk space.") from error
        try: write_sigma_json(sigma_root, sigma_json)
        except Exception as error: raise ValueError("Sigma YAML-to-JSON conversion failed. The previous JSON was preserved. Check PyYAML and the security audit log.") from error
    try: rules = json.loads(sigma_json.read_text(encoding="utf-8"))
    except Exception as error: raise ValueError("The saved Sigma JSON is missing or invalid; refresh the catalogue.") from error
    try: alerts, solutions = compile_catalog(rules, environment)
    except Exception as error: raise ValueError(f"Sigma environment compilation failed for {environment}.") from error
    write_jsonl(CATALOGS / f"{environment}_alerts.jsonl", alerts)
    write_jsonl(CATALOGS / f"{environment}_solutions.jsonl", solutions)
    (CATALOGS / f"{environment}_alerts.json").write_text(json.dumps(alerts, indent=2, default=str), encoding="utf-8")
    (CATALOGS / f"{environment}_solutions.json").write_text(json.dumps(solutions, indent=2, default=str), encoding="utf-8")
    return {"sigma_rules_read": len(rules), "applicable_alerts": len(alerts), "responses": len(solutions), "environment": environment}


def import_offline_sigma(payload: dict[str, Any]) -> dict[str, Any]:
    """Import a user-staged Sigma repository or JSON export without network access."""
    environment = str(payload.get("environment", ""))
    if environment not in ENVIRONMENTS:
        raise ValueError("Unsupported environment")
    source_name = str(payload.get("source", "sigma")).strip()
    if not source_name or Path(source_name).name != source_name or source_name in {".", ".."}:
        raise ValueError("Source must be one folder or JSON filename inside offline_sigma")
    source = (OFFLINE_SIGMA / source_name).resolve()
    if source.parent != OFFLINE_SIGMA.resolve():
        raise ValueError("Offline Sigma source escaped the approved import folder")
    if not source.exists():
        raise ValueError(f"Copy the Sigma repository or JSON export into offline_sigma/{source_name} first")
    sigma_json = DATA / "sigma-all-rules.json"
    if source.is_dir():
        imported = write_sigma_json(source, sigma_json)
        source_type = "sigma_repository"
    elif source.suffix.lower() == ".json":
        if source.stat().st_size > 300 * 1024 * 1024:
            raise ValueError("Offline Sigma JSON exceeds the 300 MB safety limit")
        rules = json.loads(source.read_text(encoding="utf-8-sig"))
        if not isinstance(rules, list) or not rules:
            raise ValueError("Offline Sigma JSON must contain a non-empty array of rule objects")
        rules = [rule for rule in rules if isinstance(rule, dict)]
        temporary = sigma_json.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(rules, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        temporary.replace(sigma_json)
        imported, source_type = len(rules), "sigma_json_export"
    else:
        raise ValueError("Offline source must be a Sigma repository folder or a .json export")
    result = build_catalog({"environment": environment, "refresh": False})
    return {"offline": True, "source": source_name, "source_type": source_type, "rules_imported": imported, **result}


def build_all_catalogs() -> dict[str, Any]:
    """Refresh Sigma once, compile all OS views, and persist browseable JSON arrays."""
    if importlib.util.find_spec("yaml") is None:
        raise ValueError("PyYAML is missing. Stop the app, run: python -m pip install -r requirements.txt, then restart.")
    sigma_root, sigma_json = ROOT / "sigma", DATA / "sigma-all-rules.json"
    try: sigma_root = sync_sigma(sigma_root)
    except Exception as error: raise ValueError("Sigma download failed. Check internet access, TLS inspection/proxy policy, GitHub access, and available disk space.") from error
    try: exported = write_sigma_json(sigma_root, sigma_json)
    except Exception as error: raise ValueError("Sigma YAML-to-JSON conversion failed. The previous JSON was preserved. Check PyYAML and the security audit log.") from error
    try: rules = json.loads(sigma_json.read_text(encoding="utf-8"))
    except Exception as error: raise ValueError("The generated Sigma JSON could not be read back safely.") from error
    summary, combined = {}, {"schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(), "environments": {}}
    for environment in ENVIRONMENTS:
        alerts, solutions = compile_catalog(rules, environment)
        write_jsonl(CATALOGS / f"{environment}_alerts.jsonl", alerts)
        write_jsonl(CATALOGS / f"{environment}_solutions.jsonl", solutions)
        (CATALOGS / f"{environment}_alerts.json").write_text(json.dumps(alerts, indent=2, default=str), encoding="utf-8")
        (CATALOGS / f"{environment}_solutions.json").write_text(json.dumps(solutions, indent=2, default=str), encoding="utf-8")
        combined["environments"][environment] = {"alerts": alerts, "solutions": solutions}
        summary[environment] = {"alerts": len(alerts), "solutions": len(solutions)}
    combined_path = DATA / "alerts-and-solutions.json"
    combined_path.write_text(json.dumps(combined, indent=2, default=str), encoding="utf-8")
    return {"sigma_rules_exported": exported, "environments": summary, "combined_json": str(combined_path.relative_to(ROOT))}


def build_executable_catalog(payload: dict[str, Any]) -> dict[str, Any]:
    environment = payload["environment"]
    if environment not in TARGET_ENVIRONMENTS: raise ValueError("Executable target must be windows_11, windows_server, or ubuntu")
    sigma_json = DATA / "sigma-all-rules.json"
    if not sigma_json.exists(): raise ValueError("Build/refresh the Sigma catalogue first")
    rules = json.loads(sigma_json.read_text(encoding="utf-8"))
    external_rules, external_rejected = load_promotable(CONTENT_CATALOG)
    rules.extend(external_rules)
    executable, solutions, rejected = build_executable(rules, environment, 100)
    rejected.extend(external_rejected)
    result = write_build(EXECUTABLE, environment, executable, solutions, rejected)
    result.update({
        "purpose": "Compile catalogue definitions into rules EDRRR can execute against later log imports.",
        "input_catalogue": str(sigma_json.relative_to(ROOT)),
        "sigma_rules_considered": len(rules),
        "external_rules_promoted": len(external_rules),
        "external_rules_rejected": len(external_rejected),
        "source_libraries": sorted({str(item.get("_export", {}).get("source_library", "sigma")) for item in rules}),
        "built_rule_preview": [
            {"alert_code": item.get("alert_rule_id"), "title": item.get("title"),
             "severity": item.get("level"), "logsource": item.get("logsource"),
             "source_file": item.get("source_file")}
            for item in executable[:20]
        ],
        "rejected_preview": rejected[:10],
        "output_files": {
            "rules": f"data/executable/{environment}_executable_rules.json",
            "responses": f"data/executable/{environment}_executable_solutions.json",
            "rejected": f"data/executable/{environment}_rejected_rules.json",
        },
        "next_step": "Open Import system logs and upload a compatible log. The result field declarative_alerts reports matches from this build.",
        "file_selector_explanation": "No file selector is shown here because this screen builds detectors from the saved Sigma catalogue; log files are selected on Import system logs.",
    })
    return result


def connector(source: str, profile: str):
    if source == "local_defender":
        return LocalDefenderConnector()
    if source == "local_windows_firewall":
        return LocalWindowsFirewallConnector()
    classes = {"mde": DefenderEndpointConnector, "crowdstrike": CrowdStrikeConnector, "sentinelone": SentinelOneConnector}
    if source not in classes:
        raise ValueError("Unsupported connector")
    return classes[source](safe_name(profile))


def import_vendor(payload: dict[str, Any]) -> dict[str, Any]:
    environment, source = payload["environment"], payload["source"]
    if environment not in ENVIRONMENTS:
        raise ValueError("Unsupported environment")
    catalog_path = CATALOGS / f"{environment}_alerts.jsonl"
    hours = max(1, min(int(payload.get("hours", 24)), 720))
    alerts = connector(source, payload.get("profile", "default")).fetch(datetime.now(timezone.utc) - timedelta(hours=hours))
    # Vendor ingestion must remain useful even when Sigma is unavailable. In
    # that case the incident receives five generic, human-approved triage and
    # containment responses; Sigma enrichment is added whenever a catalogue exists.
    catalog = load_catalog(catalog_path) if catalog_path.exists() else []
    rows = [{"environment": environment, "vendor_alert": asdict(alert), "candidate_rule_matches": match_alert(alert, catalog)} for alert in alerts]
    solutions_path = CATALOGS / f"{environment}_solutions.jsonl"
    solution_items = load_catalog(solutions_path) if solutions_path.exists() else []
    solution_index = {item["solution_code"]: item for item in solution_items}
    vendor_cases = []
    for row in rows:
        vendor = row["vendor_alert"]
        matches = row["candidate_rule_matches"]
        codes = matches[0].get("solution_codes", []) if matches else []
        attached = [solution_index[code] for code in codes if code in solution_index]
        vendor_identity = f"{vendor['source']}|{vendor['vendor_alert_id']}|{vendor['timestamp']}"
        if not attached:
            attached = recommendations("VENDOR-" + hashlib.sha256(vendor_identity.encode()).hexdigest()[:10].upper())
        vendor_cases.append({
            "case_id": "VCASE-" + hashlib.sha256(vendor_identity.encode()).hexdigest()[:12].upper(),
            "status": "NEW - ANALYST REVIEW REQUIRED", "owner": "UNASSIGNED", "disposition": "UNDETERMINED",
            "environment": environment, "vendor_alert": vendor, "candidate_rule_matches": matches,
            "recommended_solutions": attached,
            "response_status": "catalogue_matched" if codes else "generic_safe_triage",
            "warning": "Candidate matching is not proof that the Sigma rule fired. Validate the vendor evidence before using a response command.",
        })
    name = f"{safe_name(source)}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
    safe_rows = redact(rows)
    (IMPORTS / name).write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in safe_rows), encoding="utf-8")
    (OUTPUTS / "vendor_cases.json").write_text(json.dumps(redact(vendor_cases), indent=2, default=str), encoding="utf-8")
    with Store(DB_PATH) as store:
        accepted, dropped = store.ingest([UnifiedRecord.from_dict(row) for row in safe_rows], set())
        correlations = correlate(store.recent(24), 5)
        store.save_correlations(correlations)
    return {"imported": len(rows), "stored": accepted, "dropped": dropped, "candidate_matches": sum(len(row["candidate_rule_matches"]) for row in rows), "cases_with_responses": sum(bool(item["recommended_solutions"]) for item in vendor_cases), "correlations": len(correlations), "file": name}


def analyze_path(environment: str, path: Path) -> dict[str, Any]:
    try:
        events = load_jsonl(path)
        raw_events = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    except json.JSONDecodeError as error:
        raise ValueError(f"Normalized event parsing failed at line {error.lineno}, column {error.colno}: {error.msg}") from error
    if len(raw_events) > MAX_ANALYSIS_EVENTS: raise ValueError("Analysis input exceeds the 10,000-event limit")
    config_path = ROOT / "siem_config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    except json.JSONDecodeError as error:
        raise ValueError(f"SIEM configuration JSON is invalid at line {error.lineno}: {error.msg}") from error
    alerts = run(events, config)
    executable_path = EXECUTABLE / f"{environment}_executable_rules.json"
    try:
        declarative_rules = json.loads(executable_path.read_text(encoding="utf-8")) if executable_path.exists() else []
    except json.JSONDecodeError as error:
        raise ValueError(f"Executable rule build is invalid JSON at line {error.lineno}: {error.msg}; rebuild this environment") from error
    declarative_rules.extend(rule for rule in load_custom_rules(CUSTOM_RULES) if rule.get("environment") == environment)
    declarative_matches = execute(declarative_rules, raw_events)
    cases = incident_records(alerts, environment)
    executable_solutions_path = EXECUTABLE / f"{environment}_executable_solutions.json"
    try:
        executable_solutions = json.loads(executable_solutions_path.read_text(encoding="utf-8")) if executable_solutions_path.exists() else []
    except json.JSONDecodeError as error:
        raise ValueError(f"Executable response build is invalid JSON at line {error.lineno}: {error.msg}; rebuild this environment") from error
    executable_solution_index = {item.get("solution_code"): item for item in executable_solutions if item.get("solution_code")}
    for match in declarative_matches:
        evidence = match.event
        identity = f"{match.alert_rule_id}|{evidence.get('host', 'unknown')}|{evidence.get('timestamp', '')}|{json.dumps(evidence, sort_keys=True, default=str)}"
        attached = []
        for code in match.solution_codes:
            if code not in executable_solution_index:
                continue
            solution = dict(executable_solution_index[code])
            commands = [item.get("command", "") for item in solution.get("commands", []) if isinstance(item, dict) and item.get("command")]
            shell = str(solution.get("shell", "")).lower()
            if commands and shell in {"powershell", "bash"}:
                solution[shell] = "; ".join(commands) if shell == "powershell" else "\n".join(commands)
            attached.append(solution)
        cases.append({
            "case_id": "DCASE-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper(),
            "status": "NEW - ANALYST REVIEW REQUIRED", "owner": "UNASSIGNED", "disposition": "UNDETERMINED",
            "environment": environment,
            "alert": {"rule_id": match.alert_rule_id, "title": match.title, "severity": match.severity,
                      "environment": match.environment, "host": evidence.get("host", "unknown"),
                      "user": evidence.get("user", "unknown"),
                      "description": "Compiled Sigma-subset rule matched the attached normalized event.",
                      "evidence": evidence},
            "recommended_solutions": attached or recommendations(match.alert_rule_id),
            "response_status": "compiled_sigma_match",
            "warning": "Validate the normalized fields and original source event before containment.",
        })
    cases_path = OUTPUTS / "incident_cases.json"
    try:
        existing_cases = json.loads(cases_path.read_text(encoding="utf-8")) if cases_path.exists() else []
    except json.JSONDecodeError as error:
        raise ValueError(f"Saved Cases JSON is invalid at line {error.lineno}: {error.msg}; preserve and repair data/outputs/incident_cases.json") from error
    merged_cases = {item["case_id"]: item for item in existing_cases if isinstance(item, dict) and item.get("case_id")}
    merged_cases.update({item["case_id"]: item for item in cases})
    deployed_cases = list(merged_cases.values())
    (OUTPUTS / "alerts.json").write_text(json.dumps([asdict(item) for item in alerts], indent=2), encoding="utf-8")
    cases_path.write_text(json.dumps(deployed_cases, indent=2), encoding="utf-8")
    legacy_report_cases = [item for item in deployed_cases if item.get("risk") and item.get("alert", {}).get("confidence")]
    (OUTPUTS / "incident_report.md").write_text(markdown_report(legacy_report_cases), encoding="utf-8")
    (OUTPUTS / "incident_dashboard.html").write_text(html_dashboard(legacy_report_cases), encoding="utf-8")
    (OUTPUTS / "declarative_matches.json").write_text(json.dumps([asdict(item) for item in declarative_matches], indent=2), encoding="utf-8")
    preview_limit = 50
    matched_alerts = [
        {"engine": "built_in_behavioral", "alert_code": item.rule_id, "title": item.title,
         "severity": item.severity, "host": item.host, "user": item.user}
        for item in alerts
    ] + [
        {"engine": "compiled_sigma_subset", "alert_code": item.alert_rule_id, "title": item.title,
         "severity": item.severity, "host": item.event.get("host", "unknown"),
         "user": item.event.get("user", "unknown")}
        for item in declarative_matches
    ]
    try:
        analyzed_file = str(path.relative_to(ROOT)).replace("\\", "/")
    except ValueError:
        analyzed_file = path.name
    return {"analyzed_file": analyzed_file, "environment": environment,
            "events": len(events), "events_previewed": min(len(raw_events), preview_limit),
            "event_preview": redact(raw_events[:preview_limit]),
            "preview_notice": "Showing the first 50 normalized events; alert cases contain the evidence that triggered each detection." if len(raw_events) > preview_limit else "Showing all normalized events.",
            "matched_alerts": matched_alerts, "case_ids": [item.get("case_id") for item in cases],
            "curated_alerts": len(alerts), "declarative_alerts": len(declarative_matches),
            "total_alerts": len(alerts) + len(declarative_matches), "cases": len(cases),
            "deployed_case_total": len(deployed_cases)}


def analyze(payload: dict[str, Any]) -> dict[str, Any]:
    environment, name = payload["environment"], safe_name(payload.get("file", "advanced_sample_events.jsonl"))
    if environment not in ENVIRONMENTS:
        raise ValueError("Unsupported environment")
    path = ROOT / name
    if not path.exists() or path.parent != ROOT:
        raise ValueError("Input must be a JSONL file in the SIEM application folder")
    if path.stat().st_size > MAX_ANALYSIS_BYTES: raise ValueError("Analysis input exceeds the 10 MB limit")
    return analyze_path(environment, path)


def import_raw_logs(payload: dict[str, Any]) -> dict[str, Any]:
    environment, source_type = str(payload.get("environment", "")), str(payload.get("source_type", ""))
    if environment not in ENVIRONMENTS:
        raise ValueError("Unsupported environment")
    allowed = {"windows_evtx", "windows_xml", "linux_audit", "linux_auth", "normalized_jsonl"}
    if source_type not in allowed:
        raise ValueError("Unsupported raw log type")
    filename = str(payload.get("file", "")).strip()
    if not filename or Path(filename).name != filename:
        raise ValueError("Log filename must name one file inside raw_logs")
    path = (RAW_LOGS / filename).resolve()
    if path.parent != RAW_LOGS.resolve() or not path.is_file():
        raise ValueError(f"Copy {filename or 'the exported log'} into the raw_logs folder first")
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("Raw log exceeds the 100 MB local import limit")
    records = import_raw_log_file(path, source_type, safe_name(payload.get("host", "unknown")))
    if not records:
        raise ValueError("No supported security events were found in the supplied log")
    normalized_name = f"normalized-{safe_name(path.stem)}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
    normalized_path = IMPORTS / normalized_name
    normalized_path.write_text("".join(json.dumps(item, ensure_ascii=False, default=str) + "\n" for item in records), encoding="utf-8")
    result = analyze_path(environment, normalized_path)
    return {"source_file": filename, "source_type": source_type, "normalized_file": str(normalized_path.relative_to(ROOT)), "normalized_events": len(records), "deployed_to_cases": result["cases"], **result}


def run_fake_log_pack(payload: dict[str, Any]) -> dict[str, Any]:
    """Run a named, inert training dataset through the production detection path."""
    packs = {
        "windows11": ("windows_11", "windows11-normalized.jsonl"),
        "ubuntu_desktop": ("ubuntu", "ubuntu-desktop-normalized.jsonl"),
        "ubuntu_server": ("ubuntu_server", "ubuntu-server-normalized.jsonl"),
        "firewall_dns": ("windows_11", "firewall-dns-normalized.jsonl"),
    }
    key = str(payload.get("pack", ""))
    if key not in packs:
        raise ValueError("Unknown synthetic training pack")
    environment, filename = packs[key]
    path = (ROOT / "fake_logs" / filename).resolve()
    expected_parent = (ROOT / "fake_logs").resolve()
    if path.parent != expected_parent or not path.is_file():
        raise ValueError("The synthetic pack is missing. Run generate_fake_logs.py and restart EDRRR.")
    result = analyze_path(environment, path)
    return {"training_only": True, "pack": key, "environment": environment,
            "source_file": f"fake_logs/{filename}", **result}


def run_fake_edr_pack(payload: dict[str, Any]) -> dict[str, Any]:
    """Publish synthetic vendor alerts as reviewable cases with safe responses."""
    packs = {"defender": ("windows_11", "defender-edr-alerts.jsonl"),
             "crowdstrike": ("windows_11", "crowdstrike-edr-alerts.jsonl"),
             "sentinelone": ("windows_11", "sentinelone-edr-alerts.jsonl")}
    key = str(payload.get("pack", ""))
    if key not in packs:
        raise ValueError("Unknown synthetic EDR pack")
    environment, filename = packs[key]
    path = (ROOT / "fake_logs" / filename).resolve()
    if path.parent != (ROOT / "fake_logs").resolve() or not path.is_file():
        raise ValueError("The synthetic EDR pack is missing. Run generate_fake_logs.py and restart EDRRR.")
    alerts = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    destination = OUTPUTS / "vendor_cases.json"
    existing = json.loads(destination.read_text(encoding="utf-8")) if destination.exists() else []
    cases = {item.get("case_id"): item for item in existing if isinstance(item, dict) and item.get("case_id")}
    for vendor in alerts:
        identity = f"{vendor.get('source')}|{vendor.get('vendor_alert_id')}|{vendor.get('timestamp')}"
        case = {"case_id": "VCASE-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper(),
                "status": "NEW - SYNTHETIC TRAINING", "owner": "UNASSIGNED", "disposition": "UNDETERMINED",
                "environment": environment, "vendor_alert": vendor, "candidate_rule_matches": [],
                "recommended_solutions": recommendations("VENDOR-" + hashlib.sha256(identity.encode()).hexdigest()[:10].upper()),
                "response_status": "generic_safe_triage",
                "warning": "Synthetic training case. Validate real vendor evidence before using any response command."}
        cases[case["case_id"]] = case
    destination.write_text(json.dumps(redact(list(cases.values())), indent=2, default=str), encoding="utf-8")
    return {"training_only": True, "pack": key, "source_file": f"fake_logs/{filename}",
            "vendor_alerts": len(alerts), "cases_added": len(alerts), "deployed_vendor_case_total": len(cases)}


def process_content_adapter(source: str, environment: str, path: Path) -> dict[str, Any]:
    """Run one adapter without allowing its failure to affect other content."""
    if source not in CONTENT_SOURCES:
        raise ValueError("Unsupported content adapter")
    if environment not in ENVIRONMENTS:
        raise ValueError("Unsupported environment")
    result = import_content(path, source)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if result.catalogue:
        (CONTENT_CATALOG / f"{safe_name(source)}-research-{stamp}.json").write_text(json.dumps(result.catalogue, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    if result.enrichment:
        (CONTENT_CATALOG / f"{safe_name(source)}-enrichment-{stamp}.json").write_text(json.dumps(result.enrichment, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    destination = OUTPUTS / "vendor_cases.json"
    existing = json.loads(destination.read_text(encoding="utf-8")) if destination.exists() else []
    cases = {item.get("case_id"): item for item in existing if isinstance(item, dict) and item.get("case_id")}
    added_ids = []
    for vendor in result.external_alerts:
        identity = f"{source}|{vendor.get('vendor_alert_id')}|{vendor.get('timestamp')}|{vendor.get('host')}"
        case_id_value = "VCASE-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper()
        rule_id = f"{source.upper()}-" + hashlib.sha256(identity.encode()).hexdigest()[:10].upper()
        cases[case_id_value] = {
            "case_id": case_id_value, "status": "NEW - ANALYST REVIEW REQUIRED", "owner": "UNASSIGNED",
            "disposition": "UNDETERMINED", "environment": environment, "vendor_alert": vendor,
            "candidate_rule_matches": [], "recommended_solutions": recommendations(rule_id),
            "response_status": "external_adapter_safe_triage",
            "warning": f"{source} supplied the original finding. Validate its original evidence before containment; EDRRR executed no response command.",
        }
        added_ids.append(case_id_value)
    if result.external_alerts:
        destination.write_text(json.dumps(redact(list(cases.values())), indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    public = result.public()
    public.update({"environment": environment, "uploaded_file": path.name, "cases_added": len(added_ids),
                   "case_ids": added_ids, "commands_executed": False,
                   "adapter_failure_isolation": "An adapter error returns only to this import and does not stop EDRRR."})
    return public


def content_adapter_status() -> dict[str, Any]:
    modes = {"suricata": "native alert ingestion", "wazuh": "native alert ingestion", "yara": "scan-result ingestion",
             "mitre_attack": "enrichment only", "elastic": "research only", "sentinel": "research only", "splunk": "research only"}
    files = [{"name": item.name, "bytes": item.stat().st_size, "modified": datetime.fromtimestamp(item.stat().st_mtime, timezone.utc).isoformat()}
             for item in sorted(CONTENT_CATALOG.glob("*.json"), key=lambda value: value.stat().st_mtime, reverse=True)[:100]]
    return {"adapters": [{"source": source, "mode": modes[source], "foreign_queries_executed": False} for source in sorted(CONTENT_SOURCES)],
            "stored_catalogues": files, "isolation": "Each import is bounded, validated and audited independently."}


def read_jsonl_page(path: Path, limit: int = 100) -> dict[str, Any]:
    if not path.exists():
        return {"total": 0, "items": []}
    lines = [line for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    return {"total": len(lines), "items": [json.loads(line) for line in lines[:limit]]}


def browse_catalog(query: dict[str, list[str]]) -> dict[str, Any]:
    environment = query.get("environment", ["windows_11"])[0]
    kind = query.get("kind", ["alerts"])[0]
    if environment not in ENVIRONMENTS or kind not in {"alerts", "solutions"}:
        raise ValueError("Invalid catalogue selection")
    page = read_jsonl_page(CATALOGS / f"{environment}_{kind}.jsonl")
    return redact(page if page["total"] else builtin_catalog(kind, environment))


def search_offline_alerts(query: dict[str, list[str]]) -> dict[str, Any]:
    environment = query.get("environment", ["windows_11"])[0]
    if environment not in ENVIRONMENTS:
        raise ValueError("Invalid environment")
    search_source = OFFLINE_ALERT_SOLUTIONS if OFFLINE_ALERT_SOLUTIONS.exists() else OFFLINE_ALERT_MASTER
    if not search_source.exists():
        return {"total": 0, "items": [], "message": "Build the offline alert master first"}
    document = json.loads(search_source.read_text(encoding="utf-8"))
    alerts = document.get("environments", {}).get(environment, {}).get("alerts", [])
    phrase = query.get("q", [""])[0].strip().lower()[:200]
    if phrase:
        alerts = [item for item in alerts if phrase in json.dumps(item, ensure_ascii=False, default=str).lower()]
    limit = max(1, min(int(query.get("limit", ["100"])[0]), 100))
    return {"environment": environment, "query": phrase, "total": len(alerts), "items": alerts[:limit]}


def browse_cases() -> dict[str, Any]:
    path = OUTPUTS / "incident_cases.json"
    items = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    vendor_path = OUTPUTS / "vendor_cases.json"
    if vendor_path.exists(): items.extend(json.loads(vendor_path.read_text(encoding="utf-8")))
    return {"total": len(items), "items": items[:100]}


def browse_correlations() -> dict[str, Any]:
    if not DB_PATH.exists():
        return {"total": 0, "items": []}
    connection = sqlite3.connect(DB_PATH)
    try:
        rows = connection.execute("SELECT payload_json FROM correlations ORDER BY last_seen DESC LIMIT 100").fetchall()
        total = connection.execute("SELECT count(*) FROM correlations").fetchone()[0]
        return redact({"total": total, "items": [json.loads(row[0]) for row in rows]})
    finally:
        connection.close()


def browse_events(limit: int = 100) -> dict[str, Any]:
    if not DB_PATH.exists(): return {"total": 0, "items": []}
    connection = sqlite3.connect(DB_PATH)
    try:
        total = connection.execute("SELECT count(*) FROM events").fetchone()[0]
        rows = connection.execute("SELECT event_id,timestamp,source_type,source_product,record_type,severity,host,user_name,source_ip,destination_ip,bytes_out,title,raw_json FROM events ORDER BY timestamp DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall()
        names = ("event_id","timestamp","source_type","source_product","record_type","severity","host","user","source_ip","destination_ip","bytes_out","title")
        return redact({"total": total, "items": [{**dict(zip(names, row[:-1])), "raw": json.loads(row[-1])} for row in rows]})
    finally:
        connection.close()


def imported_files() -> dict[str, Any]:
    items = [{"name": path.name, "records": jsonl_count(path), "bytes": path.stat().st_size, "modified": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()} for path in sorted(IMPORTS.glob("*.jsonl"), key=lambda item: item.stat().st_mtime, reverse=True)]
    return {"total": len(items), "items": items}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def reply(self, status_code: int, value: Any, content_type: str = "application/json") -> None:
        body = value if isinstance(value, bytes) else json.dumps(value, default=str).encode()
        self.send_response(status_code)
        policy = f"default-src 'none'; script-src 'nonce-{CSRF}'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        for name, header in (("Content-Type", content_type), ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff"), ("Content-Security-Policy", policy), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"), ("Permissions-Policy", "camera=(), microphone=(), geolocation=()")):
            self.send_header(name, header)
        self.end_headers(); self.wfile.write(body)

    def trusted_host(self) -> bool:
        return self.headers.get("Host", "") in ALLOWED_HOSTS

    def api_token_valid(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-SIEM-Token", ""), CSRF)

    def do_GET(self) -> None:
        try:
            if not self.trusted_host(): self.reply(421, {"error": "untrusted host"}); return
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                page = (UI / "index.html").read_text(encoding="utf-8").replace("__CSRF__", CSRF).replace("<script>", f"<script nonce=\"{CSRF}\">")
                self.reply(200, page.encode(), "text/html; charset=utf-8"); return
            if not parsed.path.startswith("/api/") or not self.api_token_valid(): self.reply(403, {"error": "forbidden"}); return
            query = urllib.parse.parse_qs(parsed.query)
            if parsed.path == "/api/status": self.reply(200, status())
            elif parsed.path == "/api/profiles": self.reply(200, redact(profiles()))
            elif parsed.path == "/api/catalog": self.reply(200, browse_catalog(query))
            elif parsed.path == "/api/offline-alerts": self.reply(200, redact(search_offline_alerts(query)))
            elif parsed.path == "/api/offline-alert-master":
                if not OFFLINE_ALERT_MASTER.exists(): raise ValueError("Offline alert master has not been built")
                self.reply(200, OFFLINE_ALERT_MASTER.read_bytes(), "application/json; charset=utf-8")
            elif parsed.path == "/api/cases": self.reply(200, redact(browse_cases()))
            elif parsed.path == "/api/correlations": self.reply(200, browse_correlations())
            elif parsed.path == "/api/events": self.reply(200, browse_events(int(query.get("limit", ["100"])[0])))
            elif parsed.path == "/api/imports": self.reply(200, imported_files())
            elif parsed.path == "/api/json-library":
                environment, offset, limit = query.get("environment", ["windows_11"])[0], max(0, int(query.get("offset", ["0"])[0])), max(1, min(int(query.get("limit", ["50"])[0]), 100))
                if environment not in ENVIRONMENTS: raise ValueError("Invalid environment")
                alerts_path, solutions_path = CATALOGS / f"{environment}_alerts.json", CATALOGS / f"{environment}_solutions.json"
                all_alerts = json.loads(alerts_path.read_text(encoding="utf-8")) if alerts_path.exists() else []
                all_solutions = json.loads(solutions_path.read_text(encoding="utf-8")) if solutions_path.exists() else []
                solution_by_code = {item.get("solution_code"): item for item in all_solutions if isinstance(item, dict) and item.get("solution_code")}
                solutions_by_rule: dict[str, list[dict[str, Any]]] = {}
                for solution in all_solutions:
                    if isinstance(solution, dict) and solution.get("alert_rule_id"):
                        solutions_by_rule.setdefault(str(solution["alert_rule_id"]), []).append(solution)
                joined_alerts = []
                for alert in all_alerts[offset:offset+limit]:
                    if not isinstance(alert, dict):
                        continue
                    attached = [solution_by_code[code] for code in alert.get("solution_codes", []) if code in solution_by_code]
                    if not attached:
                        attached = solutions_by_rule.get(str(alert.get("alert_rule_id", "")), [])
                    joined_alerts.append({**alert, "solutions": attached[:5]})
                self.reply(200, redact({"environment": environment, "alert_count": len(all_alerts), "solution_count": len(all_solutions), "offset": offset, "limit": limit, "alerts": joined_alerts, "solutions": all_solutions[offset:offset+limit]}))
            elif parsed.path == "/api/custom-rules": self.reply(200, redact({"total": len(load_custom_rules(CUSTOM_RULES)), "items": load_custom_rules(CUSTOM_RULES)[:100]}))
            elif parsed.path == "/api/content/status": self.reply(200, redact(content_adapter_status()))
            else: self.reply(404, {"error": "not found"})
        except Exception as error:
            append_audit(AUDIT_PATH, "http_get", "failed", {"path": self.path, "error_type": type(error).__name__})
            self.reply(400, {"error": public_error(error)})

    def do_POST(self) -> None:
        if not self.trusted_host() or self.headers.get("Origin") not in ALLOWED_ORIGINS or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), CSRF):
            self.reply(403, {"error": "forbidden"}); return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if self.path == "/api/content/upload":
                if not 0 < size <= 100 * 1024 * 1024:
                    raise ValueError("Content package must be between 1 byte and 100 MB")
                filename = urllib.parse.unquote(self.headers.get("X-Content-Filename", "")).strip()
                source = self.headers.get("X-Content-Source", "").strip()
                environment = self.headers.get("X-Content-Environment", "").strip()
                if source not in CONTENT_SOURCES or environment not in ENVIRONMENTS:
                    raise ValueError("Invalid content source or environment")
                if not filename or len(filename) > 180 or Path(filename).name != filename or any(ord(character) < 32 for character in filename):
                    raise ValueError("Invalid content filename")
                stored_name = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{safe_name(source)}-{safe_name(filename)}"
                destination = (CONTENT_IMPORTS / stored_name).resolve()
                if destination.parent != CONTENT_IMPORTS.resolve():
                    raise ValueError("Content upload escaped the approved folder")
                temporary = destination.with_name(destination.name + ".uploading")
                remaining = size
                try:
                    with temporary.open("wb") as handle:
                        while remaining:
                            chunk = self.rfile.read(min(1024 * 1024, remaining))
                            if not chunk: raise ValueError("Content upload ended before the declared size")
                            handle.write(chunk); remaining -= len(chunk)
                    temporary.replace(destination)
                    with LOCK: result = process_content_adapter(source, environment, destination)
                finally:
                    if temporary.exists(): temporary.unlink()
                append_audit(AUDIT_PATH, self.path, "success", {"source": source, "filename": filename, "result": redact(result)})
                self.reply(200, {"ok": True, **result}); return
            if self.path == "/api/raw-logs/upload":
                if not 0 < size <= 100 * 1024 * 1024:
                    raise ValueError("Selected log must be between 1 byte and 100 MB")
                filename = urllib.parse.unquote(self.headers.get("X-Log-Filename", "")).strip()
                if not filename or len(filename) > 180 or Path(filename).name != filename or any(ord(character) < 32 for character in filename):
                    raise ValueError("Invalid uploaded log filename")
                destination = (RAW_LOGS / filename).resolve()
                if destination.parent != RAW_LOGS.resolve():
                    raise ValueError("Uploaded log escaped the approved intake folder")
                temporary = destination.with_name(destination.name + ".uploading")
                remaining = size
                try:
                    with temporary.open("wb") as handle:
                        while remaining:
                            chunk = self.rfile.read(min(1024 * 1024, remaining))
                            if not chunk: raise ValueError("Log upload ended before the declared size")
                            handle.write(chunk); remaining -= len(chunk)
                    temporary.replace(destination)
                    source_type = self.headers.get("X-Log-Source-Type", "")
                    analyzed_filename = extract_uploaded_log_archive(destination, source_type) if destination.suffix.lower() == ".zip" else filename
                    payload = {"file": analyzed_filename, "environment": self.headers.get("X-Log-Environment", ""), "source_type": source_type, "host": urllib.parse.unquote(self.headers.get("X-Log-Host", "unknown"))}
                    with LOCK: result = import_raw_logs(payload)
                finally:
                    if temporary.exists(): temporary.unlink()
                append_audit(AUDIT_PATH, self.path, "success", {"filename": filename, "result": redact(result)})
                self.reply(200, {"ok": True, "uploaded": filename, "archive_extracted_log": analyzed_filename if analyzed_filename != filename else None, "analysis_started_automatically": True, **result}); return
            if not 0 < size <= 65536:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(size))
            routes = {"/api/connector/save": lambda: save_connector(payload), "/api/catalog/build": lambda: build_catalog(payload), "/api/catalog/offline-import": lambda: import_offline_sigma(payload), "/api/catalog/build-all": build_all_catalogs, "/api/executable/build": lambda: build_executable_catalog(payload), "/api/custom-rule/create": lambda: create_custom_rule(CUSTOM_RULES, payload), "/api/import": lambda: import_vendor(payload), "/api/analyze": lambda: analyze(payload), "/api/raw-logs/import": lambda: import_raw_logs(payload), "/api/training/run": lambda: run_fake_log_pack(payload), "/api/training/edr": lambda: run_fake_edr_pack(payload)}
            if self.path not in routes:
                raise ValueError("Unknown action")
            with LOCK:
                result = routes[self.path]()
            append_audit(AUDIT_PATH, self.path, "success", {"result": redact(result)})
            self.reply(200, {"ok": True, **result})
        except Exception as error:
            append_audit(AUDIT_PATH, self.path, "failed", {"error_type": type(error).__name__})
            self.reply(400, {"ok": False, "error": public_error(error)})


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, handler):
        super().__init__(address, handler); self.slots = threading.BoundedSemaphore(16)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False): request.close(); return
        try: super().process_request(request, client_address)
        except Exception: self.slots.release(); raise

    def process_request_thread(self, request, client_address):
        try: super().process_request_thread(request, client_address)
        finally: self.slots.release()


def main() -> int:
    os.chdir(ROOT); validate_playbooks()
    url = f"http://{HOST}:{PORT}/"
    print(f"EDRRR — EDR Research and Response: {url} — Ctrl+C stops it")
    if os.environ.get("EDRRR_NO_BROWSER") != "1":
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    BoundedServer((HOST, PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
