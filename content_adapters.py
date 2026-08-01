#!/usr/bin/env python3
"""Fault-isolated offline adapters for non-Sigma security content.

Foreign query languages are never silently treated as executable EDRRR rules.
Adapters either produce normalized external alerts/enrichment, or research-only
catalogue entries with an explicit reason why they are not locally executable.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import tomllib
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

MAX_RECORDS = 10_000
MAX_ARCHIVE_FILES = 5_000
MAX_MEMBER_BYTES = 4 * 1024 * 1024
SUPPORTED_SOURCES = {"suricata", "wazuh", "yara", "mitre_attack", "elastic", "sentinel", "splunk"}


@dataclass
class AdapterResult:
    source: str
    mode: str
    discovered: int
    imported: int
    executable: int
    research_only: int
    rejected: int
    external_alerts: list[dict[str, Any]]
    enrichment: list[dict[str, Any]]
    catalogue: list[dict[str, Any]]
    rejected_items: list[dict[str, str]]
    warnings: list[str]

    def public(self) -> dict[str, Any]:
        value = asdict(self)
        value["external_alerts_preview"] = value.pop("external_alerts")[:20]
        value["enrichment_preview"] = value.pop("enrichment")[:20]
        value["catalogue_preview"] = value.pop("catalogue")[:20]
        value["rejected_preview"] = value.pop("rejected_items")[:20]
        return value


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, value: Any) -> str:
    return prefix + "-" + hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:12].upper()


def nested(row: dict[str, Any], path: str, default: Any = "") -> Any:
    value: Any = row
    for part in path.split("."):
        if not isinstance(value, dict): return default
        key = next((item for item in value if item.lower() == part.lower()), None)
        if key is None: return default
        value = value[key]
    return value


def json_records(text: str) -> list[dict[str, Any]]:
    # JSON Lines and a single JSON object both begin with ``{``.  Detect a
    # genuine multi-record JSONL document before the legacy whole-document
    # parser below, otherwise json.loads(text) raises "Extra data" on line 2.
    nonempty_lines = [line for line in text.splitlines() if line.strip()]
    if len(nonempty_lines) > 1:
        try:
            line_values = [json.loads(line) for line in nonempty_lines]
        except json.JSONDecodeError:
            pass
        else:
            if all(isinstance(item, dict) for item in line_values):
                return line_values
    stripped = text.lstrip()
    if not stripped: return []
    if stripped[0] in "[{":
        value = json.loads(text)
        if isinstance(value, list): return [item for item in value if isinstance(item, dict)][:MAX_RECORDS]
        if isinstance(value, dict):
            for key in ("items", "alerts", "results", "data"):
                if isinstance(value.get(key), list): return [item for item in value[key] if isinstance(item, dict)][:MAX_RECORDS]
            return [value]
    return [json.loads(line) for line in text.splitlines() if line.strip()][:MAX_RECORDS]


def iter_package(path: Path, suffixes: set[str]) -> Iterable[tuple[str, bytes]]:
    if path.suffix.lower() != ".zip":
        if path.suffix.lower() not in suffixes: return
        yield path.name, path.read_bytes()
        return
    with zipfile.ZipFile(path) as bundle:
        members = [item for item in bundle.infolist() if not item.is_dir()]
        if len(members) > MAX_ARCHIVE_FILES: raise ValueError("Content ZIP contains too many files")
        if any(item.flag_bits & 1 for item in members): raise ValueError("Encrypted content ZIPs are unsupported")
        if sum(item.file_size for item in members) > 300 * 1024 * 1024: raise ValueError("Content ZIP expands beyond 300 MB")
        for item in members:
            if Path(item.filename).suffix.lower() not in suffixes: continue
            if item.file_size > MAX_MEMBER_BYTES: continue
            if item.compress_size and item.file_size / item.compress_size > 200: raise ValueError("Unsafe ZIP expansion ratio")
            yield item.filename.replace("\\", "/"), bundle.read(item)


def external(source: str, row: dict[str, Any], title: str, severity: str, timestamp: str, host: str, user: str, identifier: str, description: str) -> dict[str, Any]:
    return {"source": source, "vendor": source.replace("_", " ").title(), "vendor_alert_id": identifier,
            "title": title or "Untitled external security alert", "severity": severity or "unknown",
            "timestamp": timestamp or now(), "host": host or "unknown", "user": user or "unknown",
            "description": description, "original_event": row}


def import_suricata(path: Path) -> AdapterResult:
    rows = json_records(path.read_text(encoding="utf-8-sig", errors="replace")); alerts = []
    for row in rows:
        if str(row.get("event_type", "")).lower() != "alert" or not isinstance(row.get("alert"), dict): continue
        alert = row["alert"]; sid = str(alert.get("signature_id", stable_id("SID", row)))
        alerts.append(external("suricata", row, str(alert.get("signature", "Suricata network alert")), str(alert.get("severity", "unknown")), str(row.get("timestamp", "")), str(row.get("host", row.get("in_iface", "network-sensor"))), "network", f"SURICATA-{sid}", str(alert.get("category", "Network signature matched"))))
    return AdapterResult("suricata", "native_alert_ingestion", len(rows), len(alerts), len(alerts), 0, len(rows)-len(alerts), alerts, [], [], [], ["Suricata executes packet signatures; EDRRR ingests EVE alert records."])


def import_wazuh(path: Path) -> AdapterResult:
    rows = json_records(path.read_text(encoding="utf-8-sig", errors="replace")); alerts = []
    for row in rows:
        rule = row.get("rule", {}) if isinstance(row.get("rule"), dict) else {}
        if not rule: continue
        identifier = f"WAZUH-{rule.get('id', stable_id('RULE', row))}"
        alerts.append(external("wazuh", row, str(rule.get("description", "Wazuh alert")), str(rule.get("level", "unknown")), str(row.get("timestamp", "")), str(nested(row, "agent.name", "unknown")), str(nested(row, "data.srcuser", nested(row, "data.dstuser", "unknown"))), identifier, str(nested(row, "full_log", rule.get("description", "Wazuh rule matched")))))
    return AdapterResult("wazuh", "native_alert_ingestion", len(rows), len(alerts), len(alerts), 0, len(rows)-len(alerts), alerts, [], [], [], ["Wazuh performed the original rule evaluation; EDRRR preserves its alert evidence."])


def import_yara(path: Path) -> AdapterResult:
    rows = json_records(path.read_text(encoding="utf-8-sig", errors="replace")); alerts = []
    for row in rows:
        rule = str(row.get("rule", row.get("rule_name", row.get("name", ""))))
        if not rule: continue
        identifier = str(row.get("id", stable_id("YARA", row)))
        alerts.append(external("yara", row, f"YARA match: {rule}", str(row.get("severity", "medium")), str(row.get("timestamp", "")), str(row.get("host", "file-analysis")), str(row.get("user", "analyst")), identifier, f"YARA rule {rule} matched {row.get('path', row.get('file', 'a supplied artifact'))}. The artifact was not executed."))
    return AdapterResult("yara", "scan_result_ingestion", len(rows), len(alerts), len(alerts), 0, len(rows)-len(alerts), alerts, [], [], [], ["This adapter imports YARA results; it never executes the supplied artifact."])


def import_mitre(path: Path) -> AdapterResult:
    document = json.loads(path.read_text(encoding="utf-8-sig")); objects = document.get("objects", []) if isinstance(document, dict) else []
    allowed = {"attack-pattern", "course-of-action", "malware", "tool", "intrusion-set", "x-mitre-data-source", "x-mitre-data-component"}
    enrichment = [{"id": item.get("id"), "type": item.get("type"), "name": item.get("name"), "description": item.get("description", ""), "external_references": item.get("external_references", []), "platforms": item.get("x_mitre_platforms", [])} for item in objects if isinstance(item, dict) and item.get("type") in allowed]
    return AdapterResult("mitre_attack", "enrichment_only", len(objects), len(enrichment), 0, len(enrichment), len(objects)-len(enrichment), [], enrichment[:MAX_RECORDS], [], [], ["ATT&CK enriches detections and cases; it does not itself fire alerts."])


def research_item(source: str, name: str, raw: dict[str, Any], language: str, query: str, path: str) -> dict[str, Any]:
    return {"content_id": str(raw.get("id", stable_id(source.upper(), {"path": path, "name": name}))), "source": source,
            "title": name or "Untitled detection", "severity": raw.get("severity", raw.get("level", "unknown")),
            "query_language": language, "query": query, "source_file": path, "status": "research_only",
            "executable": False, "reason": f"{language} is not executed by the local EDRRR evaluator; required telemetry and semantics must be validated."}


def yaml_documents(data: bytes) -> list[dict[str, Any]]:
    if importlib.util.find_spec("yaml") is None: raise ValueError("PyYAML is required for Sentinel/Splunk YAML imports")
    import yaml
    return [item for item in yaml.safe_load_all(data.decode("utf-8-sig", errors="replace")) if isinstance(item, dict)]


def import_research(path: Path, source: str) -> AdapterResult:
    suffixes = {"elastic": {".toml"}, "sentinel": {".yaml", ".yml", ".json"}, "splunk": {".yaml", ".yml", ".json"}}[source]
    catalogue, rejected, discovered = [], [], 0
    for name, data in iter_package(path, suffixes):
        try:
            if source == "elastic":
                raw = tomllib.loads(data.decode("utf-8-sig", errors="replace")); records = [raw.get("rule", raw)]
            elif Path(name).suffix.lower() == ".json": records = json_records(data.decode("utf-8-sig", errors="replace"))
            else: records = yaml_documents(data)
            discovered += len(records)
            for raw in records:
                if source == "elastic": name_value, language, query = str(raw.get("name", Path(name).stem)), str(raw.get("language", "kql")), str(raw.get("query", ""))
                elif source == "sentinel": name_value, language, query = str(raw.get("name", raw.get("displayName", Path(name).stem))), "KQL", str(raw.get("query", ""))
                else: name_value, language, query = str(raw.get("name", Path(name).stem)), "SPL", str(raw.get("search", raw.get("query", "")))
                catalogue.append(research_item(source, name_value, raw, language, query, name))
        except Exception as error:
            rejected.append({"source_file": name, "reason": type(error).__name__})
    return AdapterResult(source, "research_only", discovered, len(catalogue), 0, len(catalogue), len(rejected), [], [], catalogue[:MAX_RECORDS], rejected, ["Imported for research and mapping only; no foreign query was executed."])


def import_content(path: Path, source: str) -> AdapterResult:
    if source not in SUPPORTED_SOURCES: raise ValueError("Unsupported content adapter")
    if source == "suricata": return import_suricata(path)
    if source == "wazuh": return import_wazuh(path)
    if source == "yara": return import_yara(path)
    if source == "mitre_attack": return import_mitre(path)
    return import_research(path, source)
