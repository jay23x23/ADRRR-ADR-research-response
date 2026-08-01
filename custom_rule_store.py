"""Validated custom alert creation with collision-free local codes."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from declarative_engine import validate_detection
from sigma_catalog_builder import ENVIRONMENTS


PREFIXES = {"windows_11": "W11", "windows_server": "WSV", "linux_mint": "LMT", "ubuntu": "UBU", "ubuntu_server": "UBS"}


def load(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    if not isinstance(value, list): raise ValueError("Custom rule store must contain a JSON array")
    return value


def next_code(rules: list[dict[str, Any]], environment: str) -> str:
    prefix = f"USR-{PREFIXES[environment]}-"
    used = {str(rule.get("alert_rule_id")) for rule in rules}
    number = 1
    while f"{prefix}{number:05d}" in used: number += 1
    return f"{prefix}{number:05d}"


def create(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    environment = str(payload.get("environment", ""))
    if environment not in ENVIRONMENTS: raise ValueError("Unsupported environment")
    title = str(payload.get("title", "")).strip()
    if not 5 <= len(title) <= 160: raise ValueError("Title must contain 5 to 160 characters")
    detection = payload.get("detection")
    if isinstance(detection, str): detection = json.loads(detection)
    if not isinstance(detection, dict): raise ValueError("Detection must be a JSON object")
    if len(json.dumps(detection)) > 50_000: raise ValueError("Detection exceeds the 50 KB limit")
    validate_detection(detection)
    responses = payload.get("responses")
    if isinstance(responses, str): responses = json.loads(responses)
    if not isinstance(responses, list) or len(responses) != 5 or any(not str(item).strip() for item in responses):
        raise ValueError("Exactly five non-empty response descriptions are required")
    if any(len(str(item)) > 2000 for item in responses): raise ValueError("Each response must be 2,000 characters or fewer")
    rules = load(path)
    code = next_code(rules, environment)
    rule = {
        "alert_rule_id": code, "title": title, "description": str(payload.get("description", "")),
        "environment": environment, "level": str(payload.get("severity", "medium")).lower(),
        "logsource": {"product": "windows" if environment.startswith("windows") else "linux", "category": str(payload.get("event_type", "custom"))},
        "detection": detection, "executable": True, "engine": "local-sigma-subset-v1",
        "solution_codes": [f"{code}-{environment.upper()}-S{index:02d}" for index in range(1, 6)],
        "responses": [{"solution_code": f"{code}-{environment.upper()}-S{index:02d}", "action": action, "auto_execute": False} for index, action in enumerate(responses, 1)],
        "created_at": datetime.now(timezone.utc).isoformat(), "created_by": "local-admin-ui", "version": 1,
    }
    rules.append(rule)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(rules, indent=2), encoding="utf-8"); temporary.replace(path)
    return rule
