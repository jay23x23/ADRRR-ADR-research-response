#!/usr/bin/env python3
"""Create the local OS-categorized Sigma alert-authoring catalogue."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sigma_catalog_builder import ENVIRONMENTS


ROOT = Path(__file__).resolve().parent
SIGMA_ROOT = ROOT / "sigma"
OUTPUT = ROOT / "data" / "offline-alert-master.json"


def empty_response_slots() -> list[dict[str, object]]:
    return [
        {
            "slot": number,
            "solution_code": "",
            "title": "",
            "investigation": "",
            "powershell": "",
            "bash": "",
            "system_risk": "",
            "approval_required": "",
            "rollback": "",
        }
        for number in range(1, 6)
    ]


def scalar(text: str, key: str) -> str:
    import re
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(.+?)\s*$", text)
    if not match:
        return ""
    value = match.group(1).strip().strip("'\"")
    if value in {"|", ">", "|-", ">-"}:
        lines = []
        for line in text[match.end():].splitlines():
            if not line.strip():
                if lines: lines.append("")
                continue
            if not line[:1].isspace():
                break
            lines.append(line.strip())
        return " ".join(part for part in lines if part).strip()
    return value


def indented_value(text: str, section: str, key: str) -> str:
    import re
    block = re.search(rf"(?ms)^{re.escape(section)}:\s*\n((?:[ \t]+.*\n?)*)", text)
    if not block:
        return ""
    match = re.search(rf"(?m)^\s+{re.escape(key)}:\s*(.+?)\s*$", block.group(1))
    return match.group(1).strip().strip("'\"") if match else ""


def lightweight_export(root: Path) -> list[dict[str, object]]:
    """Index Sigma metadata without third-party packages; detection YAML stays in its source file."""
    records = []
    for path in sorted((*root.rglob("*.yml"), *root.rglob("*.yaml"))):
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            continue
        title = scalar(text, "title")
        rule_id = scalar(text, "id")
        if not title or not rule_id or "\ndetection:" not in "\n" + text:
            continue
        records.append({
            "alert_rule_id": rule_id,
            "title": title,
            "description": scalar(text, "description"),
            "status": scalar(text, "status"),
            "level": scalar(text, "level") or "unknown",
            "logsource": {
                "product": indented_value(text, "logsource", "product"),
                "service": indented_value(text, "logsource", "service"),
                "category": indented_value(text, "logsource", "category"),
            },
            "source_file": str(path.relative_to(root)).replace("\\", "/"),
        })
    return records


def applies(rule: dict[str, object], environment: str) -> bool:
    source = str(rule.get("source_file", "")).lower()
    product = str(rule.get("logsource", {}).get("product", "")).lower()  # type: ignore[union-attr]
    windows = "windows" in source or product == "windows"
    linux = any(word in source for word in ("linux", "ubuntu")) or product == "linux"
    if environment in {"windows_11", "windows_server"}:
        return windows
    if environment in {"ubuntu", "ubuntu_server", "linux_mint"}:
        return linux
    return False


def main() -> int:
    rules = lightweight_export(SIGMA_ROOT)
    if not rules:
        raise SystemExit(f"No Sigma YAML rules found below {SIGMA_ROOT}")
    environments: dict[str, dict[str, object]] = {}
    for environment in ENVIRONMENTS:
        alerts = [rule for rule in rules if applies(rule, environment)]
        authoring_alerts = []
        for alert in alerts:
            item = json.loads(json.dumps(alert, default=str))
            item["response_slots"] = empty_response_slots()
            authoring_alerts.append(item)
        environments[environment] = {
            "alert_count": len(authoring_alerts),
            "alerts": authoring_alerts,
        }
    document = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "local SigmaHQ repository snapshot",
        "purpose": "Offline detection catalogue with empty response-authoring slots",
        "environments": environments,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(document, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    temporary.replace(OUTPUT)
    print(json.dumps({name: value["alert_count"] for name, value in environments.items()}))
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
