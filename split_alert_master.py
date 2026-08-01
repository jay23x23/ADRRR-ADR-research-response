#!/usr/bin/env python3
"""Split the offline alert master into exactly 60 response-enriched packs."""

from __future__ import annotations

import json
import math
import shutil
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "data" / "offline-alert-master.json"
DESTINATION = ROOT / "data" / "alert-packs"
ENRICHED_MASTER = DESTINATION / "complete-alerts-with-solutions.json"
ACTIVE_CATALOGS = ROOT / "data" / "catalogs"
PACK_COUNT = 60


def context(alert: dict[str, object]) -> str:
    logsource = alert.get("logsource") if isinstance(alert.get("logsource"), dict) else {}
    category = str(logsource.get("category") or logsource.get("service") or logsource.get("product") or "security event")
    value = category.replace("_", " ")
    return value[:-6] if value.endswith(" event") else value


def solutions(alert: dict[str, object]) -> list[dict[str, str]]:
    rule_id = str(alert.get("alert_rule_id", "SIGMA-UNKNOWN"))
    title = str(alert.get("title", "Sigma detection"))
    source_context = context(alert)
    definitions = [
        ("Validate evidence", f"Collect the original {source_context} event, affected entities, timestamps and surrounding telemetry for '{title}'.", "Preserves evidence and reduces false-positive risk.", "Threat activity may continue while the analyst validates it.", "The rule fired but malicious intent is not established.", "SOC analyst", "No system change; return temporary logging to its prior level."),
        ("Increase focused monitoring", f"Increase time-bounded monitoring for the users, hosts, processes, addresses and files referenced by '{title}'.", "Adds context without immediately interrupting service.", "Adds telemetry cost and may collect sensitive operational data.", "Evidence is suspicious but containment would be premature.", "Senior SOC analyst and data owner", "Remove temporary collection and apply the normal retention policy."),
        ("Apply narrow temporary control", f"Temporarily restrict only the confirmed indicator, process, account action or network destination associated with '{title}'.", "Limits likely malicious activity with a smaller blast radius.", "May block legitimate work and an indicator may be shared or incomplete.", "The indicator is specific, corroborated and its dependency impact is understood.", "Incident lead and affected system owner", "Time-limit the control and remove it if validation disproves the alert."),
        ("Contain affected entity", f"Isolate the confirmed endpoint or service, or suspend the confirmed compromised account related to '{title}', while retaining management visibility.", "Reduces lateral movement, persistence and further data loss.", "Can cause user downtime, service interruption or failover load.", "Compromise is probable and the business owner accepts disruption.", "Incident commander plus system or identity owner", "Release isolation or restore access after remediation and validation."),
        ("Recover and improve controls", f"Remove confirmed persistence, rotate exposed credentials, restore from a trusted state and tune prevention/detection coverage for '{title}'.", "Addresses root cause and reduces recurrence.", "Rebuilds, credential rotation and broad control changes can cause significant disruption.", "The incident is confirmed, scoped and evidence preservation is complete.", "Incident commander, service owner and change authority", "Use backups, staged restoration and documented configuration rollback."),
    ]
    commands = [
        (
            "$Start=(Get-Date).AddHours(-2); Get-WinEvent -FilterHashtable @{LogName='Security';StartTime=$Start} -MaxEvents 500 | Export-Csv .\\argus-evidence.csv -NoTypeInformation",
            "sudo journalctl --since '-2 hours' --no-pager > ./argus-evidence.log",
        ),
        (
            "Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 Name,Id,CPU,Path; Get-NetTCPConnection | Sort-Object State,RemoteAddress",
            "ps aux --sort=-%cpu | head -n 26; sudo ss -tupna",
        ),
        (
            "New-NetFirewallRule -DisplayName 'Argus temporary confirmed-IP block' -Direction Outbound -Action Block -RemoteAddress '<CONFIRMED_IP>'",
            "sudo nft add rule inet filter output ip daddr <CONFIRMED_IP> counter drop comment 'Argus temporary confirmed-IP block'",
        ),
        (
            "Disable-NetAdapter -Name '<ADAPTER_NAME>' -Confirm:$true  # Confirm alternate management access before isolation",
            "sudo ip link set dev <INTERFACE> down  # Confirm console or alternate management access first",
        ),
        (
            "Start-MpScan -ScanType FullScan; Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20",
            "sudo journalctl -p warning --since '-24 hours' --no-pager; sudo apt-get update; apt list --upgradable",
        ),
    ]
    return [
        {
            "solution_code": f"{rule_id}-R{index:02d}",
            "title": item[0], "action": item[1], "pros": item[2], "cons": item[3],
            "use_when": item[4], "approval_required": item[5], "rollback": item[6],
            "powershell": commands[index - 1][0], "bash": commands[index - 1][1],
            "command_warning": "Replace placeholders and validate scope, authority, dependencies and rollback before execution.",
            "execution_mode": "human-approved advisory",
        }
        for index, item in enumerate(definitions, start=1)
    ]


def main() -> int:
    document = json.loads(SOURCE.read_text(encoding="utf-8"))
    flattened = []
    enriched_environments: dict[str, dict[str, object]] = {}
    for environment, section in document["environments"].items():
        enriched_environment_alerts = []
        for source_alert in section["alerts"]:
            alert = dict(source_alert)
            alert["environment"] = environment
            alert.pop("response_slots", None)
            alert["solutions"] = solutions(alert)
            flattened.append(alert)
            enriched_environment_alerts.append(alert)
        enriched_environments[environment] = {"alert_count": len(enriched_environment_alerts), "alerts": enriched_environment_alerts}
    if len(flattened) < PACK_COUNT:
        raise RuntimeError("Not enough alerts to produce 60 non-empty packs")
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for existing in DESTINATION.glob("alert-pack-*.json"):
        existing.unlink()
    size = math.ceil(len(flattened) / PACK_COUNT)
    manifest_packs = []
    for index in range(PACK_COUNT):
        items = flattened[index * size:(index + 1) * size]
        payload = {
            "schema_version": "1.0",
            "pack": index + 1,
            "pack_count": PACK_COUNT,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "alert_count": len(items),
            "solution_count": sum(len(item["solutions"]) for item in items),
            "alerts": items,
        }
        filename = f"alert-pack-{index + 1:03d}-of-{PACK_COUNT:03d}.json"
        path = DESTINATION / filename
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
        manifest_packs.append({"file": filename, "alerts": payload["alert_count"], "solutions": payload["solution_count"]})
    manifest = {
        "schema_version": "1.0", "pack_count": PACK_COUNT,
        "total_alert_records": len(flattened),
        "total_solutions": len(flattened) * 5,
        "source": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "packs": manifest_packs,
    }
    (DESTINATION / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    ENRICHED_MASTER.write_text(json.dumps({
        "schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "environments": enriched_environments,
    }, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    ACTIVE_CATALOGS.mkdir(parents=True, exist_ok=True)
    for environment, section in enriched_environments.items():
        active_alerts, active_solutions = [], []
        for enriched_alert in section["alerts"]:  # type: ignore[index]
            alert = dict(enriched_alert)
            linked_solutions = alert.get("solutions", [])
            alert["alert_code"] = alert.get("alert_rule_id")
            alert["solution_codes"] = [item["solution_code"] for item in linked_solutions]
            active_alerts.append(alert)
            for solution in linked_solutions:
                active_solutions.append({"alert_rule_id": alert["alert_rule_id"], "environment": environment, **solution})
        for kind, items in (("alerts", active_alerts), ("solutions", active_solutions)):
            json_path = ACTIVE_CATALOGS / f"{environment}_{kind}.json"
            jsonl_path = ACTIVE_CATALOGS / f"{environment}_{kind}.jsonl"
            json_path.write_text(json.dumps(items, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            jsonl_path.write_text("".join(json.dumps(item, ensure_ascii=False, default=str) + "\n" for item in items), encoding="utf-8")
    print(json.dumps({"packs": PACK_COUNT, "alerts": len(flattened), "solutions": len(flattened) * 5, "pack_size": size}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
