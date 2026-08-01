#!/usr/bin/env python3
"""Compile at least 100 genuinely locally evaluable Sigma rules per requested OS."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from declarative_engine import validate_detection
from sigma_catalog_builder import compile_catalog


TARGET_ENVIRONMENTS = ("windows_11", "windows_server", "ubuntu")


def build_executable(rules: list[dict[str, Any]], environment: str, minimum: int = 100) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    alerts, solutions = compile_catalog(rules, environment)
    source_by_id = {item.get("id"): item for item in rules if item.get("id")}
    executable, rejected = [], []
    for alert in alerts:
        source = source_by_id.get(alert.get("sigma_id"))
        if not source or not isinstance(source.get("detection"), dict):
            rejected.append({"alert_rule_id": alert["alert_rule_id"], "reason": "missing detection body"}); continue
        try:
            validate_detection(source["detection"])
        except (TypeError, ValueError, IndexError) as error:
            rejected.append({"alert_rule_id": alert["alert_rule_id"], "reason": str(error)}); continue
        executable.append({**alert, "detection": source["detection"], "executable": True, "engine": "local-sigma-subset-v1"})
    if len(executable) < minimum:
        raise RuntimeError(f"Only {len(executable)} validated executable rules were available for {environment}; required {minimum}. No rules were fabricated.")
    codes = {code for rule in executable for code in rule["solution_codes"]}
    selected_solutions = [item for item in solutions if item["solution_code"] in codes]
    return executable, selected_solutions, rejected


def write_build(root: Path, environment: str, executable: list[dict[str, Any]], solutions: list[dict[str, Any]], rejected: list[dict[str, str]]) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    (root / f"{environment}_executable_rules.json").write_text(json.dumps(executable, indent=2), encoding="utf-8")
    (root / f"{environment}_executable_solutions.json").write_text(json.dumps(solutions, indent=2), encoding="utf-8")
    (root / f"{environment}_rejected_rules.json").write_text(json.dumps(rejected, indent=2), encoding="utf-8")
    # Portable packs keep each alert beside its five response choices.  This is
    # deliberately separate from the runtime files above, which are optimized
    # for fast rule execution and solution lookup.
    pack_root = root / f"{environment}_packs"
    pack_root.mkdir(parents=True, exist_ok=True)
    solution_index = {item.get("solution_code"): item for item in solutions}
    enriched = [{**rule, "responses": [solution_index[code] for code in rule.get("solution_codes", []) if code in solution_index]} for rule in executable]
    pack_size = 60
    pack_count = (len(enriched) + pack_size - 1) // pack_size
    expected_names = set()
    for index in range(pack_count):
        name = f"pack-{index + 1:04d}-of-{pack_count:04d}.json"
        expected_names.add(name)
        payload = {"schema_version": "1.0", "environment": environment, "pack": index + 1,
                   "pack_count": pack_count, "rules": enriched[index * pack_size:(index + 1) * pack_size]}
        (pack_root / name).write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    for stale in pack_root.glob("pack-*.json"):
        if stale.name not in expected_names:
            stale.unlink()
    manifest = {"schema_version": "1.0", "environment": environment, "pack_size": pack_size,
                "pack_count": pack_count, "executable_alerts": len(executable), "responses": len(solutions),
                "rules_with_five_responses": sum(len(item["responses"]) == 5 for item in enriched)}
    (pack_root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return {"environment": environment, "executable_alerts": len(executable), "responses": len(solutions),
            "rejected": len(rejected), "pack_size": pack_size, "packs": pack_count,
            "rules_with_five_responses": manifest["rules_with_five_responses"]}
