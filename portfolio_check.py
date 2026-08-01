#!/usr/bin/env python3
"""Fail closed when a portfolio copy contains common private/runtime artifacts."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FORBIDDEN = (
    "connector_profiles.json", "data/siem_events.db", "data/security-audit.jsonl",
    "data/outputs/incident_cases.json", "data/outputs/vendor_cases.json",
)
SECRET_PATTERN = re.compile(
    r"(?i)(client_secret|api_token|api_key|authorization)\s*[=:]\s*['\"](?!__|<|\{\{)[^'\"]{8,}"
)
SCAN_SUFFIXES = {".py", ".js", ".html", ".json", ".toml", ".yml", ".yaml", ".md", ".txt"}


def main() -> int:
    failures: list[str] = []
    for relative in FORBIDDEN:
        if (ROOT / relative).exists():
            failures.append(f"runtime/private artifact present: {relative}")
    app = (ROOT / "siem_app.py").read_text(encoding="utf-8")
    if 'HOST = "127.0.0.1"' not in app and 'HOST, PORT' not in app:
        failures.append("loopback binding could not be verified")
    if "auto_execute\": False" not in (ROOT / "sigma_catalog_builder.py").read_text(encoding="utf-8"):
        failures.append("response auto-execution guard could not be verified")
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SCAN_SUFFIXES:
            continue
        if "third_party" in path.parts or path.stat().st_size > 5_000_000:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if SECRET_PATTERN.search(text):
            failures.append(f"possible embedded secret: {path.relative_to(ROOT)}")
    if failures:
        print("PORTFOLIO CHECK FAILED")
        print("\n".join(f"- {item}" for item in failures))
        return 1
    print("PORTFOLIO CHECK PASSED")
    print("No committed runtime data or obvious embedded credentials were found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
