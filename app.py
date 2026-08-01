#!/usr/bin/env python3
"""Home SIEM learning scaffold: normalize events, build lineage, and alert."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "sh", "bash"}
OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
WEB_SERVERS = {"w3wp.exe", "httpd.exe", "apache2", "nginx"}
BROWSERS_MAIL = {"chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe", "thunderbird.exe"}


@dataclass(frozen=True)
class ProcessEvent:
    """A small, vendor-neutral process schema inspired by ECS."""

    timestamp: str
    host: str
    user: str
    process_name: str
    process_executable: str
    process_pid: int
    process_command_line: str
    parent_name: str
    parent_executable: str
    parent_pid: int
    process_guid: str = ""
    hashes: str = ""
    source: str = "unknown"

    @property
    def identity(self) -> tuple[str, int, str]:
        """Prefer ProcessGuid; otherwise combine host, PID, and timestamp."""
        return (self.host, self.process_pid, self.process_guid or self.timestamp)


@dataclass(frozen=True)
class Alert:
    rule: str
    severity: str
    reason: str
    mitre_attack: str
    event: ProcessEvent


def leaf(path: str) -> str:
    """Return a lowercase executable name for Windows or POSIX paths."""
    return path.replace("\\", "/").rsplit("/", 1)[-1].lower()


def integer(value: Any) -> int:
    """Convert decimal or hexadecimal event-log identifiers to integers."""
    try:
        return int(str(value or "0"), 0)
    except ValueError:
        return 0


def first(raw: dict[str, Any], *names: str, default: Any = "") -> Any:
    """Return the first populated field among several vendor spellings."""
    for name in names:
        if name in raw and raw[name] not in (None, ""):
            return raw[name]
    return default


def normalize(raw: dict[str, Any]) -> ProcessEvent:
    """Map Sysmon, Windows 4688, Auditd, or ECS-like JSON into one schema."""
    executable = str(first(raw, "process.executable", "Image", "NewProcessName", "exe"))
    parent_executable = str(first(raw, "process.parent.executable", "ParentImage", "ParentProcessName", "parent_exe"))
    timestamp = str(first(raw, "@timestamp", "UtcTime", "TimeCreated", "timestamp"))
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    return ProcessEvent(
        timestamp=timestamp,
        host=str(first(raw, "host.name", "Computer", "hostname", default="unknown-host")),
        user=str(first(raw, "user.name", "User", "SubjectUserName", "uid", default="unknown-user")),
        process_name=str(first(raw, "process.name", default=leaf(executable))),
        process_executable=executable,
        process_pid=integer(first(raw, "process.pid", "ProcessId", "NewProcessId", "pid")),
        process_command_line=str(first(raw, "process.command_line", "CommandLine", "ProcessCommandLine", "proctitle")),
        parent_name=str(first(raw, "process.parent.name", default=leaf(parent_executable))),
        parent_executable=parent_executable,
        parent_pid=integer(first(raw, "process.parent.pid", "ParentProcessId", "ProcessIdOfCreatorProcess", "ppid")),
        process_guid=str(first(raw, "process.entity_id", "ProcessGuid")),
        hashes=str(first(raw, "process.hash", "Hashes", "hashes")),
        source=str(first(raw, "event.module", "Channel", "source", default="unknown")),
    )


def load_events(path: Path) -> list[ProcessEvent]:
    """Read JSON, JSON Lines, or CSV and normalize every record."""
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    else:
        text = path.read_text(encoding="utf-8-sig")
        if path.suffix.lower() == ".json":
            value = json.loads(text)
            rows = value if isinstance(value, list) else [value]
        else:
            rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    return [normalize(row) for row in rows]


def detect(event: ProcessEvent) -> list[Alert]:
    """Apply understandable parent-child and path rules to one event."""
    child = leaf(event.process_executable or event.process_name)
    parent = leaf(event.parent_executable or event.parent_name)
    child_path = event.process_executable.lower().replace("/", "\\")
    alerts: list[Alert] = []

    def add(rule: str, severity: str, reason: str, technique: str) -> None:
        alerts.append(Alert(rule, severity, reason, technique, event))

    if parent in OFFICE and child in SHELLS:
        add("Office spawned a script interpreter", "high", f"{parent} -> {child}", "T1204 / T1059")
    if parent in WEB_SERVERS and child in SHELLS | {"whoami", "whoami.exe"}:
        add("Web server spawned an interactive tool", "critical", f"{parent} -> {child}", "T1505.003 / T1059")
    if child == "lsass.exe" and parent != "wininit.exe":
        add("Unexpected LSASS parent", "critical", f"Expected wininit.exe, saw {parent or 'unknown'}", "T1036")
    if child == "svchost.exe" and parent != "services.exe":
        add("Unexpected svchost parent", "high", f"Expected services.exe, saw {parent or 'unknown'}", "T1036")
    untrusted = "\\appdata\\local\\temp\\" in child_path or child_path.startswith("/tmp/")
    if parent in BROWSERS_MAIL and untrusted:
        add("Browser or mail client launched a temporary binary", "medium", f"{parent} -> {event.process_executable}", "T1204 / T1036")
    return alerts


def build_lineage(events: Iterable[ProcessEvent]) -> dict[tuple[str, int], list[ProcessEvent]]:
    """Index children by host and PPID; PIDs alone are not globally unique."""
    tree: dict[tuple[str, int], list[ProcessEvent]] = {}
    for event in events:
        tree.setdefault((event.host, event.parent_pid), []).append(event)
    return tree


def download_sigma_snapshot(destination: Path) -> Path:
    """Download the official branch snapshot with ZIP-slip and size protections."""
    url = "https://codeload.github.com/SigmaHQ/sigma/zip/refs/heads/master"
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sigma-download-", dir=destination.parent) as folder:
        temporary = Path(folder)
        archive = temporary / "sigma.zip"
        request = urllib.request.Request(url, headers={"User-Agent": "Argus-SIEM/1.0", "Accept": "application/zip"})
        total = 0
        with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as handle:
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > 200 * 1024 * 1024:
                    raise RuntimeError("Sigma download exceeded the 200 MB compressed limit")
                handle.write(chunk)
        extracted = temporary / "extracted"
        extracted.mkdir()
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if len(members) > 50_000 or sum(item.file_size for item in members) > 1024 * 1024 * 1024:
                raise RuntimeError("Sigma archive exceeds extraction safety limits")
            for item in members:
                relative = Path(item.filename)
                if relative.is_absolute() or ".." in relative.parts:
                    raise RuntimeError("Unsafe path found in Sigma archive")
            bundle.extractall(extracted)
        roots = [item for item in extracted.iterdir() if item.is_dir()]
        if len(roots) != 1 or not (roots[0] / "rules").exists():
            raise RuntimeError("Downloaded Sigma snapshot does not contain the expected rules directory")
        final_destination = destination.with_name(destination.name + "-snapshot") if (destination / ".git").exists() else destination
        candidate = final_destination.with_name(final_destination.name + "-new")
        if candidate.exists(): shutil.rmtree(candidate)
        shutil.move(str(roots[0]), str(candidate))
    previous = final_destination.with_name(final_destination.name + "-previous")
    if previous.exists(): shutil.rmtree(previous)
    if final_destination.exists(): final_destination.replace(previous)
    candidate.replace(final_destination)
    if previous.exists(): shutil.rmtree(previous)
    (final_destination / ".sigma-source.json").write_text(json.dumps({"source": url, "method": "official_branch_snapshot", "downloaded_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")
    return final_destination


def sync_sigma(destination: Path) -> Path:
    """Use Git when available, otherwise safely download the official snapshot."""
    url = "https://github.com/SigmaHQ/sigma.git"
    try:
        if (destination / ".git").exists():
            subprocess.run(["git", "-C", str(destination), "pull", "--ff-only"], check=True, capture_output=True, text=True)
        elif destination.exists() and any(destination.iterdir()):
            return download_sigma_snapshot(destination)
        else:
            subprocess.run(["git", "clone", "--depth", "1", url, str(destination)], check=True, capture_output=True, text=True)
        commit = subprocess.run(["git", "-C", str(destination), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
        (destination / ".sigma-source.json").write_text(json.dumps({"source": url, "method": "git", "commit": commit, "updated_at": datetime.now(timezone.utc).isoformat()}, indent=2), encoding="utf-8")
        return destination
    except (FileNotFoundError, subprocess.CalledProcessError, OSError):
        return download_sigma_snapshot(destination)


def sigma_export(root: Path) -> list[dict[str, Any]]:
    """Losslessly export every readable Sigma YAML document to JSON objects."""
    try:
        import yaml
    except ImportError as error:
        raise RuntimeError("Install PyYAML: python -m pip install -r requirements.txt") from error
    exported: list[dict[str, Any]] = []
    paths = sorted([*root.rglob("*.yml"), *root.rglob("*.yaml")])
    for path in paths:
        try:
            documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except (OSError, yaml.YAMLError):
            continue
        for document_number, rule in enumerate(documents, start=1):
            if not isinstance(rule, dict):
                continue
            # Keep the complete rule and add provenance under a private metadata key.
            exported.append({
                "_export": {
                    "source_file": str(path.relative_to(root)).replace("\\", "/"),
                    "document": document_number,
                    "repository": "https://github.com/SigmaHQ/sigma",
                },
                **rule,
            })
    return exported


def write_sigma_json(root: Path, output: Path) -> int:
    """Write all Sigma rules atomically enough for a local learning project."""
    rules = sigma_export(root)
    if not rules:
        raise RuntimeError(f"No readable Sigma rules were found under {root}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(rules, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    temporary.replace(output)
    return len(rules)


def main() -> int:
    parser = argparse.ArgumentParser(description="Learn process lineage and defensive SIEM detections")
    commands = parser.add_subparsers(dest="command", required=True)
    analyze = commands.add_parser("analyze", help="normalize events and print alerts")
    analyze.add_argument("input", type=Path, help="JSON, JSONL, or CSV event file")
    analyze.add_argument("--normalized", type=Path, help="optional normalized JSON output")
    sync = commands.add_parser("sigma-sync", help="clone or update SigmaHQ rules")
    sync.add_argument("destination", type=Path, nargs="?", default=Path("sigma"))
    export = commands.add_parser("sigma-export", help="export every Sigma rule as one JSON array")
    export.add_argument("root", type=Path, nargs="?", default=Path("sigma"))
    export.add_argument("--output", type=Path, default=Path("sigma-all-rules.json"))
    args = parser.parse_args()

    if args.command == "sigma-sync":
        actual = sync_sigma(args.destination)
        print(f"Sigma rules ready at {actual.resolve()}")
        return 0
    if args.command == "sigma-export":
        count = write_sigma_json(args.root, args.output)
        print(f"Exported {count} Sigma rules to {args.output.resolve()}")
        return 0

    events = load_events(args.input)
    build_lineage(events)
    alerts = [alert for event in events for alert in detect(event)]
    if args.normalized:
        args.normalized.write_text(json.dumps([asdict(event) for event in events], indent=2), encoding="utf-8")
    print(json.dumps([asdict(alert) for alert in alerts], indent=2))
    print(f"Processed {len(events)} events; generated {len(alerts)} alerts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
