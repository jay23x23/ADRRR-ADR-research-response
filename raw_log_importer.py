#!/usr/bin/env python3
"""Offline parsers for staged Windows and Linux security logs."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MAX_EVENTS = 10_000


def iso(value: str) -> str:
    value = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def windows_xml_records(text: str) -> list[dict[str, Any]]:
    records = []
    for match in re.finditer(r"<Event\b[\s\S]*?</Event>", text, flags=re.IGNORECASE):
        try:
            root = ET.fromstring(match.group(0))
        except ET.ParseError:
            continue
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        system = root.find("e:System", ns)
        if system is None:
            continue
        event_id = (system.findtext("e:EventID", default="", namespaces=ns) or "").strip()
        provider_node = system.find("e:Provider", ns)
        computer = system.findtext("e:Computer", default="unknown", namespaces=ns)
        time_node = system.find("e:TimeCreated", ns)
        data = {}
        for index, node in enumerate(root.findall(".//e:EventData/e:Data", ns)):
            data[node.attrib.get("Name", f"field_{index}")] = node.text or ""
        records.append({
            "event_id": event_id,
            "provider": provider_node.attrib.get("Name", "") if provider_node is not None else "",
            "timestamp": iso(time_node.attrib.get("SystemTime", "")) if time_node is not None else iso(""),
            "host": computer,
            "data": data,
        })
        if len(records) >= MAX_EVENTS:
            break
    return records


def export_evtx(path: Path) -> str:
    command = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        "$ErrorActionPreference='Stop'; "
        "Get-WinEvent -Path $args[0] -MaxEvents 10000 | ForEach-Object { $_.ToXml() }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command, str(path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, check=False,
    )
    if result.returncode:
        raise RuntimeError("Windows could not read the EVTX file. Run EDRRR as Administrator and verify the export is valid.")
    return result.stdout


def normalize_windows(record: dict[str, Any]) -> dict[str, Any] | None:
    event_id, data = str(record["event_id"]), record["data"]
    base = {"timestamp": record["timestamp"], "host": record["host"], "user": data.get("User", data.get("SubjectUserName", data.get("TargetUserName", "unknown"))), "source": f"windows:{event_id}"}
    if event_id in {"1", "4688"}:
        return {**base, "event_type": "process", "process_executable": data.get("Image", data.get("NewProcessName", "")), "process_pid": data.get("ProcessId", data.get("NewProcessId", "")), "process_command_line": data.get("CommandLine", data.get("ProcessCommandLine", "")), "parent_executable": data.get("ParentImage", data.get("ParentProcessName", "")), "parent_pid": data.get("ParentProcessId", data.get("ProcessId", ""))}
    if event_id == "10":
        return {**base, "event_type": "process_access", "source_process": data.get("SourceImage", ""), "target_process": data.get("TargetImage", ""), "granted_access": data.get("GrantedAccess", "")}
    if event_id == "11":
        return {**base, "event_type": "file", "path": data.get("TargetFilename", ""), "action": "created", "process_executable": data.get("Image", "")}
    if event_id in {"12", "13", "14"}:
        return {**base, "event_type": "registry", "key": data.get("TargetObject", ""), "action": "set" if event_id == "13" else "modified", "value": data.get("Details", "")}
    if event_id in {"4624", "4625"}:
        return {**base, "event_type": "authentication", "outcome": "success" if event_id == "4624" else "failure", "source_ip": data.get("IpAddress", ""), "logon_type": data.get("LogonType", ""), "device_id": data.get("WorkstationName", "")}
    if event_id in {"4728", "4732", "4756"}:
        return {**base, "event_type": "group_change", "action": "member_added", "target_user": data.get("MemberName", data.get("MemberSid", "")), "group": data.get("TargetUserName", "")}
    if event_id in {"5152", "5156", "5157"}:
        return {**base, "event_type": "network", "source_ip": data.get("SourceAddress", ""), "destination_ip": data.get("DestAddress", ""), "destination_port": data.get("DestPort", ""), "process_executable": data.get("Application", ""), "outcome": "blocked" if event_id in {"5152", "5157"} else "allowed"}
    if event_id == "22":
        return {**base, "event_type": "dns", "query": data.get("QueryName", ""), "response": data.get("QueryResults", ""), "process_executable": data.get("Image", "")}
    return None


def parse_linux_audit(text: str, host: str) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for line in text.splitlines():
        serial = re.search(r"audit\(([^:]+):(\d+)\)", line)
        if not serial:
            continue
        key, row = serial.group(2), groups.setdefault(serial.group(2), {"timestamp": iso(datetime.fromtimestamp(float(serial.group(1)), timezone.utc).isoformat()), "args": []})
        event_type = re.search(r"type=([A-Z_]+)", line)
        if event_type and event_type.group(1) == "SYSCALL":
            for name in ("exe", "pid", "ppid", "uid", "auid", "comm"):
                match = re.search(rf"\b{name}=(\"[^\"]*\"|\S+)", line)
                if match: row[name] = match.group(1).strip('"')
        if event_type and event_type.group(1) == "EXECVE":
            args = sorted((int(index), value) for index, value in re.findall(r"\ba(\d+)=\"([^\"]*)\"", line))
            row["args"].extend(value for _, value in args)
    output = []
    for row in groups.values():
        if not row.get("exe") and not row.get("args"):
            continue
        output.append({"timestamp": row["timestamp"], "event_type": "process", "host": host, "user": row.get("auid", row.get("uid", "unknown")), "source": "auditd:execve", "process_executable": row.get("exe", row.get("args", [""])[0]), "process_pid": row.get("pid", ""), "process_command_line": " ".join(row.get("args", [])), "parent_pid": row.get("ppid", "")})
    return output[:MAX_EVENTS]


def parse_linux_auth(text: str, host: str) -> list[dict[str, Any]]:
    output = []
    pattern = re.compile(r"(?P<outcome>Failed|Accepted) \S+ for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)")
    year = datetime.now().year
    for line in text.splitlines():
        match = pattern.search(line)
        if not match:
            continue
        try: timestamp = datetime.strptime(f"{year} {line[:15]}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError: timestamp = iso("")
        output.append({"timestamp": timestamp, "event_type": "authentication", "host": host, "user": match.group("user"), "source": "linux:auth", "outcome": "failure" if match.group("outcome") == "Failed" else "success", "source_ip": match.group("ip")})
    return output[:MAX_EVENTS]


def import_file(path: Path, source_type: str, host: str = "unknown") -> list[dict[str, Any]]:
    if source_type == "windows_evtx":
        return [item for record in windows_xml_records(export_evtx(path)) if (item := normalize_windows(record))]
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    if source_type == "windows_xml":
        return [item for record in windows_xml_records(text) if (item := normalize_windows(record))]
    if source_type == "normalized_jsonl":
        stripped = text.strip()
        if not stripped:
            return []
        # Accept a conventional JSON array/single object as well as JSONL.
        # JSONL cannot be detected from its first character because every line
        # normally begins with "{".
        try:
            document = json.loads(stripped)
        except json.JSONDecodeError:
            records = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(
                        f"Invalid normalized JSONL at line {line_number}, column {error.colno}: {error.msg}"
                    ) from error
                if not isinstance(record, dict):
                    raise ValueError(f"Normalized JSONL line {line_number} must contain one JSON object")
                records.append(record)
                if len(records) >= MAX_EVENTS:
                    break
            return records
        if isinstance(document, dict):
            return [document]
        if isinstance(document, list):
            if not all(isinstance(record, dict) for record in document):
                raise ValueError("Normalized JSON arrays may contain only event objects")
            return document[:MAX_EVENTS]
        raise ValueError("Normalized JSON must be an object, an array of objects, or one object per line")
    if source_type == "linux_audit":
        return parse_linux_audit(text, host)
    if source_type == "linux_auth":
        return parse_linux_auth(text, host)
    raise ValueError("Unsupported raw log source type")
