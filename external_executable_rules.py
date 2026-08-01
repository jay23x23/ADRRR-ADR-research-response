"""Strict promotion of simple foreign-library queries into local rules.

Only conjunctions of literal field comparisons are accepted.  Anything with
aggregation, sequences, joins, subqueries or negation stays research-only.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


FIELD_MAP = {
    "image": "process.executable", "process_name": "process.name", "process.name": "process.name",
    "process.executable": "process.executable", "commandline": "process.command_line",
    "process.command_line": "process.command_line", "parentimage": "process.parent.executable",
    "user": "user", "username": "user", "host": "host", "computer": "host",
    "destinationip": "destination.ip", "sourceip": "source.ip", "queryname": "dns.question.name",
}
UNSUPPORTED = re.compile(r"\b(summarize|stats|count|sequence|join|transaction|eval|lookup|subsearch|by)\b|\[|\]", re.I)


def _field(value: str) -> str | None:
    return FIELD_MAP.get(value.strip().lower())


def _selection(pairs: list[tuple[str, str, str]]) -> dict[str, Any]:
    selection: dict[str, Any] = {}
    for source_field, operator, raw_value in pairs:
        target = _field(source_field)
        if not target:
            raise ValueError(f"unsupported field: {source_field}")
        value = raw_value.strip().strip('"\'')
        if not value:
            raise ValueError("empty comparison value")
        if "*" in value:
            if value.startswith("*") and value.endswith("*"): target += "|contains"; value = value.strip("*")
            elif value.startswith("*"): target += "|endswith"; value = value[1:]
            elif value.endswith("*"): target += "|startswith"; value = value[:-1]
            else: raise ValueError("middle wildcards are unsupported")
        if operator not in {"=", "=="}:
            raise ValueError("only positive equality is executable")
        selection[target] = value
    if not selection:
        raise ValueError("no executable comparisons")
    return selection


def translate(item: dict[str, Any]) -> dict[str, Any]:
    source, query = str(item.get("source", "")).lower(), str(item.get("query", "")).strip()
    if source not in {"elastic", "sentinel", "splunk"} or not query:
        raise ValueError("unsupported source or empty query")
    if UNSUPPORTED.search(query):
        raise ValueError("aggregation, sequence, join or advanced query syntax is unsupported")
    pairs: list[tuple[str, str, str]] = []
    if source == "elastic":
        body = query.split(" where ", 1)[-1]
        pairs = re.findall(r"([A-Za-z_][\w.]*)\s*(==|=)\s*(\"[^\"]+\"|'[^']+')", body)
    elif source == "sentinel":
        clauses = re.findall(r"([A-Za-z_][\w.]*)\s*(==|=)\s*(\"[^\"]+\"|'[^']+')", query)
        pairs = clauses
    else:
        for field, value in re.findall(r"\b([A-Za-z_][\w.]*)=(\"[^\"]+\"|'[^']+'|[^\s|]+)", query):
            if field.lower() not in {"index", "sourcetype", "source"}:
                pairs.append((field, "=", value))
    selection = _selection(pairs)
    text = " ".join((query, str(item.get("title", "")))).lower()
    product = "linux" if any(token in text for token in ("linux", "auditd", "journald", "sshd", "/bin/")) else "windows"
    content_id = str(item.get("content_id") or hashlib.sha256((source + query).encode()).hexdigest())
    return {
        "id": f"{source}-{content_id}", "title": str(item.get("title", "Untitled external detection")),
        "description": f"Strictly translated from the {source} open detection library.",
        "level": str(item.get("severity", "unknown")).lower(), "status": "experimental",
        "logsource": {"product": product, "category": "process_creation"},
        "tags": [f"source.{source}", "translation.strict_literal_subset"],
        "detection": {"selection": selection, "condition": "selection"},
        "_export": {"source_file": item.get("source_file"), "source_library": source,
                    "original_query": query, "translation": "strict-literal-v1"},
    }


def load_promotable(catalogue_root: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    promoted, rejected, seen = [], [], set()
    for path in sorted(catalogue_root.glob("*-research-*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
            items = payload if isinstance(payload, list) else payload.get("catalogue", payload.get("items", []))
            for item in items if isinstance(items, list) else []:
                if not isinstance(item, dict): continue
                identity = (item.get("source"), item.get("content_id"), item.get("query"))
                if identity in seen: continue
                seen.add(identity)
                try: promoted.append(translate(item))
                except ValueError as error: rejected.append({"source_file": str(item.get("source_file", path.name)), "reason": str(error)})
        except (OSError, ValueError, TypeError) as error:
            rejected.append({"source_file": path.name, "reason": type(error).__name__})
    return promoted, rejected
