#!/usr/bin/env python3
"""Cross-source correlation and retention-aware SQLite storage learning layer."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


SOURCE_TYPES = {"edr", "identity", "email", "firewall", "network", "cloud", "vpn", "badge"}


def moment(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class UnifiedRecord:
    event_id: str
    timestamp: str
    source_type: str
    source_product: str
    record_type: str
    title: str
    severity: str
    host: str
    user: str
    source_ip: str
    destination_ip: str
    bytes_out: int
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "UnifiedRecord":
        # Accept vendor_connectors.py output without discarding candidate matches.
        if "vendor_alert" in row:
            vendor = row["vendor_alert"]
            raw = vendor.get("raw") or {}
            inferred_type = "firewall" if vendor.get("source") == "windows_firewall_local" else "edr"
            row = {
                "timestamp": vendor.get("timestamp"), "source_type": inferred_type, "source_product": vendor.get("source"),
                "record_type": "alert", "title": vendor.get("title"), "severity": vendor.get("severity"),
                "host": vendor.get("host"), "user": vendor.get("user"),
                "source_ip": raw.get("source_ip") or raw.get("local_ip") or "",
                "destination_ip": raw.get("destination_ip") or raw.get("remote_address") or "",
                "bytes_out": raw.get("bytes_out") or 0, "raw": {"vendor_alert": vendor, "candidate_rule_matches": row.get("candidate_rule_matches", [])},
            }
        required = ("timestamp", "source_type", "title")
        missing = [name for name in required if not row.get(name)]
        if missing:
            raise ValueError(f"Missing unified fields: {', '.join(missing)}")
        source_type = str(row["source_type"]).lower()
        if source_type not in SOURCE_TYPES:
            raise ValueError(f"Unsupported source_type: {source_type}")
        identity = str(row.get("event_id") or json.dumps(row, sort_keys=True, default=str))
        return cls(
            event_id=str(row.get("event_id") or hashlib.sha256(identity.encode()).hexdigest()[:24]),
            timestamp=moment(str(row["timestamp"])).isoformat(), source_type=source_type,
            source_product=str(row.get("source_product", "unknown")), record_type=str(row.get("record_type", "alert")).lower(),
            title=str(row["title"]), severity=str(row.get("severity", "unknown")).lower(),
            host=str(row.get("host", "")).lower(), user=str(row.get("user", "")).lower(),
            source_ip=str(row.get("source_ip", "")), destination_ip=str(row.get("destination_ip", "")),
            bytes_out=int(row.get("bytes_out", 0) or 0), raw=row.get("raw", row),
        )


@dataclass(frozen=True)
class Correlation:
    correlation_id: str
    rule_id: str
    title: str
    risk_score: int
    reason: str
    entities: dict[str, list[str]]
    event_ids: tuple[str, ...]
    first_seen: str
    last_seen: str


class Store:
    """Learning store; production needs managed scaling, HA, RBAC, and backups."""

    def __init__(self, path: Path) -> None:
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS events(
          event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, source_type TEXT NOT NULL,
          source_product TEXT NOT NULL, record_type TEXT NOT NULL, severity TEXT NOT NULL,
          host TEXT, user_name TEXT, source_ip TEXT, destination_ip TEXT, bytes_out INTEGER,
          title TEXT NOT NULL, raw_json TEXT NOT NULL, expires_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_events_time ON events(timestamp);
        CREATE INDEX IF NOT EXISTS ix_events_user_time ON events(user_name,timestamp);
        CREATE INDEX IF NOT EXISTS ix_events_source_ip_time ON events(source_ip,timestamp);
        CREATE INDEX IF NOT EXISTS ix_events_host_time ON events(host,timestamp);
        CREATE TABLE IF NOT EXISTS correlations(
          correlation_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, first_seen TEXT NOT NULL,
          last_seen TEXT NOT NULL, risk_score INTEGER NOT NULL, payload_json TEXT NOT NULL,
          expires_at TEXT NOT NULL
        );
        """)

    def close(self) -> None:
        """Release SQLite handles deterministically (important on Windows)."""
        if self.db is not None:
            self.db.close()
            self.db = None

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def ingest(self, records: Iterable[UnifiedRecord], critical_hosts: set[str]) -> tuple[int, int]:
        accepted = dropped = 0
        now = datetime.now(timezone.utc)
        for item in records:
            # Alert-first: reject raw high-volume telemetry unless the exact host is allowlisted.
            if item.record_type == "raw" and item.host not in critical_hosts:
                dropped += 1
                continue
            days = 30 if item.record_type == "raw" else 365
            expires = (now + timedelta(days=days)).isoformat()
            cursor = self.db.execute(
                "INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (item.event_id, item.timestamp, item.source_type, item.source_product, item.record_type,
                 item.severity, item.host, item.user, item.source_ip, item.destination_ip, item.bytes_out,
                 item.title, json.dumps(item.raw, ensure_ascii=False), expires),
            )
            accepted += max(cursor.rowcount, 0)
        self.db.commit()
        return accepted, dropped

    def recent(self, hours: int) -> list[UnifiedRecord]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        rows = self.db.execute("SELECT event_id,timestamp,source_type,source_product,record_type,title,severity,host,user_name,source_ip,destination_ip,bytes_out,raw_json FROM events WHERE timestamp>=? ORDER BY timestamp", (cutoff,))
        return [UnifiedRecord(*row[:-1], raw=json.loads(row[-1])) for row in rows]

    def save_correlations(self, items: Iterable[Correlation]) -> None:
        expires = (datetime.now(timezone.utc) + timedelta(days=730)).isoformat()
        for item in items:
            self.db.execute("INSERT OR REPLACE INTO correlations VALUES(?,?,?,?,?,?,?)", (item.correlation_id, item.rule_id, item.first_seen, item.last_seen, item.risk_score, json.dumps(asdict(item)), expires))
        self.db.commit()

    def purge_expired(self) -> tuple[int, int]:
        now = datetime.now(timezone.utc).isoformat()
        before_events = self.db.execute("SELECT count(*) FROM events").fetchone()[0]
        before_correlations = self.db.execute("SELECT count(*) FROM correlations").fetchone()[0]
        self.db.execute("DELETE FROM events WHERE expires_at < ?", (now,))
        self.db.execute("DELETE FROM correlations WHERE expires_at < ?", (now,))
        self.db.commit()
        return before_events - self.db.execute("SELECT count(*) FROM events").fetchone()[0], before_correlations - self.db.execute("SELECT count(*) FROM correlations").fetchone()[0]


def shared(a: UnifiedRecord, b: UnifiedRecord) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {}
    for name in ("host", "user", "source_ip", "destination_ip"):
        left, right = getattr(a, name), getattr(b, name)
        if left and left == right:
            entities[name] = [left]
    # An EDR host IP can appear as another product's source IP.
    if a.destination_ip and a.destination_ip == b.source_ip:
        entities.setdefault("ip", []).append(a.destination_ip)
    if b.destination_ip and b.destination_ip == a.source_ip:
        entities.setdefault("ip", []).append(b.destination_ip)
    return entities


def correlate(records: list[UnifiedRecord], minutes: int = 5, massive_upload_bytes: int = 100_000_000) -> list[Correlation]:
    """Correlate EDR with non-EDR context; never correlate on time alone."""
    window = timedelta(minutes=minutes)
    results: list[Correlation] = []
    edr = [item for item in records if item.source_type == "edr"]
    for alert in edr:
        related = []
        entity_map: dict[str, set[str]] = {}
        categories: set[str] = set()
        for other in records:
            if other.event_id == alert.event_id or other.source_type == "edr":
                continue
            if abs(moment(other.timestamp) - moment(alert.timestamp)) > window:
                continue
            common = shared(alert, other)
            if not common:
                continue
            related.append(other)
            categories.add(other.source_type)
            for name, values in common.items():
                entity_map.setdefault(name, set()).update(values)
        if not related:
            continue
        score = 35 + min(40, len(categories) * 10)
        if any(item.source_type in {"firewall", "network"} and item.bytes_out >= massive_upload_bytes for item in related):
            score += 20
        if {"identity", "email"} & categories:
            score += 10
        score = min(score, 100)
        event_ids = tuple([alert.event_id] + [item.event_id for item in related])
        first = min([alert.timestamp] + [item.timestamp for item in related])
        last = max([alert.timestamp] + [item.timestamp for item in related])
        identity = "|".join(sorted(event_ids))
        results.append(Correlation(
            correlation_id="CORR-" + hashlib.sha256(identity.encode()).hexdigest()[:12].upper(),
            rule_id="CORR-EDR-CONTEXT-001", title="EDR alert with cross-source activity",
            risk_score=score,
            reason=f"EDR alert linked within ±{minutes} minutes to: {', '.join(sorted(categories))}",
            entities={name: sorted(values) for name, values in entity_map.items()},
            event_ids=event_ids, first_seen=first, last_seen=last,
        ))
    return results


def read_jsonl(paths: Iterable[Path]) -> list[UnifiedRecord]:
    output = []
    for path in paths:
        output.extend(UnifiedRecord.from_dict(json.loads(line)) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip())
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Store and correlate EDR, identity, email, firewall, cloud, VPN, and badge events")
    parser.add_argument("inputs", type=Path, nargs="+")
    parser.add_argument("--database", type=Path, default=Path("siem_events.db"))
    parser.add_argument("--critical-host", action="append", default=[], help="exact lowercase host allowed to send raw records")
    parser.add_argument("--window-minutes", type=int, default=5)
    parser.add_argument("--output", type=Path, default=Path("correlations.json"))
    args = parser.parse_args()
    with Store(args.database) as store:
        accepted, dropped = store.ingest(read_jsonl(args.inputs), {host.lower() for host in args.critical_host})
        correlations = correlate(store.recent(hours=24), args.window_minutes)
        store.save_correlations(correlations)
        store.purge_expired()
    args.output.write_text(json.dumps([asdict(item) for item in correlations], indent=2), encoding="utf-8")
    print(f"Accepted {accepted}; dropped {dropped} non-allowlisted raw records; wrote {len(correlations)} correlations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
