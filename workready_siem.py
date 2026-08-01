#!/usr/bin/env python3
"""Stateful defensive-analytics lab spanning endpoint, identity, network, and DNS."""

from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import math
import statistics
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from response_playbooks import recommendations, solution_catalog, validate_playbooks


RUNTIME_ENVIRONMENTS = ("windows_11", "windows_server", "linux_mint", "ubuntu", "ubuntu_server")


def choose_environment(provided: str | None) -> str:
    """Require an explicit platform choice interactively or through automation."""
    if provided:
        return provided
    print("Select the monitored environment:")
    for index, name in enumerate(RUNTIME_ENVIRONMENTS, start=1):
        print(f"  {index}. {name}")
    answer = input("Environment number: ").strip()
    try:
        return RUNTIME_ENVIRONMENTS[int(answer) - 1]
    except (ValueError, IndexError) as error:
        raise SystemExit("Invalid environment selection; no analysis was run") from error


def utc(value: str) -> datetime:
    """Parse ISO-8601 into an aware UTC datetime."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def leaf(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1].lower()


def entropy(value: str) -> float:
    """Shannon entropy: higher values indicate less predictable text."""
    if not value:
        return 0.0
    counts = Counter(value.lower())
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


@dataclass(frozen=True)
class Event:
    """Vendor-neutral event envelope; details holds type-specific fields."""

    timestamp: datetime
    event_type: str
    host: str
    user: str
    source: str
    details: dict[str, Any]
    raw: dict[str, Any] = field(repr=False)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Event":
        known = {"timestamp", "event_type", "host", "user", "source"}
        missing = [name for name in ("timestamp", "event_type", "host") if not raw.get(name)]
        if missing:
            raise ValueError(f"Missing required event fields: {', '.join(missing)}")
        return cls(
            timestamp=utc(str(raw["timestamp"])),
            event_type=str(raw["event_type"]).lower(),
            host=str(raw["host"]).lower(),
            user=str(raw.get("user", "unknown")).lower(),
            source=str(raw.get("source", "unknown")).lower(),
            details={key: value for key, value in raw.items() if key not in known},
            raw=raw,
        )


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    confidence: str
    mitre_attack: tuple[str, ...]
    reason: str
    investigation: tuple[str, ...]
    evidence: dict[str, Any]
    timestamp: str
    host: str
    user: str


DEFAULTS: dict[str, Any] = {
    "brute_force_failures": 5,
    "brute_force_window_seconds": 600,
    "beacon_min_connections": 6,
    "beacon_interval_jitter_ratio": 0.15,
    "exfil_bytes": 100_000_000,
    "dns_min_queries": 20,
    "dns_window_seconds": 60,
    "dns_label_length": 45,
    "dns_entropy": 3.8,
    "unusual_login_start_hour": 0,
    "unusual_login_end_hour": 5,
    "critical_paths": ["c:/windows/system32/", "c:/windows/syswow64/", "/etc/", "/boot/", "/usr/bin/"],
    "run_key_fragments": ["software\\microsoft\\windows\\currentversion\\run"],
    "privileged_groups": ["domain admins", "enterprise admins", "administrators", "sudo", "wheel"],
    "service_accounts": [],
    "expected_countries": {},
    "known_devices": {},
    "server_hosts": [],
    "approved_lsass_readers": ["csrss.exe", "wininit.exe", "msmpeng.exe"],
}


class DetectionEngine:
    """Stateful correlation engine for ordered events from a bounded time window."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = DEFAULTS | (config or {})
        self.failed_logins: dict[str, deque[Event]] = defaultdict(deque)
        self.connections: dict[tuple[str, str, int], deque[Event]] = defaultdict(deque)
        self.dns_queries: dict[tuple[str, str], deque[Event]] = defaultdict(deque)

    def alert(
        self,
        event: Event,
        rule_id: str,
        title: str,
        severity: str,
        confidence: str,
        techniques: tuple[str, ...],
        reason: str,
        investigation: tuple[str, ...],
    ) -> Alert:
        return Alert(
            rule_id, title, severity, confidence, techniques, reason, investigation,
            event.raw, event.timestamp.isoformat(), event.host, event.user,
        )

    def process(self, event: Event) -> list[Alert]:
        """Route one normalized event to the relevant analytic."""
        handlers = {
            "process": self.process_event,
            "process_access": self.process_access,
            "api_call": self.process_access,
            "file": self.file_event,
            "registry": self.registry_event,
            "authentication": self.authentication,
            "group_change": self.group_change,
            "network": self.network,
            "dns": self.dns,
        }
        handler = handlers.get(event.event_type)
        return handler(event) if handler else []

    def process_event(self, event: Event) -> list[Alert]:
        d = event.details
        child = leaf(str(d.get("process_executable", d.get("process_name", ""))))
        parent = leaf(str(d.get("parent_executable", d.get("parent_name", ""))))
        path = str(d.get("process_executable", "")).lower().replace("\\", "/")
        office = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
        shells = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "sh", "bash"}
        web = {"w3wp.exe", "httpd.exe", "apache2", "nginx"}
        browsers = {"chrome.exe", "msedge.exe", "firefox.exe", "outlook.exe", "thunderbird.exe"}
        results: list[Alert] = []
        if parent in office and child in shells:
            results.append(self.alert(event, "PROC-001", "Office spawned an interpreter", "high", "medium", ("T1204", "T1059"), f"{parent} created {child}", ("Review the document and command line", "Check signer, hash, descendants, and network activity")))
        if parent in web and child in shells | {"whoami", "whoami.exe"}:
            results.append(self.alert(event, "PROC-002", "Web server spawned an interactive tool", "critical", "high", ("T1505.003", "T1059"), f"{parent} created {child}", ("Isolate the web workload if exploitation is corroborated", "Review web access logs and child processes")))
        expected = {"lsass.exe": "wininit.exe", "svchost.exe": "services.exe"}
        if child in expected and parent != expected[child]:
            results.append(self.alert(event, "PROC-003", "Protected-name process has unexpected parent", "critical", "medium", ("T1036"), f"Expected {expected[child]}, observed {parent or 'missing parent'}", ("Validate telemetry completeness", "Verify image path, signature, hash, and ProcessGuid")))
        if parent in browsers and ("/appdata/local/temp/" in path or path.startswith("/tmp/")):
            results.append(self.alert(event, "PROC-004", "User application launched temporary executable", "medium", "medium", ("T1204",), f"{parent} created {path}", ("Check download origin and file reputation", "Review user intent and subsequent activity")))
        return results

    def process_access(self, event: Event) -> list[Alert]:
        d = event.details
        source = leaf(str(d.get("source_process", "")))
        target = leaf(str(d.get("target_process", "")))
        api = str(d.get("api", "")).lower()
        access = str(d.get("granted_access", "")).lower()
        results: list[Alert] = []
        injection_apis = {"virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection", "queueuserapc"}
        if api in injection_apis:
            results.append(self.alert(event, "MEM-001", "Potential process-injection API", "high", "medium", ("T1055",), f"{source} invoked {api} against {target}", ("Correlate the full API sequence", "Inspect source signature, call stack, target, and resulting thread")))
        sensitive_masks = {"0x10", "0x1010", "0x1410", "0x1fffff", "process_vm_read"}
        approved = {name.lower() for name in self.config["approved_lsass_readers"]}
        if target == "lsass.exe" and source not in approved and access in sensitive_masks:
            results.append(self.alert(event, "CRED-001", "Unapproved LSASS memory access", "critical", "high", ("T1003.001",), f"{source} accessed LSASS with {access}", ("Validate source signature and call trace", "Preserve volatile evidence and inspect credential-access activity")))
        return results

    def file_event(self, event: Event) -> list[Alert]:
        d = event.details
        path = str(d.get("path", "")).lower().replace("\\", "/")
        action = str(d.get("action", "")).lower()
        executable = path.endswith((".exe", ".dll", ".sys", ".scr", ".ps1", ".sh"))
        critical = any(path.startswith(prefix.lower().replace("\\", "/")) for prefix in self.config["critical_paths"])
        temporary = "/temp/" in path or path.startswith("/tmp/")
        results = []
        if critical and action in {"created", "modified", "deleted", "renamed"}:
            results.append(self.alert(event, "FILE-001", "Critical path changed", "high", "medium", ("T1562.001", "T1036"), f"{action}: {path}", ("Compare hash and signer with the approved baseline", "Identify the writing process and change ticket")))
        if temporary and executable and action in {"created", "renamed"}:
            results.append(self.alert(event, "FILE-002", "Executable created in temporary path", "medium", "low", ("T1105",), f"{action}: {path}", ("Find the creating process", "Check hash prevalence and subsequent execution")))
        return results

    def registry_event(self, event: Event) -> list[Alert]:
        d = event.details
        key = str(d.get("key", "")).lower()
        action = str(d.get("action", "")).lower()
        if action in {"set", "created", "modified"} and any(part in key for part in self.config["run_key_fragments"]):
            return [self.alert(event, "REG-001", "Run-key persistence modified", "high", "medium", ("T1060", "T1547.001"), f"{action}: {key}", ("Inspect value data and writing process", "Validate signer, user intent, and installation change"))]
        return []

    def authentication(self, event: Event) -> list[Alert]:
        d = event.details
        outcome = str(d.get("outcome", "")).lower()
        logon_type = str(d.get("logon_type", "")).lower()
        key = f"{event.host}|{event.user}|{d.get('source_ip', '')}"
        window = timedelta(seconds=int(self.config["brute_force_window_seconds"]))
        queue = self.failed_logins[key]
        while queue and event.timestamp - queue[0].timestamp > window:
            queue.popleft()
        if outcome == "failure":
            queue.append(event)
            return []
        results: list[Alert] = []
        if outcome == "success" and len(queue) >= int(self.config["brute_force_failures"]):
            results.append(self.alert(event, "AUTH-001", "Failures followed by successful login", "high", "high", ("T1110", "T1078"), f"Success followed {len(queue)} failures inside {window}", ("Validate source IP and device", "Review activity after authentication")))
            queue.clear()
        start, end = int(self.config["unusual_login_start_hour"]), int(self.config["unusual_login_end_hour"])
        if outcome == "success" and start <= event.timestamp.hour < end:
            results.append(self.alert(event, "AUTH-002", "Login during configured unusual hours", "low", "low", ("T1078",), f"Successful login at {event.timestamp.hour:02d}:00 UTC", ("Compare with the user's schedule and history", "Do not escalate on time alone")))
        country = str(d.get("source_country", "")).upper()
        expected = {x.upper() for x in self.config["expected_countries"].get(event.user, [])}
        if outcome == "success" and country and expected and country not in expected:
            results.append(self.alert(event, "AUTH-003", "Login from unexpected country", "medium", "medium", ("T1078",), f"Observed {country}; expected {sorted(expected)}", ("Check VPN/proxy and IP reputation", "Confirm with the user through an approved channel")))
        device = str(d.get("device_id", ""))
        known = set(self.config["known_devices"].get(event.user, []))
        if outcome == "success" and device and known and device not in known:
            results.append(self.alert(event, "AUTH-004", "Login from a new device", "medium", "medium", ("T1078",), f"Device {device} is outside the configured baseline", ("Inspect device compliance and MFA result", "Compare browser, IP, and session behavior")))
        services = {x.lower() for x in self.config["service_accounts"]}
        if outcome == "success" and event.user in services and logon_type in {"interactive", "2", "10", "remoteinteractive"}:
            results.append(self.alert(event, "AUTH-005", "Service account used interactively", "high", "high", ("T1078.002",), f"{event.user} used logon type {logon_type}", ("Identify the operator and endpoint", "Rotate credentials if unauthorized")))
        return results

    def group_change(self, event: Event) -> list[Alert]:
        d = event.details
        group = str(d.get("group", "")).lower()
        action = str(d.get("action", "")).lower()
        if action in {"member_added", "added", "add"} and group in {x.lower() for x in self.config["privileged_groups"]}:
            return [self.alert(event, "PRIV-001", "Member added to privileged group", "high", "high", ("T1098", "T1078"), f"{d.get('target_user', 'unknown')} added to {group}", ("Validate the change ticket and actor", "Review the new member's sessions and changes"))]
        return []

    def network(self, event: Event) -> list[Alert]:
        d = event.details
        destination = str(d.get("destination_ip", ""))
        port = int(d.get("destination_port", 0) or 0)
        sent = int(d.get("bytes_sent", 0) or 0)
        key = (event.host, destination, port)
        queue = self.connections[key]
        queue.append(event)
        while len(queue) > 30:
            queue.popleft()
        results: list[Alert] = []
        minimum = int(self.config["beacon_min_connections"])
        if len(queue) >= minimum and destination and not private_ip(destination):
            intervals = [(b.timestamp - a.timestamp).total_seconds() for a, b in zip(queue, list(queue)[1:])]
            mean = statistics.fmean(intervals) if intervals else 0
            jitter = statistics.pstdev(intervals) / mean if mean > 0 else 1
            if mean >= 5 and jitter <= float(self.config["beacon_interval_jitter_ratio"]):
                results.append(self.alert(event, "NET-001", "Regular outbound connection pattern", "medium", "medium", ("T1071",), f"{len(queue)} connections to {destination}:{port}; mean {mean:.1f}s, jitter {jitter:.2f}", ("Extend the time range", "Check destination age/reputation and process ownership")))
                queue.clear()
        if sent >= int(self.config["exfil_bytes"]) and not private_ip(destination):
            results.append(self.alert(event, "NET-002", "Large outbound transfer", "high", "medium", ("T1041",), f"Sent {sent} bytes to {destination}:{port}", ("Compare volume with the host role and historical baseline", "Identify process, protocol, destination owner, and transferred data")))
        lateral_ports = {22: "SSH", 445: "SMB", 3389: "RDP"}
        source_ip = str(d.get("source_ip", ""))
        servers = {x.lower() for x in self.config["server_hosts"]}
        if port in lateral_ports and private_ip(source_ip) and private_ip(destination) and event.host not in servers:
            results.append(self.alert(event, "NET-003", "Workstation used a lateral-movement protocol", "medium", "low", ("T1021",), f"{event.host} connected to {destination} over {lateral_ports[port]}", ("Confirm the source and destination asset roles", "Correlate authentication and remote process/service events")))
        return results

    def dns(self, event: Event) -> list[Alert]:
        d = event.details
        query = str(d.get("query", "")).rstrip(".").lower()
        labels = query.split(".")
        registrable_guess = ".".join(labels[-2:]) if len(labels) >= 2 else query
        key = (event.host, registrable_guess)
        queue = self.dns_queries[key]
        window = timedelta(seconds=int(self.config["dns_window_seconds"]))
        queue.append(event)
        while queue and event.timestamp - queue[0].timestamp > window:
            queue.popleft()
        longest = max(labels, key=len, default="")
        suspicious_label = len(longest) >= int(self.config["dns_label_length"]) and entropy(longest) >= float(self.config["dns_entropy"])
        if len(queue) >= int(self.config["dns_min_queries"]) and suspicious_label:
            result = self.alert(event, "DNS-001", "High-volume encoded-looking DNS queries", "high", "medium", ("T1071.004",), f"{len(queue)} queries to {registrable_guess}; label length {len(longest)}, entropy {entropy(longest):.2f}", ("Inspect full query distribution and record types", "Check the requesting process and authoritative domain"))
            queue.clear()
            return [result]
        return []


def load_jsonl(path: Path) -> list[Event]:
    events = [Event.from_dict(json.loads(line)) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    return sorted(events, key=lambda event: event.timestamp)


def run(events: Iterable[Event], config: dict[str, Any] | None = None) -> list[Alert]:
    engine = DetectionEngine(config)
    return [alert for event in events for alert in engine.process(event)]


def risk_details(alert: Alert) -> dict[str, Any]:
    """Convert severity and confidence into a transparent triage score."""
    impact = {"low": 1, "medium": 2, "high": 3, "critical": 4}[alert.severity]
    certainty = {"low": 1, "medium": 2, "high": 3}[alert.confidence]
    score = round((impact * 0.65 + certainty * 0.35) / 4 * 100)
    if score >= 75:
        priority, target = "P1", "Acknowledge within 15 minutes"
    elif score >= 55:
        priority, target = "P2", "Acknowledge within 1 hour"
    elif score >= 35:
        priority, target = "P3", "Review during the same business day"
    else:
        priority, target = "P4", "Review within 3 business days"
    return {"score": score, "priority": priority, "response_target": target}


def case_id(alert: Alert) -> str:
    """Create a repeatable, non-secret identifier from stable alert fields."""
    identity = f"{alert.rule_id}|{alert.host}|{alert.user}|{alert.timestamp}|{alert.reason}"
    return "INC-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()


def incident_records(alerts: Iterable[Alert], environment: str = "training") -> list[dict[str, Any]]:
    """Turn alerts into visible analyst work items; low risk is never discarded."""
    records = []
    for alert in alerts:
        records.append({
            "case_id": case_id(alert),
            "environment": environment,
            "status": "NEW - ANALYST REVIEW REQUIRED",
            "owner": "UNASSIGNED",
            "disposition": "UNDETERMINED",
            "risk": risk_details(alert),
            "alert": asdict(alert),
            "recommended_solutions": recommendations(alert.rule_id),
            "analyst_notes": [],
            "audit_history": [{"timestamp": datetime.now(timezone.utc).isoformat(), "action": "case_created", "actor": "home-siem"}],
        })
    return sorted(records, key=lambda item: (-item["risk"]["score"], item["alert"]["timestamp"]))


def markdown_report(cases: list[dict[str, Any]]) -> str:
    """Produce a readable shift report without removing low-priority cases."""
    created = datetime.now(timezone.utc).isoformat()
    counts = Counter(case["risk"]["priority"] for case in cases)
    lines = [
        "# SIEM incident queue",
        "",
        f"Generated: `{created}`",
        "",
        f"Open cases: **{len(cases)}** — P1: {counts['P1']}, P2: {counts['P2']}, P3: {counts['P3']}, P4: {counts['P4']}",
        "",
        "> P4/low-risk cases remain visible and require a documented disposition. Risk score prioritizes review; it does not prove maliciousness.",
        "",
    ]
    for case in cases:
        alert, risk = case["alert"], case["risk"]
        lines.extend([
            f"## {case['case_id']} — {alert['title']}",
            "",
            f"- Status: **{case['status']}**",
            f"- Owner: **{case['owner']}**",
            f"- Priority / score: **{risk['priority']} / {risk['score']}**",
            f"- Response target: {risk['response_target']}",
            f"- Severity / confidence: {alert['severity']} / {alert['confidence']}",
            f"- Time / host / user: `{alert['timestamp']}` / `{alert['host']}` / `{alert['user']}`",
            f"- Rule / ATT&CK: `{alert['rule_id']}` / {', '.join(alert['mitre_attack'])}",
            f"- Reason: {alert['reason']}",
            "- Required follow-up:",
            *[f"  - [ ] {step}" for step in alert["investigation"]],
            "  - [ ] Record owner, evidence reviewed, decision, and rationale",
            "  - [ ] Set disposition: true positive, benign positive, false positive, or data-quality issue",
            "  - [ ] Close only after documenting follow-up or linking an escalated incident",
            "- Response choices (human approval required):",
            *[
                f"  - `{solution['solution_code']}` — {solution['action']} **System risk:** {solution['system_risk']}"
                for solution in case["recommended_solutions"]
            ],
            "",
        ])
    return "\n".join(lines)


def html_dashboard(cases: list[dict[str, Any]]) -> str:
    """Render a dependency-free, read-only front end for cases and response choices."""
    def esc(value: Any) -> str:
        return html.escape(str(value), quote=True)

    cards = []
    for case in cases:
        alert, risk = case["alert"], case["risk"]
        solutions = "".join(
            f"""
            <details class="solution">
              <summary><code>{esc(item['solution_code'])}</code> — {esc(item['action'])}</summary>
              <dl>
                <dt>Security benefit</dt><dd>{esc(item['benefit'])}</dd>
                <dt>Risk to server/functionality</dt><dd class="warning">{esc(item['system_risk'])}</dd>
                <dt>Use when</dt><dd>{esc(item['when'])}</dd>
                <dt>Approval</dt><dd>{esc(item['approval'])}</dd>
                <dt>Rollback</dt><dd>{esc(item['rollback'])}</dd>
              </dl>
            </details>"""
            for item in case["recommended_solutions"]
        )
        cards.append(f"""
        <article class="case">
          <header><span class="priority {esc(risk['priority'])}">{esc(risk['priority'])}</span>
            <h2>{esc(case['case_id'])} — {esc(alert['title'])}</h2></header>
          <p><strong>Environment:</strong> {esc(case.get('environment', 'unknown'))} · <strong>Status:</strong> {esc(case['status'])} · <strong>Score:</strong> {esc(risk['score'])}/100 ·
             <strong>Host:</strong> {esc(alert['host'])} · <strong>User:</strong> {esc(alert['user'])}</p>
          <p><strong>Reason:</strong> {esc(alert['reason'])}</p>
          <p><strong>Alert code:</strong> <code>{esc(alert['rule_id'])}</code> ·
             <strong>Response target:</strong> {esc(risk['response_target'])}</p>
          <h3>Five response choices</h3>
          <p class="notice">Choose only after validating evidence, dependencies, authority, and rollback readiness.</p>
          {solutions}
        </article>""")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Home SIEM incident queue</title><style>
:root{{--bg:#0b1220;--panel:#121d31;--text:#e8eef8;--muted:#a9b8cf;--line:#2a3951;--warn:#ffd27a}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}}
main{{max-width:1100px;margin:auto;padding:28px}} .case{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px;margin:18px 0}}
header{{display:flex;gap:12px;align-items:center}} h1,h2,h3{{line-height:1.2}} h2{{font-size:19px;margin:0}} code{{color:#9fcbff}}
.priority{{padding:5px 9px;border-radius:7px;font-weight:800}} .P1{{background:#8b1e2d}} .P2{{background:#9a4b16}} .P3{{background:#756312}} .P4{{background:#24577b}}
.solution{{border-top:1px solid var(--line);padding:11px 0}} summary{{cursor:pointer;font-weight:650}} dl{{display:grid;grid-template-columns:190px 1fr;gap:7px;margin-left:20px}}
dt{{color:var(--muted)}} dd{{margin:0}} .warning{{color:var(--warn)}} .notice{{color:var(--warn)}}
@media(max-width:650px){{dl{{grid-template-columns:1fr}} header{{align-items:flex-start}}}}
</style></head><body><main><h1>SIEM incident queue</h1>
<p>Every detected alert is visible. Recommendations are advisory and never execute containment automatically.</p>
{''.join(cards) if cards else '<p>No alert cases were generated for this input.</p>'}
</main></body></html>"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Defensive SIEM correlation learning lab")
    parser.add_argument("events", type=Path, help="normalized JSON Lines input")
    parser.add_argument("--environment", choices=RUNTIME_ENVIRONMENTS, help="prompted when omitted")
    parser.add_argument("--config", type=Path, default=Path("siem_config.json"))
    parser.add_argument("--output", type=Path, default=Path("alerts.json"))
    parser.add_argument("--cases", type=Path, default=Path("incident_cases.json"))
    parser.add_argument("--report", type=Path, default=Path("incident_report.md"))
    parser.add_argument("--dashboard", type=Path, default=Path("incident_dashboard.html"))
    parser.add_argument("--solutions", type=Path, default=Path("solutions_catalog.json"))
    args = parser.parse_args()
    environment = choose_environment(args.environment)
    config = json.loads(args.config.read_text(encoding="utf-8")) if args.config.exists() else {}
    validate_playbooks()
    events = load_jsonl(args.events)
    alerts = run(events, config)
    args.output.write_text(json.dumps([asdict(item) for item in alerts], indent=2), encoding="utf-8")
    cases = incident_records(alerts, environment)
    args.cases.write_text(json.dumps(cases, indent=2), encoding="utf-8")
    args.report.write_text(markdown_report(cases), encoding="utf-8")
    args.dashboard.write_text(html_dashboard(cases), encoding="utf-8")
    args.solutions.write_text(json.dumps(solution_catalog(), indent=2), encoding="utf-8")
    print(f"Processed {len(events)} events; wrote {len(alerts)} alerts, {len(cases)} cases, the dashboard, report, and solution catalog")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
