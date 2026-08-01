#!/usr/bin/env python3
"""Read-only alert connectors and conservative Sigma catalogue matching."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from sigma_catalog_builder import ENVIRONMENTS, select_environment
from security_controls import validate_https_url


def credential(name: str, profile: str = "default") -> str:
    """Read a credential from the environment first, then the OS credential store."""
    if os.environ.get(name):
        return str(os.environ[name])
    try:
        import keyring
    except ImportError as error:
        raise RuntimeError(f"Missing {name}; install keyring or set the environment variable") from error
    value = keyring.get_password(f"home-siem:{profile}", name)
    if not value:
        raise RuntimeError(f"Missing credential {name} for profile {profile}")
    return value


@dataclass(frozen=True)
class VendorAlert:
    timestamp: str
    source: str
    vendor_alert_id: str
    title: str
    description: str
    severity: str
    status: str
    host: str
    user: str
    mitre_attack: tuple[str, ...]
    raw: dict[str, Any]


def iso(value: Any) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return str(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def techniques(value: Any) -> tuple[str, ...]:
    matches = re.findall(r"\bT\d{4}(?:\.\d{3})?\b", json.dumps(value), flags=re.IGNORECASE)
    return tuple(sorted({item.upper() for item in matches}))


def request_json(url: str, *, headers: dict[str, str] | None = None, data: dict[str, Any] | None = None) -> dict[str, Any]:
    encoded = None if data is None else urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(url, data=encoded, headers=headers or {})
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            raise RuntimeError("HTTP redirects are disabled for connector requests")
    with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def bearer_json(url: str, token: str) -> dict[str, Any]:
    return request_json(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})


class LocalDefenderConnector:
    """Read Microsoft Defender Antivirus Operational events on this Windows host."""

    EVENT_IDS = (1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 1120, 1121, 1122, 1123, 1124, 1127, 1150, 1151)

    def fetch(self, since: datetime) -> list[VendorAlert]:
        if os.name != "nt":
            raise RuntimeError("local_defender is available only on Windows")
        ids = ",".join(str(value) for value in self.EVENT_IDS)
        script = rf"""
$events = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Windows Defender/Operational'; Id={ids}; StartTime=[datetime]::Parse('{since.isoformat()}')}} -ErrorAction Stop
$events | ForEach-Object {{
  $xml = [xml]$_.ToXml()
  $data = @{{}}
  foreach ($node in $xml.Event.EventData.Data) {{ $data[[string]$node.Name] = [string]$node.'#text' }}
  [pscustomobject]@{{timestamp=$_.TimeCreated.ToUniversalTime().ToString('o'); id=[string]$_.RecordId; event_id=$_.Id; title=$_.LevelDisplayName; message=$_.Message; host=$_.MachineName; data=$data}}
}} | ConvertTo-Json -Depth 8 -Compress
"""
        completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], check=True, capture_output=True, text=True)
        if not completed.stdout.strip():
            return []
        value = json.loads(completed.stdout)
        rows = value if isinstance(value, list) else [value]
        return [VendorAlert(
            timestamp=iso(row.get("timestamp")), source="microsoft_defender_local",
            vendor_alert_id=f"defender-event-{row.get('id')}",
            title=f"Microsoft Defender event {row.get('event_id')}: {row.get('title', '')}",
            description=str(row.get("message", "")), severity="unknown", status="observed",
            host=str(row.get("host", "unknown")), user=str((row.get("data") or {}).get("User", "unknown")),
            mitre_attack=techniques(row), raw=row,
        ) for row in rows]


class LocalWindowsFirewallConnector:
    """Read blocked/allowed Windows Filtering Platform events from the local Security log."""

    EVENT_IDS = (5152, 5154, 5156, 5157, 5158)

    def fetch(self, since: datetime) -> list[VendorAlert]:
        if os.name != "nt": raise RuntimeError("local_windows_firewall is available only on Windows")
        ids = ",".join(str(value) for value in self.EVENT_IDS)
        script = rf"""
$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; Id={ids}; StartTime=[datetime]::Parse('{since.isoformat()}')}} -ErrorAction Stop
$events | ForEach-Object {{
  $xml = [xml]$_.ToXml(); $data = @{{}}
  foreach ($node in $xml.Event.EventData.Data) {{ $data[[string]$node.Name] = [string]$node.'#text' }}
  [pscustomobject]@{{timestamp=$_.TimeCreated.ToUniversalTime().ToString('o'); id=[string]$_.RecordId; event_id=$_.Id; message=$_.Message; host=$_.MachineName; data=$data}}
}} | ConvertTo-Json -Depth 8 -Compress
"""
        completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], check=True, capture_output=True, text=True)
        if not completed.stdout.strip(): return []
        value = json.loads(completed.stdout); rows = value if isinstance(value, list) else [value]
        return [VendorAlert(
            timestamp=iso(row.get("timestamp")), source="windows_firewall_local", vendor_alert_id=f"firewall-event-{row.get('id')}",
            title=f"Windows Firewall event {row.get('event_id')}", description=str(row.get("message", "")),
            severity="medium" if int(row.get("event_id", 0)) in {5152, 5157} else "informational", status="observed",
            host=str(row.get("host", "unknown")), user=str((row.get("data") or {}).get("UserID", "unknown")),
            mitre_attack=techniques(row), raw={**row, "source_ip": (row.get("data") or {}).get("SourceAddress", ""), "destination_ip": (row.get("data") or {}).get("DestAddress", ""), "destination_port": (row.get("data") or {}).get("DestPort", "")},
        ) for row in rows]


class DefenderEndpointConnector:
    """Import Microsoft Defender for Endpoint alerts using application OAuth."""

    def __init__(self, profile: str = "default") -> None:
        self.tenant = credential("MDE_TENANT_ID", profile)
        self.client = credential("MDE_CLIENT_ID", profile)
        self.secret = credential("MDE_CLIENT_SECRET", profile)

    def token(self) -> str:
        result = request_json(
            f"https://login.microsoftonline.com/{urllib.parse.quote(self.tenant)}/oauth2/v2.0/token",
            data={"client_id": self.client, "client_secret": self.secret, "grant_type": "client_credentials", "scope": "https://api.security.microsoft.com/.default"},
        )
        return str(result["access_token"])

    def fetch(self, since: datetime) -> list[VendorAlert]:
        token = self.token()
        filter_value = urllib.parse.quote(f"lastUpdateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}")
        url = f"https://api.security.microsoft.com/api/alerts?$filter={filter_value}"
        rows: list[dict[str, Any]] = []
        while url:
            if urllib.parse.urlsplit(url).hostname != "api.security.microsoft.com":
                raise RuntimeError("Defender pagination attempted to leave the approved API host")
            page = bearer_json(url, token)
            rows.extend(page.get("value", []))
            url = str(page.get("@odata.nextLink", ""))
        return [VendorAlert(
            timestamp=iso(row.get("alertCreationTime") or row.get("lastUpdateTime")), source="microsoft_defender_endpoint",
            vendor_alert_id=str(row.get("id", "unknown")), title=str(row.get("title", "Untitled Defender alert")),
            description=str(row.get("description", "")), severity=str(row.get("severity", "unknown")).lower(),
            status=str(row.get("status", "unknown")).lower(), host=str(row.get("computerDnsName") or row.get("machineId") or "unknown"),
            user=str(row.get("userPrincipalName") or "unknown"), mitre_attack=techniques(row), raw=row,
        ) for row in rows]


class CrowdStrikeConnector:
    """Import Falcon alerts through CrowdStrike's supported FalconPy SDK."""

    def __init__(self, profile: str = "default") -> None:
        self.profile = profile

    def fetch(self, since: datetime) -> list[VendorAlert]:
        try:
            from falconpy import Alerts
        except ImportError as error:
            raise RuntimeError("Install crowdstrike-falconpy from requirements-connectors.txt") from error
        base_url = validate_https_url(credential("FALCON_BASE_URL", self.profile))
        client = Alerts(
            client_id=credential("FALCON_CLIENT_ID", self.profile), client_secret=credential("FALCON_CLIENT_SECRET", self.profile),
            base_url=base_url,
        )
        after, rows = None, []
        filter_value = f"updated_timestamp:>='{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"
        while True:
            response = client.get_alerts_combined(filter=filter_value, limit=1000, sort="updated_timestamp.asc", after=after)
            if int(response.get("status_code", 500)) >= 400:
                raise RuntimeError(f"Falcon Alerts API failed: {response.get('body', {}).get('errors', response)}")
            body = response.get("body", {})
            rows.extend(body.get("resources", []))
            after = ((body.get("meta") or {}).get("pagination") or {}).get("after")
            if not after:
                break
        return [VendorAlert(
            timestamp=iso(row.get("updated_timestamp") or row.get("created_timestamp")), source="crowdstrike_falcon",
            vendor_alert_id=str(row.get("composite_id") or row.get("id") or "unknown"),
            title=str(row.get("name") or row.get("display_name") or "Untitled Falcon alert"),
            description=str(row.get("description") or row.get("objective") or ""), severity=str(row.get("severity_name") or row.get("severity") or "unknown").lower(),
            status=str(row.get("status") or "unknown").lower(), host=str(row.get("hostname") or row.get("device", {}).get("hostname") or "unknown"),
            user=str(row.get("user_name") or row.get("user", {}).get("name") or "unknown"), mitre_attack=techniques(row), raw=row,
        ) for row in rows]


class SentinelOneConnector:
    """Import Singularity threats; console URL and versioned path are configurable."""

    def __init__(self, profile: str = "default") -> None:
        self.profile = profile

    def fetch(self, since: datetime) -> list[VendorAlert]:
        console = validate_https_url(credential("S1_CONSOLE_URL", self.profile))
        token = credential("S1_API_TOKEN", self.profile)
        try:
            path = credential("S1_THREATS_PATH", self.profile)
        except RuntimeError:
            path = "/web/api/v2.1/threats"
        if not path.startswith("/web/api/") or ".." in path or "://" in path:
            raise ValueError("SentinelOne API path must remain under /web/api/")
        cursor, rows = "", []
        while True:
            query = {"createdAt__gte": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "limit": "1000"}
            if cursor:
                query["cursor"] = cursor
            url = f"{console}{path}?{urllib.parse.urlencode(query)}"
            page = request_json(url, headers={"Authorization": f"ApiToken {token}", "Accept": "application/json"})
            data = page.get("data", page)
            rows.extend(data if isinstance(data, list) else data.get("threats", []))
            cursor = str((page.get("pagination") or {}).get("nextCursor") or "")
            if not cursor:
                break
        return [VendorAlert(
            timestamp=iso(row.get("createdAt") or row.get("updatedAt")), source="sentinelone_singularity",
            vendor_alert_id=str(row.get("id") or row.get("threatInfo", {}).get("threatId") or "unknown"),
            title=str(row.get("threatInfo", {}).get("threatName") or row.get("name") or "Untitled SentinelOne threat"),
            description=str(row.get("description") or row.get("threatInfo", {}).get("classification") or ""),
            severity=str(row.get("threatInfo", {}).get("confidenceLevel") or row.get("severity") or "unknown").lower(),
            status=str(row.get("threatInfo", {}).get("incidentStatus") or row.get("status") or "unknown").lower(),
            host=str(row.get("agentRealtimeInfo", {}).get("agentComputerName") or row.get("agentDetectionInfo", {}).get("name") or "unknown"),
            user=str(row.get("agentDetectionInfo", {}).get("agentLastLoggedInUserName") or "unknown"), mitre_attack=techniques(row), raw=row,
        ) for row in rows]


def tokens(value: str) -> set[str]:
    stop = {"the", "and", "for", "from", "with", "alert", "detection", "suspicious", "potential"}
    return {word for word in re.findall(r"[a-z0-9]+", value.lower()) if len(word) >= 3 and word not in stop}


def load_catalog(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]


def match_alert(alert: VendorAlert, catalog: Iterable[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    """Rank candidate rules; this is correlation assistance, not exact attribution."""
    alert_words, alert_techniques = tokens(alert.title + " " + alert.description), set(alert.mitre_attack)
    candidates = []
    for rule in catalog:
        rule_words = tokens(str(rule.get("title", "")) + " " + str(rule.get("description", "")))
        rule_techniques = {tag.split("attack.", 1)[1].upper() for tag in rule.get("tags", []) if str(tag).lower().startswith("attack.t")}
        technique_overlap = alert_techniques & rule_techniques
        union = alert_words | rule_words
        title_score = len(alert_words & rule_words) / len(union) if union else 0.0
        score = min(1.0, (0.7 if technique_overlap else 0.0) + 0.3 * title_score)
        if score >= 0.12:
            candidates.append({
                "alert_rule_id": rule.get("alert_rule_id"), "title": rule.get("title"),
                "score": round(score, 3), "match_type": "candidate",
                "reasons": ([f"ATT&CK overlap: {', '.join(sorted(technique_overlap))}"] if technique_overlap else []) + [f"title similarity: {title_score:.3f}"],
                "solution_codes": rule.get("solution_codes", []),
            })
    return sorted(candidates, key=lambda item: (-item["score"], str(item["alert_rule_id"])))[:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description="Import and normalize endpoint security alerts")
    parser.add_argument("--source", choices=("local_defender", "local_windows_firewall", "mde", "crowdstrike", "sentinelone"), required=True)
    parser.add_argument("--environment", choices=ENVIRONMENTS, help="prompted when omitted")
    parser.add_argument("--profile", default="default", help="credential-store profile created by connector_setup.py")
    parser.add_argument("--catalog", type=Path, required=True, help="matching environment_alerts.jsonl")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--output", type=Path, default=Path("imported_vendor_alerts.jsonl"))
    args = parser.parse_args()
    environment = select_environment(args.environment)
    compatible = {
        "local_defender": {"windows_11", "windows_server"}, "local_windows_firewall": {"windows_11", "windows_server"},
        "mde": set(ENVIRONMENTS), "crowdstrike": set(ENVIRONMENTS), "sentinelone": set(ENVIRONMENTS),
    }
    if environment not in compatible[args.source]:
        raise SystemExit(f"{args.source} is not compatible with {environment}")
    connectors = {
        "local_defender": LocalDefenderConnector, "local_windows_firewall": LocalWindowsFirewallConnector,
        "mde": DefenderEndpointConnector,
        "crowdstrike": CrowdStrikeConnector,
        "sentinelone": SentinelOneConnector,
    }
    since = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    connector = connectors[args.source]() if args.source in {"local_defender", "local_windows_firewall"} else connectors[args.source](args.profile)
    alerts = connector.fetch(since)
    catalog = load_catalog(args.catalog)
    output = [{"environment": environment, "vendor_alert": asdict(alert), "candidate_rule_matches": match_alert(alert, catalog)} for alert in alerts]
    args.output.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in output), encoding="utf-8")
    print(f"Imported {len(alerts)} alerts from {args.source}; wrote normalized candidates to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
