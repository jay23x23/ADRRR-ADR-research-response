#!/usr/bin/env python3
"""Local-only EDR connector setup UI backed by the operating-system credential store."""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from vendor_connectors import CrowdStrikeConnector, DefenderEndpointConnector, SentinelOneConnector
from sigma_catalog_builder import ENVIRONMENTS


HOST, PORT = "127.0.0.1", 8765
CSRF_TOKEN = secrets.token_urlsafe(32)
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}
ALLOWED_ORIGINS = {f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"}
CONFIG_PATH = Path("connector_profiles.json")
FIELDS = {
    "mde": ("MDE_TENANT_ID", "MDE_CLIENT_ID", "MDE_CLIENT_SECRET"),
    "crowdstrike": ("FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL"),
    "sentinelone": ("S1_CONSOLE_URL", "S1_API_TOKEN", "S1_THREATS_PATH"),
}
SECRET_FIELDS = {"MDE_CLIENT_SECRET", "FALCON_CLIENT_SECRET", "S1_API_TOKEN"}


HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIEM connector setup</title><style>body{font:16px system-ui;max-width:760px;margin:30px auto;padding:20px;background:#0b1220;color:#edf3fb}form{background:#142039;padding:22px;border-radius:12px}label{display:block;margin:13px 0 5px}input,select,button{width:100%;padding:10px;font:inherit}button{margin-top:18px;background:#3d7fd6;color:white;border:0;border-radius:7px}pre{white-space:pre-wrap}.warn{color:#ffd27a}</style></head>
<body><h1>Connect an EDR</h1><p class="warn">This page is served only on 127.0.0.1. Secrets go to the OS credential store and are never returned to the browser or written to connector_profiles.json.</p>
<form id="f"><label>Profile name</label><input name="profile" value="default" required pattern="[A-Za-z0-9_.-]+">
<label>Environment</label><select name="environment"><option>windows_11</option><option>windows_server</option><option>linux_mint</option><option>ubuntu</option><option>ubuntu_server</option></select>
<label>EDR</label><select name="source" id="source"><option value="mde">Microsoft Defender for Endpoint</option><option value="crowdstrike">CrowdStrike Falcon</option><option value="sentinelone">SentinelOne Singularity</option></select>
<div id="fields"></div><label><input style="width:auto" type="checkbox" name="test" checked> Test read-only connection before saving profile</label><button>Test and save securely</button></form><pre id="result"></pre>
<script>const specs={mde:[['MDE_TENANT_ID','Tenant ID','text'],['MDE_CLIENT_ID','Client ID','text'],['MDE_CLIENT_SECRET','Client secret','password']],crowdstrike:[['FALCON_CLIENT_ID','Client ID','text'],['FALCON_CLIENT_SECRET','Client secret','password'],['FALCON_BASE_URL','Regional API URL','url']],sentinelone:[['S1_CONSOLE_URL','Console URL','url'],['S1_API_TOKEN','Read-only API token','password'],['S1_THREATS_PATH','Threats API path','text']]};
function draw(){fields.innerHTML=specs[source.value].map(x=>`<label>${x[1]}</label><input name="${x[0]}" type="${x[2]}" required>`).join('')} source.onchange=draw;draw();
f.onsubmit=async e=>{e.preventDefault();result.textContent='Testing…';const data=Object.fromEntries(new FormData(f));data.test=f.elements.test.checked;const r=await fetch('/api/save',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':'__TOKEN__'},body:JSON.stringify(data)});result.textContent=JSON.stringify(await r.json(),null,2)};</script></body></html>""".replace("__TOKEN__", CSRF_TOKEN)


def profiles() -> list[dict[str, Any]]:
    if not CONFIG_PATH.exists():
        return []
    value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    return value if isinstance(value, list) else []


def save(payload: dict[str, Any]) -> dict[str, Any]:
    import keyring
    source, profile = str(payload["source"]), str(payload["profile"])
    if source not in FIELDS or payload.get("environment") not in ENVIRONMENTS or not profile.replace("-", "").replace("_", "").replace(".", "").isalnum():
        raise ValueError("Invalid connector source or profile name")
    service = f"home-siem:{profile}"
    previous = {name: keyring.get_password(service, name) for name in FIELDS[source]}
    try:
        for name in FIELDS[source]:
            value = str(payload.get(name, ""))
            if not value:
                raise ValueError(f"Missing {name}")
            keyring.set_password(service, name, value)
        connector = {"mde": DefenderEndpointConnector, "crowdstrike": CrowdStrikeConnector, "sentinelone": SentinelOneConnector}[source](profile)
        count = None
        if payload.get("test"):
            count = len(connector.fetch(datetime.now(timezone.utc) - timedelta(minutes=5)))
    except Exception:
        for name, value in previous.items():
            if value is None:
                try:
                    keyring.delete_password(service, name)
                except keyring.errors.PasswordDeleteError:
                    pass
            else:
                keyring.set_password(service, name, value)
        raise
    items = [item for item in profiles() if item.get("profile") != profile]
    items.append({"profile": profile, "source": source, "environment": payload["environment"], "tested_at": datetime.now(timezone.utc).isoformat() if payload.get("test") else None})
    CONFIG_PATH.write_text(json.dumps(items, indent=2), encoding="utf-8")
    return {"ok": True, "profile": profile, "source": source, "alerts_seen_during_test": count, "message": "Credentials saved in the OS credential store"}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return  # Avoid logging request data.

    def reply(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status); self.send_header("Content-Type", content_type); self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(body)

    def do_GET(self) -> None:
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            self.reply(421, b"untrusted host", "text/plain"); return
        if self.path != "/":
            self.reply(404, b"not found", "text/plain"); return
        self.reply(200, HTML.encode(), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if self.headers.get("Host", "") not in ALLOWED_HOSTS or self.headers.get("Origin") not in ALLOWED_ORIGINS or self.path != "/api/save" or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), CSRF_TOKEN):
            self.reply(403, b'{"ok":false,"error":"forbidden"}', "application/json"); return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if size <= 0 or size > 32768:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(size))
            result, status = save(payload), 200
        except Exception as error:
            result, status = {"ok": False, "error": str(error)}, 400
        self.reply(status, json.dumps(result).encode(), "application/json")


def main() -> int:
    print(f"Open http://{HOST}:{PORT} — press Ctrl+C to stop the local setup service")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
