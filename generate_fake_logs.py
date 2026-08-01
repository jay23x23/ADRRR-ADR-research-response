#!/usr/bin/env python3
"""Generate deterministic, synthetic SOC training telemetry for EDRRR.

Nothing in this file executes suspicious commands. It only writes inert log text.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "fake_logs"
BASE = datetime(2026, 7, 30, 8, 0, tzinfo=timezone.utc)


def event(offset: int, event_type: str, host: str, user: str, source: str, **details: object) -> dict:
    return {"timestamp": (BASE + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z"),
            "event_type": event_type, "host": host, "user": user, "source": source, **details}


def write_jsonl(name: str, rows: list[dict]) -> None:
    (OUT / name).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def windows_pack() -> list[dict]:
    rows = []
    # Normal enterprise background activity provides realistic analyst noise.
    for i in range(80):
        rows.append(event(i * 17, "process", "W11-FIN-042", "j.smith", "sysmon:1",
            process_executable=[r"C:\\Windows\\System32\\RuntimeBroker.exe", r"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"][i % 3],
            process_pid=str(4100 + i), process_command_line="normal signed application activity",
            parent_executable=r"C:\\Windows\\explorer.exe", parent_pid="1840"))
    suspicious = [
        event(1500, "process", "W11-FIN-042", "j.smith", "sysmon:1", process_executable=r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", process_pid="8120", process_command_line="powershell.exe -NoProfile -EncodedCommand <redacted-training-value>", parent_executable=r"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", parent_pid="7704"),
        event(1510, "file", "W11-FIN-042", "j.smith", "sysmon:11", path=r"C:\\Users\\j.smith\\AppData\\Local\\Temp\\update-check.exe", action="created", process_executable=r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
        event(1520, "process", "W11-FIN-042", "j.smith", "sysmon:1", process_executable=r"C:\\Users\\j.smith\\AppData\\Local\\Temp\\update-check.exe", process_pid="8177", process_command_line="update-check.exe --silent", parent_executable=r"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", parent_pid="7312"),
        event(1530, "registry", "W11-FIN-042", "j.smith", "sysmon:13", key=r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater", action="set", value=r"C:\\Users\\j.smith\\AppData\\Local\\Temp\\update-check.exe"),
        event(1540, "process_access", "W11-FIN-042", "j.smith", "sysmon:10", source_process=r"C:\\Users\\j.smith\\AppData\\Local\\Temp\\update-check.exe", target_process=r"C:\\Windows\\System32\\lsass.exe", granted_access="0x1010"),
        event(1550, "process", "W11-FIN-042", "SYSTEM", "sysmon:1", process_executable=r"C:\\Windows\\System32\\svchost.exe", process_pid="8220", process_command_line="svchost.exe -k fake-training", parent_executable=r"C:\\Users\\Public\\service-wrapper.exe", parent_pid="8200"),
        event(1560, "group_change", "DC-LAB-01", "LAB\\administrator", "security:4728", action="member_added", target_user="LAB\\temp.contractor", group="Domain Admins"),
    ]
    rows.extend(suspicious)
    # Brute-force then success, plus lateral movement and exfiltration.
    for i in range(7):
        rows.append(event(1600 + i * 12, "authentication", "W11-FIN-042", "j.smith", "security:4625", outcome="failure", source_ip="198.51.100.77", logon_type="10", device_id="UNKNOWN-RDP"))
    rows.append(event(1690, "authentication", "W11-FIN-042", "j.smith", "security:4624", outcome="success", source_ip="198.51.100.77", logon_type="10", device_id="UNKNOWN-RDP"))
    rows.append(event(1700, "network", "W11-FIN-042", "j.smith", "firewall", source_ip="10.20.4.42", destination_ip="10.20.8.15", destination_port=445, bytes_sent=34000, process_executable="powershell.exe", outcome="allowed"))
    rows.append(event(1720, "network", "W11-FIN-042", "j.smith", "firewall", source_ip="10.20.4.42", destination_ip="8.8.4.4", destination_port=443, bytes_sent=734003200, process_executable="update-check.exe", outcome="allowed"))
    return rows


def linux_pack(host: str, server: bool = False) -> list[dict]:
    rows = []
    parent = "/usr/sbin/nginx" if server else "/usr/bin/gnome-shell"
    for i in range(70):
        rows.append(event(i * 19, "process", host, "root" if server else "analyst", "auditd:execve",
            process_executable=["/usr/bin/systemctl", "/usr/bin/python3", "/usr/bin/apt", "/usr/bin/dbus-daemon"][i % 4], process_pid=str(2200+i),
            process_command_line="routine operating-system activity", parent_executable="/usr/lib/systemd/systemd", parent_pid="1"))
    rows.extend([
        event(1800, "process", host, "www-data", "auditd:execve", process_executable="/usr/bin/bash", process_pid="9050", process_command_line="bash -c id", parent_executable=parent if server else "/usr/sbin/apache2", parent_pid="1440"),
        event(1810, "file", host, "root", "auditd:path", path="/etc/cron.d/system-health", action="created", process_executable="/usr/bin/bash"),
        event(1820, "file", host, "analyst", "auditd:path", path="/tmp/.cache-helper.sh", action="created", process_executable="/usr/bin/curl"),
        event(1830, "group_change", host, "root", "linux:usermod", action="member_added", target_user="support-temp", group="sudo"),
        event(1840, "network", host, "www-data", "firewall", source_ip="10.30.5.20", destination_ip="10.30.5.31", destination_port=22, bytes_sent=8000, process_executable="bash", outcome="allowed"),
        event(1850, "network", host, "www-data", "firewall", source_ip="10.30.5.20", destination_ip="8.8.4.4", destination_port=443, bytes_sent=943718400, process_executable="curl", outcome="allowed"),
    ])
    for i in range(8):
        rows.append(event(1900+i*8, "authentication", host, "backup", "linux:auth", outcome="failure", source_ip="203.0.113.55"))
    rows.append(event(1970, "authentication", host, "backup", "linux:auth", outcome="success", source_ip="203.0.113.55"))
    return rows


def network_pack() -> list[dict]:
    rows = []
    for i in range(100):
        rows.append(event(i * 23, "network", f"W11-SALES-{i%12:03d}", "employee", "firewall:traffic",
            source_ip=f"10.40.2.{20+i%12}", destination_ip="192.0.2.10", destination_port=443,
            bytes_sent=12000+(i*31), process_executable="chrome.exe", outcome="allowed"))
    for i in range(12):
        rows.append(event(2600+i*60, "network", "W11-HR-009", "a.jones", "firewall:traffic", source_ip="10.40.9.9",
            destination_ip="1.1.1.1", destination_port=8443, bytes_sent=4200, process_executable="rundll32.exe", outcome="allowed"))
    label = "a9f3k7q2w8m4z6x1c5v0b7n2d9s4j8h6p3t1r5y7u0e2i4o6"
    for i in range(25):
        rows.append(event(3500+i*2, "dns", "W11-HR-009", "a.jones", "sysmon:22", query=f"{label}{i:02d}.telemetry-example.invalid", response="NXDOMAIN", process_executable="rundll32.exe"))
    return rows


def edr_pack(vendor: str) -> list[dict]:
    names = {
        "defender": "Microsoft Defender for Endpoint",
        "crowdstrike": "CrowdStrike Falcon",
        "sentinelone": "SentinelOne Singularity",
    }
    rows = []
    for i in range(30):
        rows.append({"timestamp": (BASE+timedelta(minutes=i)).isoformat().replace("+00:00","Z"), "source": vendor,
          "vendor": names[vendor], "vendor_alert_id": f"{vendor.upper()}-TRAIN-{i+1:04d}",
          "title": ["Suspicious PowerShell behavior", "Credential access behavior", "Malicious persistence attempt", "Possible command-and-control traffic", "Remote service activity"][i%5],
          "severity": ["medium", "high", "critical"][i%3], "host": f"TRAIN-{i%6:02d}", "user": f"lab-user-{i%4}",
          "status": "new", "description": "Synthetic training alert modelled on common EDR alert fields; no malicious action occurred.",
          "mitre_attack": [["T1059.001"], ["T1003.001"], ["T1547.001"], ["T1071.001"], ["T1021"]][i%5],
          "process": {"name": ["powershell.exe","unknown-reader.exe","reg.exe","rundll32.exe","wmic.exe"][i%5], "command_line": "<redacted synthetic training command>"},
          "network": {"remote_ip": f"203.0.113.{20+i}", "remote_port": 443}, "evidence": {"confidence": 60+(i%4)*10, "training": True}})
    return rows


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    packs = {
        "windows11-normalized.jsonl": windows_pack(),
        "ubuntu-desktop-normalized.jsonl": linux_pack("UBU-DESK-017"),
        "ubuntu-server-normalized.jsonl": linux_pack("UBU-WEB-01", True),
        "firewall-dns-normalized.jsonl": network_pack(),
    }
    for name, rows in packs.items():
        write_jsonl(name, rows)
        # Keep a root-level copy because EDRRR's original detection-lab API
        # intentionally accepts only files located directly in the app folder.
        (ROOT / f"training-{name}").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    small_windows = [row for row in packs["windows11-normalized.jsonl"]
                     if row.get("source") in {"sysmon:1", "sysmon:10"}
                     and ("WINWORD" in str(row) or row.get("event_type") == "process_access")]
    small_linux = [event(i * 20, "authentication", "training-ubuntu", "demo", "linux:auth",
                         outcome="failure", source_ip="203.0.113.55") for i in range(5)]
    small_linux.append(event(110, "authentication", "training-ubuntu", "demo", "linux:auth",
                             outcome="success", source_ip="203.0.113.55"))
    (ROOT / "training-windows-sysmon-sample.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in small_windows), encoding="utf-8")
    (ROOT / "training-linux-auth-sample.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in small_linux), encoding="utf-8")
    for vendor in ("defender", "crowdstrike", "sentinelone"):
        write_jsonl(f"{vendor}-edr-alerts.jsonl", edr_pack(vendor))
    manifest = {"generated_at": datetime.now(timezone.utc).isoformat(), "synthetic": True,
                "files": [{"name": name, "records": len(rows), "kind": "normalized_security_events"} for name, rows in packs.items()] +
                         [{"name": f"{v}-edr-alerts.jsonl", "records": 30, "kind": "vendor_edr_alerts"} for v in ("defender","crowdstrike","sentinelone")],
                "warning": "Training data only. TEST-NET IP ranges and .invalid domains are intentionally non-production."}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (OUT / "README.txt").write_text(
        "EDRRR REALISTIC SYNTHETIC TRAINING PACK\n\nThese files are inert training telemetry, not malware.\n"
        "They mix ordinary enterprise noise with linked suspicious behaviors. Import the *-normalized.jsonl files through Import system logs.\n"
        "The three *-edr-alerts.jsonl files model vendor alert exports and are intended for connector/import exercises.\n"
        "All public IPs use RFC 5737 documentation networks and domains end in .invalid.\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
