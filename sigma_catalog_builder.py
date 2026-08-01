#!/usr/bin/env python3
"""Compile Sigma rules into environment-filtered alerts and five safe response workflows."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ENVIRONMENTS = ("windows_11", "windows_server", "linux_mint", "ubuntu", "ubuntu_server")


def stable_alert_code(rule: dict[str, Any]) -> str:
    identity = str(rule.get("id") or rule.get("_export", {}).get("source_file") or rule.get("title", "unknown"))
    return "SIGMA-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()


def applicable_environments(rule: dict[str, Any]) -> list[str]:
    """Map Sigma logsource product to the requested endpoint environments."""
    logsource = rule.get("logsource") or {}
    product = str(logsource.get("product", "")).lower()
    category = str(logsource.get("category", "")).lower()
    source = str(rule.get("_export", {}).get("source_file", "")).lower()
    text = " ".join([product, category, source, str(rule.get("title", "")).lower()])
    environments: list[str] = []
    if product == "windows" or "/windows/" in source or "windows" in text:
        environments.extend(["windows_11", "windows_server"])
    if product == "linux" or "/linux/" in source or any(token in text for token in ("linux", "auditd", "journald")):
        environments.extend(["linux_mint", "ubuntu", "ubuntu_server"])
    return list(dict.fromkeys(environments))


def family(rule: dict[str, Any]) -> str:
    """Classify a rule into a response family without changing its detection logic."""
    logsource = rule.get("logsource") or {}
    text = " ".join([
        str(logsource.get("category", "")), str(logsource.get("service", "")),
        str(rule.get("title", "")), " ".join(rule.get("tags", []) or []),
    ]).lower()
    routes = (
        ("dns", ("dns",)),
        ("identity", ("authentication", "logon", "login", "account", "user", "group", "sudo", "sshd")),
        ("registry", ("registry",)),
        ("file", ("file", "image_load", "driver_load")),
        ("network", ("network", "firewall", "proxy")),
        ("process", ("process", "powershell", "shell", "command")),
    )
    for name, tokens in routes:
        if any(token in text for token in tokens):
            return name
    return "generic"


WINDOWS_COMMANDS: dict[str, dict[str, str]] = {
    "generic": {
        "inspect": "Get-WinEvent -ListLog * | Select-Object LogName,RecordCount,LastWriteTime",
        "enrich": "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture",
        "contain_check": "Write-Warning 'No containment command is defined for this rule family; escalate for a rule-specific playbook.'",
        "contain": "Write-Error 'Containment intentionally blocked: unsupported rule family.'",
        "verify": "Write-Output 'Evidence collection completed; no system change was made.'",
        "rollback": "Write-Output 'No rollback required because containment was blocked.'"
    },
    "process": {
        "inspect": "Get-CimInstance Win32_Process -Filter \"ProcessId={{process_pid}}\" | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine",
        "enrich": "Get-Process -Id {{process_pid}} -FileVersionInfo; Get-AuthenticodeSignature -LiteralPath '{{file_path}}'; Get-FileHash -LiteralPath '{{file_path}}' -Algorithm SHA256",
        "contain_check": "Get-Process -Id {{process_pid}} | Format-List Id,Name,Path,StartTime",
        "contain": "Stop-Process -Id {{process_pid}} -Confirm -PassThru",
        "verify": "Get-Process -Id {{process_pid}} -ErrorAction SilentlyContinue",
        "rollback": "# A terminated process cannot be resumed. Restart only from a verified executable/service definition after owner approval."
    },
    "file": {
        "inspect": "Get-Item -LiteralPath '{{file_path}}' | Format-List FullName,Length,CreationTimeUtc,LastWriteTimeUtc,Attributes",
        "enrich": "Get-FileHash -LiteralPath '{{file_path}}' -Algorithm SHA256; Get-AuthenticodeSignature -LiteralPath '{{file_path}}'",
        "contain_check": "Test-Path -LiteralPath '{{file_path}}'; Get-Acl -LiteralPath '{{file_path}}' | Format-List",
        "contain": "Move-Item -LiteralPath '{{file_path}}' -Destination '{{approved_quarantine_path}}' -Confirm",
        "verify": "Test-Path -LiteralPath '{{file_path}}'; Get-Item -LiteralPath '{{approved_quarantine_path}}'",
        "rollback": "Move-Item -LiteralPath '{{approved_quarantine_path}}' -Destination '{{file_path}}' -Confirm"
    },
    "registry": {
        "inspect": "Get-ItemProperty -LiteralPath '{{registry_path}}' | Format-List",
        "enrich": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=12,13,14;StartTime=(Get-Date).AddHours(-2)}",
        "contain_check": "Get-ItemPropertyValue -LiteralPath '{{registry_path}}' -Name '{{value_name}}'",
        "contain": "Remove-ItemProperty -LiteralPath '{{registry_path}}' -Name '{{value_name}}' -WhatIf",
        "verify": "Get-ItemProperty -LiteralPath '{{registry_path}}' -ErrorAction SilentlyContinue",
        "rollback": "New-ItemProperty -LiteralPath '{{registry_path}}' -Name '{{value_name}}' -Value '{{preserved_value}}' -PropertyType String -WhatIf"
    },
    "identity": {
        "inspect": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625,4728,4732,4756;StartTime=(Get-Date).AddHours(-4)} | Select-Object TimeCreated,Id,Message",
        "enrich": "Get-LocalUser -Name '{{account_name}}' | Format-List *",
        "contain_check": "Get-LocalUser -Name '{{account_name}}' | Select-Object Name,Enabled,LastLogon",
        "contain": "Disable-LocalUser -Name '{{account_name}}' -WhatIf",
        "verify": "Get-LocalUser -Name '{{account_name}}' | Select-Object Name,Enabled",
        "rollback": "Enable-LocalUser -Name '{{account_name}}' -WhatIf"
    },
    "network": {
        "inspect": "Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq '{{remote_ip}}'} | Format-Table -AutoSize",
        "enrich": "Resolve-DnsName '{{domain}}' -ErrorAction SilentlyContinue; Test-NetConnection -ComputerName '{{remote_ip}}' -Port {{remote_port}} -InformationLevel Detailed",
        "contain_check": "Get-NetFirewallRule -DisplayName 'SIEM {{case_id}}' -ErrorAction SilentlyContinue",
        "contain": "New-NetFirewallRule -DisplayName 'SIEM {{case_id}}' -Direction Outbound -RemoteAddress '{{remote_ip}}' -Action Block -WhatIf",
        "verify": "Get-NetFirewallRule -DisplayName 'SIEM {{case_id}}' | Get-NetFirewallAddressFilter",
        "rollback": "Remove-NetFirewallRule -DisplayName 'SIEM {{case_id}}' -WhatIf"
    },
    "dns": {
        "inspect": "Resolve-DnsName '{{domain}}' -Type A -ErrorAction SilentlyContinue; Get-DnsClientCache | Where-Object {$_.Entry -like '*{{domain}}*'}",
        "enrich": "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=22;StartTime=(Get-Date).AddHours(-2)}",
        "contain_check": "Get-NetFirewallRule -DisplayName 'SIEM DNS {{case_id}}' -ErrorAction SilentlyContinue",
        "contain": "New-NetFirewallRule -DisplayName 'SIEM DNS {{case_id}}' -Direction Outbound -RemoteAddress '{{resolved_ip}}' -Action Block -WhatIf",
        "verify": "Resolve-DnsName '{{domain}}' -ErrorAction SilentlyContinue",
        "rollback": "Remove-NetFirewallRule -DisplayName 'SIEM DNS {{case_id}}' -WhatIf"
    },
}


LINUX_COMMANDS: dict[str, dict[str, str]] = {
    "generic": {
        "inspect": "sudo journalctl --since '-2 hours' --no-pager -n 500",
        "enrich": "uname -a; cat /etc/os-release; systemctl --failed --no-pager",
        "contain_check": "printf '%s\n' 'No containment command is defined for this rule family; escalate for a rule-specific playbook.'",
        "contain": "false # Containment intentionally blocked: unsupported rule family",
        "verify": "printf '%s\n' 'Evidence collection completed; no system change was made.'",
        "rollback": "true # No rollback required"
    },
    "process": {
        "inspect": "ps -o pid,ppid,user,lstart,etime,cmd -p '{{process_pid}}'",
        "enrich": "sudo readlink -f '/proc/{{process_pid}}/exe'; sudo tr '\\0' ' ' < '/proc/{{process_pid}}/cmdline'; sha256sum -- '{{file_path}}'",
        "contain_check": "ps -o pid,ppid,user,state,cmd -p '{{process_pid}}'",
        "contain": "sudo kill -STOP -- '{{process_pid}}'",
        "verify": "ps -o pid,state,cmd -p '{{process_pid}}'",
        "rollback": "sudo kill -CONT -- '{{process_pid}}'"
    },
    "file": {
        "inspect": "sudo stat -- '{{file_path}}'; sudo file -- '{{file_path}}'",
        "enrich": "sudo sha256sum -- '{{file_path}}'; sudo getfacl --absolute-names -- '{{file_path}}'",
        "contain_check": "sudo test -e '{{file_path}}' && sudo ls -la -- '{{file_path}}'",
        "contain": "sudo mv -- '{{file_path}}' '{{approved_quarantine_path}}'",
        "verify": "sudo test ! -e '{{file_path}}' && sudo test -e '{{approved_quarantine_path}}'",
        "rollback": "sudo mv -- '{{approved_quarantine_path}}' '{{file_path}}'"
    },
    "registry": {
        "inspect": "printf '%s\n' 'Windows registry telemetry is not applicable to this Linux environment.'",
        "enrich": "printf '%s\n' 'Re-check the Sigma logsource mapping; do not translate registry actions to Linux.'",
        "contain_check": "false # Not applicable",
        "contain": "false # Not applicable; intentionally blocked",
        "verify": "true",
        "rollback": "true"
    },
    "identity": {
        "inspect": "sudo journalctl --since '-4 hours' _COMM=sshd --no-pager; sudo last -Fai | head -100",
        "enrich": "sudo passwd -S -- '{{account_name}}'; sudo id -- '{{account_name}}'; sudo chage -l -- '{{account_name}}'",
        "contain_check": "sudo passwd -S -- '{{account_name}}'; loginctl user-status '{{account_name}}' --no-pager",
        "contain": "sudo passwd -l -- '{{account_name}}'",
        "verify": "sudo passwd -S -- '{{account_name}}'",
        "rollback": "sudo passwd -u -- '{{account_name}}'"
    },
    "network": {
        "inspect": "sudo ss -tpn | grep -F -- '{{remote_ip}}'",
        "enrich": "getent hosts '{{domain}}'; ip route get '{{remote_ip}}'",
        "contain_check": "sudo nft list ruleset",
        "contain": "sudo nft add rule inet siem output ip daddr '{{remote_ip}}' counter drop comment 'SIEM {{case_id}}'",
        "verify": "sudo nft -a list chain inet siem output",
        "rollback": "sudo nft delete rule inet siem output handle '{{nft_rule_handle}}'"
    },
    "dns": {
        "inspect": "getent ahosts '{{domain}}'; resolvectl query '{{domain}}'",
        "enrich": "sudo journalctl --since '-2 hours' -u systemd-resolved --no-pager | grep -F -- '{{domain}}'",
        "contain_check": "sudo nft list ruleset; resolvectl status",
        "contain": "sudo nft add rule inet siem output ip daddr '{{resolved_ip}}' counter drop comment 'SIEM DNS {{case_id}}'",
        "verify": "sudo nft -a list chain inet siem output",
        "rollback": "sudo nft delete rule inet siem output handle '{{nft_rule_handle}}'"
    },
}


WINDOWS_SERVER_OVERRIDES: dict[str, dict[str, str]] = {
    "generic": {
        "inspect": "Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber; Get-Service | Where-Object Status -eq 'Running'; Get-NetTCPConnection -State Established",
        "enrich": "Get-WinEvent -FilterHashtable @{LogName='System';StartTime=(Get-Date).AddHours(-2)} | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message",
    },
    "process": {
        "inspect": "Get-CimInstance Win32_Process -Filter \"ProcessId={{process_pid}}\" | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine; Get-CimInstance Win32_Service | Where-Object ProcessId -eq {{process_pid}} | Select-Object Name,State,StartMode,PathName",
        "contain_check": "Get-CimInstance Win32_Service | Where-Object ProcessId -eq {{process_pid}}; Get-NetTCPConnection -OwningProcess {{process_pid}} -ErrorAction SilentlyContinue; Get-ClusterGroup -ErrorAction SilentlyContinue",
        "contain": "Stop-Process -Id {{process_pid}} -WhatIf -Confirm",
        "rollback": "# Remove -WhatIf only after service owner/failover approval. Restart through Start-Service '{{service_name}}' or the approved cluster/application runbook."
    },
    "identity": {
        "contain_check": "Get-LocalUser -Name '{{account_name}}' -ErrorAction SilentlyContinue; Get-CimInstance Win32_Service | Where-Object StartName -match '{{account_name}}'; Get-ScheduledTask | Where-Object {$_.Principal.UserId -match '{{account_name}}'}",
        "contain": "Disable-LocalUser -Name '{{account_name}}' -WhatIf",
        "rollback": "Enable-LocalUser -Name '{{account_name}}' -WhatIf # Domain/service identities require their dedicated IAM and dependency runbook."
    },
    "network": {
        "contain_check": "Get-NetTCPConnection -State Established; Get-NetRoute; Get-NetFirewallRule -DisplayName 'SIEM {{case_id}}' -ErrorAction SilentlyContinue",
        "contain": "New-NetFirewallRule -DisplayName 'SIEM {{case_id}}' -Direction Outbound -RemoteAddress '{{remote_ip}}' -Action Block -WhatIf # Confirm cluster, backup, monitoring, and management dependencies first",
    },
}


UBUNTU_SERVER_OVERRIDES: dict[str, dict[str, str]] = {
    "generic": {
        "inspect": "uname -a; cat /etc/os-release; systemctl --failed --no-pager; systemctl list-units --type=service --state=running --no-pager; sudo ss -lntup",
        "enrich": "sudo journalctl --since '-2 hours' -p warning --no-pager; df -hT; free -h",
    },
    "process": {
        "inspect": "ps -o pid,ppid,user,lstart,etime,cmd -p '{{process_pid}}'; systemctl status '{{service_name}}' --no-pager; systemctl list-dependencies --reverse '{{service_name}}' --no-pager",
        "contain_check": "sudo ss -tpn | grep -F 'pid={{process_pid}},' || true; systemctl show '{{service_name}}' -p ActiveState,SubState,Restart,Requires,Wants,Before,After",
        "contain": "sudo systemctl stop '{{service_name}}' # Only after failover, SSH-access, dependency, and transaction checks",
        "verify": "systemctl is-active '{{service_name}}'; sudo ss -lntup",
        "rollback": "sudo systemctl start '{{service_name}}'; systemctl status '{{service_name}}' --no-pager"
    },
    "identity": {
        "contain_check": "sudo passwd -S -- '{{account_name}}'; sudo grep -R --fixed-strings '{{account_name}}' /etc/systemd/system /etc/cron* 2>/dev/null || true; loginctl user-status '{{account_name}}' --no-pager",
        "contain": "sudo passwd -l -- '{{account_name}}' # Confirm service and automation dependencies first",
    },
    "network": {
        "contain_check": "sudo nft list ruleset; ip route; sudo ss -tpn; systemctl status ssh --no-pager",
        "contain": "sudo nft add rule inet siem output ip daddr '{{remote_ip}}' counter drop comment 'SIEM {{case_id}}' # Verify the inet/siem/output table and chain exist first",
    },
}


def merged_commands(base: dict[str, dict[str, str]], overrides: dict[str, dict[str, str]], rule_family: str) -> dict[str, str]:
    selected = dict(base.get(rule_family, base["generic"]))
    selected.update(overrides.get(rule_family, {}))
    return selected


def commands(environment: str, rule_family: str) -> dict[str, str]:
    if environment == "windows_server":
        return merged_commands(WINDOWS_COMMANDS, WINDOWS_SERVER_OVERRIDES, rule_family)
    if environment == "ubuntu_server":
        return merged_commands(LINUX_COMMANDS, UBUNTU_SERVER_OVERRIDES, rule_family)
    library = WINDOWS_COMMANDS if environment == "windows_11" else LINUX_COMMANDS
    return library.get(rule_family, library["generic"])


def workflows(alert_code: str, environment: str, rule_family: str) -> list[dict[str, Any]]:
    cmd = commands(environment, rule_family)
    shell = "powershell" if environment in {"windows_11", "windows_server"} else "bash"
    powershell_cmd = merged_commands(WINDOWS_COMMANDS, WINDOWS_SERVER_OVERRIDES if environment == "windows_server" else {}, rule_family)
    bash_cmd = merged_commands(LINUX_COMMANDS, UBUNTU_SERVER_OVERRIDES if environment == "ubuntu_server" else {}, rule_family)
    definitions = (
        ("S01", "Evidence-only triage", "read_only", ["inspect", "enrich"]),
        ("S02", "Enhanced investigation", "read_only", ["inspect", "enrich", "verify"]),
        ("S03", "Narrow containment", "changes_system", ["contain_check", "contain", "verify", "rollback"]),
        ("S04", "Host/account containment", "high_impact", ["inspect", "contain_check", "contain", "verify", "rollback"]),
        ("S05", "Recovery and broader incident response", "high_impact", ["inspect", "enrich", "contain_check", "contain", "verify", "rollback"]),
    )
    results = []
    for suffix, title, impact, phases in definitions:
        results.append({
            "solution_code": f"{alert_code}-{environment.upper()}-{suffix}",
            "alert_rule_id": alert_code,
            "environment": environment,
            "title": title,
            "impact": impact,
            "shell": shell,
            "auto_execute": False,
            "human_approval_required": impact != "read_only",
            "warning": "Replace and validate every {{placeholder}}. Run inspection first. Preserve evidence and confirm rollback before containment.",
            "execution_guidance": "PowerShell commands containing -WhatIf are previews; remove -WhatIf only after approval. Bash has no universal dry-run, so review the exact expanded command and prerequisites before sudo.",
            "server_safety": ("Confirm service role, failover, remote-management path, dependencies, active transactions, recovery owner, and maintenance authority." if environment in {"windows_server", "ubuntu_server"} else "Confirm user impact, management connectivity, evidence preservation, and rollback readiness."),
            "commands": [{"phase": phase, "command": cmd[phase]} for phase in phases],
            "commands_by_shell": {
                "powershell": [{"phase": phase, "command": powershell_cmd[phase]} for phase in phases],
                "bash": [{"phase": phase, "command": bash_cmd[phase]} for phase in phases],
            },
            "shell_compatibility": {
                "powershell": "native" if environment in {"windows_11", "windows_server"} else "reference_only_use_on_windows_equivalent",
                "bash": "native" if environment not in {"windows_11", "windows_server"} else "reference_only_use_on_linux_equivalent",
            },
        })
    return results


def compile_catalog(rules: list[dict[str, Any]], environment: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    alerts, solutions = [], []
    for rule in rules:
        environments = applicable_environments(rule)
        if environment not in environments:
            continue
        code = stable_alert_code(rule)
        rule_family = family(rule)
        alerts.append({
            "alert_rule_id": code,
            "sigma_id": rule.get("id"),
            "title": rule.get("title", "Untitled Sigma rule"),
            "description": rule.get("description", ""),
            "level": rule.get("level", "unknown"),
            "status": rule.get("status", "unknown"),
            "logsource": rule.get("logsource", {}),
            "tags": rule.get("tags", []),
            "environment": environment,
            "family": rule_family,
            "source_file": rule.get("_export", {}).get("source_file"),
            "source_library": rule.get("_export", {}).get("source_library", "sigma"),
            "original_query": rule.get("_export", {}).get("original_query"),
            "translation": rule.get("_export", {}).get("translation", "native_sigma_subset"),
            "solution_codes": [item["solution_code"] for item in workflows(code, environment, rule_family)],
        })
        solutions.extend(workflows(code, environment, rule_family))
    return alerts, solutions


def select_environment(provided: str | None) -> str:
    if provided:
        return provided
    print("Select the SIEM environment:")
    for number, value in enumerate(ENVIRONMENTS, start=1):
        print(f"  {number}. {value}")
    selected = input("Environment number: ").strip()
    try:
        return ENVIRONMENTS[int(selected) - 1]
    except (ValueError, IndexError) as error:
        raise SystemExit("Invalid environment selection") from error


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(record, ensure_ascii=False, default=str) + "\n" for record in records), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build environment-specific Sigma alert and response catalogues")
    parser.add_argument("sigma_json", type=Path, help="sigma-all-rules.json from app.py sigma-export")
    parser.add_argument("--environment", choices=ENVIRONMENTS, help="prompted when omitted")
    parser.add_argument("--alerts", type=Path, default=Path("environment_alerts.jsonl"))
    parser.add_argument("--solutions", type=Path, default=Path("environment_solutions.jsonl"))
    args = parser.parse_args()
    environment = select_environment(args.environment)
    rules = json.loads(args.sigma_json.read_text(encoding="utf-8"))
    if not isinstance(rules, list):
        raise SystemExit("Sigma export must be a JSON array")
    alerts, solutions = compile_catalog(rules, environment)
    write_jsonl(args.alerts, alerts)
    write_jsonl(args.solutions, solutions)
    print(f"Environment: {environment}")
    print(f"Applicable alerts: {len(alerts)}")
    print(f"Generated solutions: {len(solutions)} (exactly five per alert)")
    if len(solutions) < 5000:
        print("Coverage is below 5,000 because fewer than 1,000 applicable source rules were present; no duplicates were fabricated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
