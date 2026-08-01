"""Human-approved response choices for every detection in workready_siem.py."""

from __future__ import annotations

from typing import Any


def choice(action: str, benefit: str, system_risk: str, when: str, approval: str, rollback: str) -> dict[str, str]:
    return {"action": action, "benefit": benefit, "system_risk": system_risk, "when": when, "approval": approval, "rollback": rollback}


def five(*items: dict[str, str]) -> list[dict[str, str]]:
    if len(items) != 5:
        raise ValueError("Every playbook must contain exactly five response choices")
    return list(items)


def command_pair(step: int) -> dict[str, str]:
    """Return reviewable Windows and Linux commands for a response tier.

    Placeholders make disruptive commands fail safely until an analyst replaces
    them after validating evidence and obtaining the approval shown in the case.
    EDRRR only displays/copies these strings; it never executes them.
    """
    pairs = {
        1: {
            "powershell": "Get-Process | Sort-Object CPU -Descending | Select-Object -First 25 Name,Id,Path,CPU",
            "bash": "ps -eo user,pid,ppid,lstart,cmd --sort=-%cpu | head -n 26",
        },
        2: {
            "powershell": "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 200 | Format-List TimeCreated,Id,ProviderName,Message",
            "bash": "sudo journalctl --since '1 hour ago' --no-pager -o short-iso | tail -n 200",
        },
        3: {
            "powershell": "New-NetFirewallRule -DisplayName 'EDRRR temporary indicator block' -Direction Outbound -RemoteAddress '<INDICATOR_IP>' -Action Block",
            "bash": "sudo nft add rule inet filter output ip daddr '<INDICATOR_IP>' counter drop comment 'EDRRR temporary indicator block'",
        },
        4: {
            "powershell": "Disable-NetAdapter -Name '<ADAPTER_NAME>' -Confirm:$true",
            "bash": "sudo ip link set dev '<INTERFACE_NAME>' down",
        },
        5: {
            "powershell": "Start-MpScan -ScanType FullScan; Get-MpThreatDetection",
            "bash": "sudo journalctl --since '24 hours ago' --priority=warning --no-pager; sudo debsums -s",
        },
    }
    return pairs[step]


PLAYBOOKS: dict[str, list[dict[str, str]]] = {
    "PROC-001": five(
        choice("Collect the Office document, process tree, command line, hash, signer, and network events.", "Preserves evidence with no interruption.", "Malicious code may continue while evidence is collected.", "Low-confidence match or business-critical workstation.", "SOC analyst", "No rollback; document collection scope."),
        choice("Suspend the child interpreter process after preserving volatile evidence.", "Pauses suspected execution without stopping Office or the host.", "Can freeze a legitimate macro, automation, or user workflow.", "Suspicious command line but compromise is not confirmed.", "Senior analyst", "Resume the process if verified benign; otherwise terminate it."),
        choice("Terminate the child and quarantine its script or payload hash.", "Stops the observed execution path.", "May interrupt approved scripts and lose unsaved process state.", "Evidence strongly links the child to an unauthorized payload.", "Incident lead", "Remove the quarantine only after validation and restore approved files from source."),
        choice("Isolate the endpoint from the network while retaining management access.", "Limits command-and-control and lateral movement.", "Disconnects the user and can interrupt business applications.", "Malicious descendants, persistence, or network indicators are present.", "Incident lead and endpoint owner", "Release isolation after scoping, remediation, and validation scans."),
        choice("Disable the user session/account and reimage the endpoint.", "Provides strong containment and removes uncertain endpoint state.", "High user downtime; may destroy volatile evidence and affect dependent credentials.", "Confirmed compromise with credential exposure or unreliable cleanup.", "Incident commander and business owner", "Restore account after credential reset; rebuild from an approved image and restore validated data."),
    ),
    "PROC-002": five(
        choice("Capture web access logs, process tree, command line, memory metadata, and relevant application logs.", "Validates whether the child came from exploitation.", "The web shell or exploit may remain active during collection.", "Initial alert on a redundant or low-impact service.", "SOC analyst", "No rollback; preserve evidence immutably."),
        choice("Block the suspicious source IP, URL, or request signature at the WAF/reverse proxy.", "Interrupts the observed exploit path with limited server impact.", "IP blocking can miss distributed attackers or block shared legitimate proxies.", "A specific malicious request or source is identified.", "Web/security operations", "Time-limit the block and remove it after application remediation and review."),
        choice("Terminate the child process and remove the confirmed web-shell artifact.", "Stops the known interactive foothold.", "May kill a legitimate worker child; deletion can alter forensic evidence.", "Artifact and process are confirmed malicious and evidence is preserved.", "Incident lead and application owner", "Restore validated application files from deployment artifacts."),
        choice("Drain traffic and isolate the affected server from non-management networks.", "Contains lateral movement while preserving a service pool if redundant.", "Reduces capacity and can cause an outage if redundancy is insufficient.", "Confirmed compromise on a load-balanced or failover-capable service.", "Incident commander, application owner, network operations", "Reintroduce only after rebuild, credential rotation, and health validation."),
        choice("Take the service offline and rebuild the server from trusted infrastructure-as-code or image.", "Strongest assurance against persistent server compromise.", "Potential customer outage, lost transactions, and dependency failures.", "Active exploitation, credential theft, or uncertain system integrity.", "Incident commander and business continuity owner", "Fail over first where possible; restore service from trusted build and validated data."),
    ),
    "PROC-003": five(
        choice("Verify parent telemetry, ProcessGuid, image path, signature, hash, boot time, and sensor health.", "Distinguishes masquerading from missing/corrupt ancestry data.", "A malicious protected-name process may continue running.", "Parent is missing or sensor data quality is uncertain.", "SOC analyst", "No rollback."),
        choice("Increase EDR monitoring and collect memory/image metadata for the suspicious process.", "Improves confidence without immediate disruption.", "Additional collection can consume CPU/storage and still allow activity.", "Signed/path evidence is inconclusive.", "Senior analyst", "Return collection policy to normal after triage."),
        choice("Suspend the unexpected protected-name process if it is not the OS instance.", "Stops potential masquerading while retaining memory.", "Suspending a genuine LSASS or svchost instance can crash or destabilize Windows.", "PID, path, and signature prove this is a separate suspicious instance.", "Endpoint incident lead", "Resume only if identity is conclusively verified; never suspend genuine LSASS casually."),
        choice("Isolate the endpoint and acquire forensic evidence.", "Limits spread while avoiding unsafe termination of critical processes.", "User/service interruption and possible application timeouts.", "Masquerading is probable or additional malicious behavior exists.", "Incident lead and system owner", "Release after remediation or rebuild and validation."),
        choice("Perform controlled shutdown/rebuild using the endpoint-response procedure.", "Restores trusted system state.", "Can lose volatile evidence; abrupt handling of critical processes can cause data loss.", "Confirmed system-process impersonation or compromised OS trust.", "Incident commander and system owner", "Acquire evidence first; rebuild and restore validated business data."),
    ),
    "PROC-004": five(
        choice("Check download origin, browser history, signer, hash prevalence, and subsequent execution.", "Often resolves legitimate installers without disruption.", "Payload may execute while being reviewed.", "Single low-confidence temporary-path event.", "SOC analyst", "No rollback."),
        choice("Quarantine the file but leave the endpoint connected.", "Prevents re-execution with limited user impact.", "Can break a legitimate installer/update and may not stop an already running process.", "File is unknown or low-prevalence and not business approved.", "Senior analyst", "Restore only after signer/hash/source validation."),
        choice("Terminate the related process tree and quarantine descendants.", "Stops the active execution chain.", "May close browser/mail sessions and lose unsaved user work.", "Suspicious command line, child activity, or reputation corroborates risk.", "Incident lead", "Restore approved files and applications after review."),
        choice("Isolate the endpoint and reset affected browser/session tokens.", "Limits outbound control and session theft.", "Disconnects the user and invalidates legitimate sessions.", "Network callbacks, credential theft, or persistence is observed.", "Incident lead and identity team", "Release after cleanup; users reauthenticate through approved channels."),
        choice("Reimage the endpoint and reset exposed credentials.", "Returns endpoint and identity state to a trusted baseline.", "Substantial downtime and possible loss of local-only data.", "Confirmed payload execution with uncertain scope.", "Incident commander and business owner", "Restore validated data and access after rebuild."),
    ),
    "MEM-001": five(
        choice("Collect the complete API sequence, call stack, source/target metadata, signer, and memory telemetry.", "Reduces false positives from debuggers, security tools, and accessibility software.", "Injection may complete during collection.", "A single API call without corroboration.", "SOC analyst", "No rollback."),
        choice("Apply enhanced monitoring to the source and target processes.", "Can reveal remote thread creation or payload execution.", "Consumes endpoint resources and allows continued activity.", "Medium-confidence sequence on a critical system.", "Senior analyst", "Return policy to normal after the investigation window."),
        choice("Suspend the source process and capture memory.", "Pauses the suspected injector while preserving volatile evidence.", "May freeze a legitimate security/management application.", "Untrusted source or multiple injection-stage APIs are observed.", "Endpoint incident lead", "Resume only if verified benign; otherwise terminate after evidence capture."),
        choice("Terminate source and injected target, then isolate the endpoint.", "Stops the observed injected execution and network spread.", "Terminating a critical target can crash applications or the OS.", "Payload execution is confirmed and target termination is safe.", "Incident lead and system owner", "Restart affected services from trusted binaries; release isolation after validation."),
        choice("Capture forensic image, rotate exposed credentials, and rebuild.", "Addresses uncertain in-memory persistence and credential exposure.", "High downtime and forensic/storage cost.", "Confirmed injection into security-sensitive or privileged processes.", "Incident commander", "Rebuild from trusted media; restore only validated data and credentials."),
    ),
    "CRED-001": five(
        choice("Validate the source signer, access mask, call trace, EDR product status, and approved-tool list.", "Avoids disrupting legitimate antivirus and authentication components.", "Credential access may continue during validation.", "Unknown source or ambiguous access semantics.", "Senior SOC analyst", "No rollback."),
        choice("Block/quarantine the source executable hash after preserving evidence.", "Prevents repeated LSASS access from that binary.", "Hash blocks can affect legitimate software versions and do not stop renamed/recompiled variants.", "Source is untrusted or reputation/call trace is suspicious.", "Incident lead", "Remove block only after verified false positive and fleet impact review."),
        choice("Suspend or terminate the source process—not LSASS—and isolate its account session.", "Stops the accessor while protecting OS stability.", "Can interrupt legitimate administration; session termination may lose work.", "Unauthorized access is strongly supported.", "Incident lead and identity team", "Restore access after investigation and credential reset."),
        choice("Isolate the endpoint and reset credentials used or cached on it, prioritizing privileged accounts.", "Limits reuse of potentially dumped credentials.", "Wide credential resets can break services, tasks, and applications.", "Credible LSASS dumping or post-access activity.", "Incident commander, identity owner, system owner", "Coordinate service-account rotation and validate dependencies before restoration."),
        choice("Rebuild the endpoint and conduct enterprise credential-exposure hunting.", "Restores host trust and searches for lateral consequences.", "High operational effort; forced resets can cause broad outages.", "Confirmed credential dumping or domain-privileged exposure.", "Incident commander and identity leadership", "Phased credential rotation, validated rebuild, and monitored return to service."),
    ),
    "FILE-001": five(
        choice("Compare hash, signer, owner, timestamps, writing process, deployment records, and known-good baseline.", "Separates patching/configuration activity from tampering.", "A malicious modification remains present during review.", "Unconfirmed change on a critical path.", "SOC analyst and system owner", "No rollback."),
        choice("Copy the artifact for evidence and increase monitoring on the writer and affected path.", "Preserves evidence and detects follow-on changes.", "Extra monitoring consumes resources and does not undo tampering.", "Business-critical file where immediate replacement is risky.", "Senior analyst", "Return monitoring to baseline after disposition."),
        choice("Quarantine the changed noncritical artifact and restore its known-good version.", "Removes the suspect file while limiting scope.", "Wrong-version restoration can break applications or patch state.", "Baseline and dependency impact are verified.", "System owner and incident lead", "Retain backup; restore quarantined version if change is approved."),
        choice("Stop the affected service, restore trusted files, and rotate its credentials.", "Prevents continued execution of tampered components.", "Service outage and possible transaction interruption.", "Active service loads the modified file or compromise is probable.", "Application owner and incident lead", "Use maintenance/failover plan and validated deployment rollback."),
        choice("Isolate and rebuild the server from trusted configuration.", "Provides strongest integrity assurance.", "Major downtime, dependency impact, and evidence-loss risk.", "Multiple protected files changed or system trust is lost.", "Incident commander and business owner", "Fail over where possible; rebuild, validate, and restore controlled traffic."),
    ),
    "FILE-002": five(
        choice("Identify the creating process, source URL, hash, signer, prevalence, and whether execution occurred.", "May establish a legitimate installer/update quickly.", "Payload remains available during triage.", "Low-confidence creation without execution.", "SOC analyst", "No rollback."),
        choice("Quarantine the temporary executable.", "Prevents later execution.", "Can interrupt legitimate installation or software updates.", "Unknown or unapproved executable that has not run.", "Senior analyst", "Restore only after ownership/source verification."),
        choice("Block the hash/path pattern and terminate associated processes.", "Stops current and repeated execution.", "Broad path rules can block many legitimate temporary installers.", "Confirmed suspicious file with narrow indicators.", "Incident lead", "Use time-limited narrow rule; remove after remediation and validation."),
        choice("Isolate the endpoint and hunt the hash across the fleet.", "Contains spread and measures prevalence.", "User downtime and fleet-search resource cost.", "Execution, persistence, or callbacks are observed.", "Incident lead", "Release clean hosts after validation; retain targeted block if justified."),
        choice("Rebuild and rotate credentials if the payload executed with meaningful privileges.", "Restores trusted state and addresses credential risk.", "High downtime and reset impact.", "Confirmed privileged execution or uncertain persistence.", "Incident commander", "Restore validated data and staged credential access."),
    ),
    "REG-001": five(
        choice("Collect old/new values, actor, writing process, signer, and installation/change context.", "Distinguishes legitimate autostart software from persistence.", "Persistence remains active pending review.", "Single uncorroborated Run-key modification.", "SOC analyst", "No rollback."),
        choice("Disable the autorun value while preserving its data and referenced file.", "Prevents next-logon execution with limited immediate disruption.", "May stop legitimate agents, tray applications, or business startup workflows.", "Value is unapproved or points to a suspicious path.", "Senior analyst and endpoint owner", "Restore the saved value after validation."),
        choice("Remove the value and quarantine its referenced payload.", "Removes the persistence mechanism and executable.", "Could break legitimate software startup or update behavior.", "Payload is confirmed malicious and evidence is preserved.", "Incident lead", "Restore approved application configuration from deployment source."),
        choice("Isolate the endpoint and search equivalent keys/payloads fleet-wide.", "Limits control and detects campaign spread.", "Endpoint disruption and potential search load.", "Persistence accompanies execution or network indicators.", "Incident lead", "Release after cleanup, credential review, and clean persistence scan."),
        choice("Rebuild and reset exposed credentials.", "Addresses additional unseen persistence and trust loss.", "High downtime and credential dependency impact.", "Multiple persistence mechanisms or privileged compromise.", "Incident commander", "Rebuild from trusted image and restore controlled access."),
    ),
    "AUTH-001": five(
        choice("Review source IP, failure reasons, targeted account, device, MFA, VPN, and post-login activity.", "Distinguishes user mistakes from brute force.", "An attacker may retain the successful session.", "Low-value account or ambiguous shared source.", "SOC analyst", "No rollback."),
        choice("Apply rate limiting or a temporary source challenge/block.", "Slows guessing with less account impact.", "May block users behind shared NAT/VPN and attackers can rotate IPs.", "Repeated attempts from a narrow source set.", "Identity/network operations", "Expire the block automatically and monitor recurrence."),
        choice("Revoke the successful session and require step-up MFA.", "Cuts off the potentially compromised session.", "Logs out a legitimate user and may interrupt work.", "Successful login context differs from the user's norm.", "Senior analyst or identity operations", "User reauthenticates after identity verification."),
        choice("Temporarily disable the account and reset credentials/tokens.", "Stops account use and invalidates known credentials.", "Can interrupt business processes and dependent services.", "Post-login activity or MFA evidence supports compromise.", "Incident lead and account owner", "Re-enable after verified reset and dependency review."),
        choice("Contain affected endpoints and launch broader identity compromise response.", "Addresses session theft, lateral movement, and related accounts.", "Broad operational impact and investigation cost.", "Privileged account, multiple hosts, or confirmed malicious actions.", "Incident commander and identity leadership", "Staged restoration after session revocation, credential rotation, and scoping."),
    ),
    "AUTH-002": five(
        choice("Compare with schedule, timezone, on-call duties, travel, and historical login pattern.", "Resolves a weak anomaly without disruption.", "Account misuse may continue while checking context.", "Time-of-day is the only anomaly.", "SOC analyst", "No rollback."),
        choice("Request user confirmation through an approved independent channel.", "Adds human context without changing access.", "Social engineering or delayed response can reduce assurance.", "Login is unusual but not overtly malicious.", "SOC analyst", "Document confirmation method and result."),
        choice("Require step-up MFA for the active session.", "Raises assurance while preserving access.", "Can interrupt unattended work or users without MFA access.", "Additional weak anomalies exist.", "Identity operations", "Return conditional-access policy after review if it was temporary."),
        choice("Revoke the session and restrict sign-in pending verification.", "Stops potentially unauthorized access.", "Interrupts legitimate after-hours work.", "Device, IP, or actions are also suspicious.", "Incident lead and account owner", "Restore after identity verification and credential review."),
        choice("Disable the account and contain accessed systems.", "Limits confirmed account compromise.", "Potentially broad business outage for privileged/service identities.", "Confirmed unauthorized login or harmful actions.", "Incident commander", "Coordinate credential reset and controlled re-enablement."),
    ),
    "AUTH-003": five(
        choice("Validate geolocation quality, VPN/proxy egress, travel, and impossible-travel timing.", "Reduces false positives from inaccurate/shared IP geography.", "Session remains active.", "Country mismatch is the only signal.", "SOC analyst", "No rollback."),
        choice("Ask the user to confirm the login through an independent channel.", "Quickly adds identity context.", "User confirmation alone can be unreliable.", "Unusual country with valid MFA and managed device.", "SOC analyst", "Document result."),
        choice("Require step-up MFA and restrict sensitive actions.", "Limits damage while maintaining partial access.", "Can block legitimate travel work and requires capable identity controls.", "Some context is suspicious but not conclusive.", "Identity operations", "Remove temporary restriction after verified context."),
        choice("Revoke sessions and reset credentials.", "Stops use of stolen credentials/tokens.", "Logs out legitimate sessions and may affect applications.", "User denies login or device/IP context is malicious.", "Incident lead", "Restore after reset, MFA validation, and device check."),
        choice("Disable account and isolate systems accessed by the session.", "Contains confirmed account-driven compromise.", "High business impact, especially for privileged identities.", "Malicious post-login activity or lateral movement is observed.", "Incident commander", "Controlled restoration after scoping and remediation."),
    ),
    "AUTH-004": five(
        choice("Check device enrollment, compliance, fingerprint stability, browser changes, and user history.", "Distinguishes replacements/reinstalls from attacker devices.", "Potentially hostile session remains active.", "New-device status is the only signal.", "SOC analyst", "No rollback."),
        choice("Request independent user confirmation and device registration.", "Validates ownership with limited interruption.", "A compromised user channel can provide false assurance.", "Expected device lifecycle change is plausible.", "SOC/IT support", "Remove unapproved registration if validation fails."),
        choice("Require MFA and block access to sensitive applications until compliant.", "Reduces exposure while preserving basic access.", "Can hinder legitimate BYOD or emergency work.", "Device is unmanaged or risk context is mixed.", "Identity/security operations", "Restore application access after compliance verification."),
        choice("Revoke the session and block the device identifier.", "Stops the observed device from using the account.", "Fingerprint changes can block legitimate devices and identifiers may be spoofed.", "User denies the device or behavior is suspicious.", "Incident lead", "Remove block after verified enrollment/reset."),
        choice("Disable account, reset tokens, and investigate accessed systems.", "Contains confirmed account takeover.", "Broad user and application interruption.", "Confirmed malicious device/session actions.", "Incident commander", "Controlled account restoration after scoping."),
    ),
    "AUTH-005": five(
        choice("Validate account purpose, logon type mapping, scheduled work, actor, and source host.", "Distinguishes administration from service-account misuse.", "Interactive session continues during validation.", "First occurrence without harmful behavior.", "SOC analyst and service owner", "No rollback."),
        choice("Terminate the interactive session while leaving noninteractive service use intact.", "Stops risky session with limited service impact.", "May interrupt approved emergency maintenance.", "No approved interactive-use exception exists.", "Identity operations and service owner", "Allow a documented time-bound exception if verified."),
        choice("Deny interactive logon for the account through policy.", "Prevents recurrence while preserving properly configured services.", "Misconfigured tasks/services using interactive logon may fail.", "Account design confirms interactive use is unnecessary.", "Identity architecture and service owner", "Roll back policy if dependencies fail; remediate dependencies."),
        choice("Rotate the account credential and restart dependent services in a controlled window.", "Invalidates potentially exposed credentials.", "Can cause widespread service outages if dependencies are unknown.", "Unauthorized use or credential exposure is likely.", "Incident lead, identity and application owners", "Inventory dependencies first; retain emergency rollback credential per policy."),
        choice("Disable the account and fail over/rebuild affected services.", "Strong containment for confirmed privileged service-account compromise.", "Severe multi-service impact.", "Confirmed malicious use with available continuity plan.", "Incident commander and business continuity owner", "Use replacement managed identity and controlled service restoration."),
    ),
    "PRIV-001": five(
        choice("Validate actor, ticket, target, group scope, approval, and effective privileges.", "Resolves approved administration without disrupting access.", "Unauthorized privilege remains active during review.", "Change may be legitimate and no misuse is observed.", "SOC analyst and IAM owner", "No rollback."),
        choice("Apply heightened monitoring and time-limit the membership.", "Preserves required access while reducing exposure.", "Monitoring does not prevent abuse; expiry may interrupt work.", "Approved emergency or project access.", "IAM owner", "Automatically remove membership at expiry unless renewed."),
        choice("Remove the member from the privileged group.", "Immediately removes the new privilege grant.", "Can disrupt legitimate administration or incident recovery.", "No valid approval or actor is suspicious.", "IAM lead and account owner", "Re-add only through approved privileged-access workflow."),
        choice("Revoke sessions/tokens and reset the target and actor credentials.", "Stops use of already-issued privileged sessions.", "May interrupt administrators and automation.", "Privilege was used or credentials may be compromised.", "Incident lead and IAM", "Controlled reauthentication after reset and validation."),
        choice("Disable involved accounts and investigate domain-wide changes.", "Contains confirmed directory compromise.", "Major administrative and business impact.", "Malicious privilege escalation or domain-admin exposure.", "Incident commander and identity leadership", "Use break-glass continuity process and staged restoration."),
    ),
    "NET-001": five(
        choice("Extend the time range and enrich destination, process, certificate, DNS, reputation, and asset role.", "Distinguishes software updates and monitoring from command-and-control.", "Possible C2 continues.", "Timing regularity is the only evidence.", "SOC analyst", "No rollback."),
        choice("Capture traffic metadata/packet samples and increase endpoint monitoring.", "Improves protocol and process attribution.", "Collection has privacy, storage, and performance costs.", "Destination is unknown but blocking is premature.", "Senior analyst and network owner", "Stop capture after the approved window and protect collected data."),
        choice("Block the destination for the single host or process.", "Interrupts suspected C2 with narrow scope.", "Can break a legitimate SaaS/update dependency; IPs may be shared.", "Destination/process is suspicious and dependency impact is understood.", "Incident lead and network operations", "Time-limit rule and remove after disposition."),
        choice("Isolate the endpoint while retaining management telemetry.", "Stops broader C2 and lateral movement.", "User/service disconnection.", "Malicious payload, persistence, or commands corroborate beaconing.", "Incident lead and system owner", "Release after cleanup/rebuild and validation."),
        choice("Block indicators fleet-wide and rebuild affected hosts.", "Contains a confirmed campaign.", "Shared infrastructure blocks may cause widespread outages.", "Confirmed C2 with multiple compromised hosts.", "Incident commander and network leadership", "Stage blocks, monitor impact, and restore validated hosts."),
    ),
    "NET-002": five(
        choice("Validate direction, bytes, protocol, process, destination owner, asset role, baseline, and data classification.", "Distinguishes backups/uploads from exfiltration.", "Transfer may continue.", "Volume is the only signal.", "SOC analyst and data owner", "No rollback."),
        choice("Rate-limit the connection or apply DLP inspection.", "Reduces loss while preserving some functionality.", "Performance degradation, privacy concerns, and encrypted-content limits.", "Transfer is suspicious but service continuity matters.", "Network/security operations and data owner", "Remove throttle after disposition."),
        choice("Block the destination or process-specific connection.", "Stops the current transfer.", "May interrupt cloud storage, backups, or customer traffic.", "Destination/payload is unauthorized and impact is understood.", "Incident lead and application owner", "Restore narrow access after validation."),
        choice("Isolate the host and revoke associated sessions/tokens.", "Stops additional transfer and account reuse.", "Host downtime and application/session interruption.", "Sensitive data or compromised process is identified.", "Incident commander and data owner", "Controlled restoration after scoping and remediation."),
        choice("Invoke breach response, preserve evidence, and coordinate legal/privacy notifications.", "Addresses confirmed material data loss comprehensively.", "High organizational impact; premature declaration has legal and reputational consequences.", "Exfiltration is confirmed and notification thresholds may be met.", "Incident commander, legal, privacy, and executive owner", "Follow the formal breach plan; decisions and evidence remain auditable."),
    ),
    "NET-003": five(
        choice("Confirm asset roles, administrator identity, change window, authentication, and remote-service events.", "Separates IT operations from lateral movement.", "Attacker connection may remain active.", "Port/host-role mismatch is the only signal.", "SOC analyst", "No rollback."),
        choice("Increase logging and restrict the connection to approved source/destination identities.", "Improves visibility and narrows access.", "Policy change can affect helpdesk/management workflows.", "Legitimate need exists but current access is too broad.", "Network/IAM operations", "Restore documented access path if business impact occurs."),
        choice("Terminate the remote session and block that source-destination pair.", "Stops the observed lateral path.", "Can interrupt legitimate administration or file operations.", "No approved activity or suspicious credentials/processes are present.", "Incident lead and system owners", "Remove narrow block after credential and host validation."),
        choice("Isolate the source host and reset the used account.", "Contains likely lateral movement.", "User/service downtime and credential dependency impact.", "Remote execution or malicious authentication is corroborated.", "Incident lead and identity owner", "Release after endpoint and identity remediation."),
        choice("Segment affected network zone and initiate enterprise lateral-movement response.", "Limits a confirmed multi-host intrusion.", "Can disrupt many services and dependencies.", "Multiple hosts, privileged credentials, or active propagation.", "Incident commander and network/business continuity leaders", "Use staged segmentation and controlled service restoration."),
    ),
    "DNS-001": five(
        choice("Inspect full queries, record types, process, resolver, domain ownership/age, response data, and historical baseline.", "Distinguishes CDNs/security tools from tunnelling.", "Possible tunnel remains active.", "Entropy/volume heuristic without corroboration.", "SOC analyst", "No rollback."),
        choice("Log all matching DNS transactions and capture relevant endpoint/network telemetry.", "Builds evidence about encoding and direction.", "Privacy/storage cost and continued communication.", "More context is required before blocking.", "Senior analyst and privacy/network owner", "Stop enhanced collection after approved window."),
        choice("Sinkhole or block the specific domain for the affected host.", "Interrupts suspected DNS C2/exfiltration narrowly.", "Can break legitimate services; wildcard blocking may overreach.", "Domain and requesting process are suspicious.", "Incident lead and DNS operations", "Time-limit and remove after validation; preserve sinkhole evidence."),
        choice("Isolate the endpoint and block the confirmed domain enterprise-wide.", "Stops endpoint activity and protects peers.", "Endpoint downtime and possible enterprise service impact.", "Payload or decoded content corroborates tunnelling.", "Incident commander and network owner", "Stage broad block and release clean systems after validation."),
        choice("Rebuild affected hosts and rotate exposed credentials/data-access tokens.", "Addresses confirmed tunnel payload and possible data/credential loss.", "High downtime and token/service disruption.", "Confirmed command channel or sensitive-data exfiltration.", "Incident commander, data and identity owners", "Controlled rebuild, token rotation, and monitored return."),
    ),
}


DETECTABLE_RULE_IDS = {
    "PROC-001", "PROC-002", "PROC-003", "PROC-004", "MEM-001", "CRED-001",
    "FILE-001", "FILE-002", "REG-001", "AUTH-001", "AUTH-002", "AUTH-003",
    "AUTH-004", "AUTH-005", "PRIV-001", "NET-001", "NET-002", "NET-003", "DNS-001",
}


def recommendations(rule_id: str) -> list[dict[str, str]]:
    items = PLAYBOOKS.get(rule_id, five(
        choice("Collect and validate the alert evidence.", "Improves confidence.", "Threat may continue during review.", "Unknown rule or incomplete context.", "SOC analyst", "No rollback."),
        choice("Increase monitoring for the affected entity.", "Adds context.", "Resource and privacy impact.", "Blocking is premature.", "Senior analyst", "Return monitoring to baseline."),
        choice("Apply a narrow temporary control to the confirmed indicator.", "Limits activity.", "May affect legitimate use.", "Indicator is sufficiently specific.", "Incident lead", "Time-limit and remove after review."),
        choice("Contain the affected account or host.", "Limits spread.", "Business interruption.", "Compromise is probable.", "Incident commander and owner", "Restore after remediation."),
        choice("Invoke the formal incident-response plan.", "Coordinates high-impact response.", "Substantial operational cost.", "Compromise and material impact are confirmed.", "Incident commander", "Follow continuity and recovery plans."),
    ))
    return [{"solution_code": f"{rule_id}-S{index:02d}", "alert_rule_id": rule_id,
             **item, **command_pair(index)} for index, item in enumerate(items, start=1)]


def solution_catalog() -> dict[str, Any]:
    """Return the complete ID-to-solutions relationship for JSON export."""
    validate_playbooks()
    return {
        "schema_version": "1.0",
        "warning": "Recommendations require human approval; system-impacting actions are never executed automatically.",
        "alerts": {
            rule_id: {
                "alert_rule_id": rule_id,
                "solutions": recommendations(rule_id),
            }
            for rule_id in sorted(DETECTABLE_RULE_IDS)
        },
    }


def validate_playbooks() -> None:
    missing = DETECTABLE_RULE_IDS - PLAYBOOKS.keys()
    extra = PLAYBOOKS.keys() - DETECTABLE_RULE_IDS
    wrong = {rule_id for rule_id, items in PLAYBOOKS.items() if len(items) != 5}
    if missing or extra or wrong:
        raise ValueError(f"Playbook coverage error: missing={missing}, extra={extra}, wrong_count={wrong}")
