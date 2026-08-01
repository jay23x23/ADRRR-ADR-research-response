# Security-lead review of Argus SIEM

## Scope and trust boundaries

Reviewed components include the localhost web service, browser UI, EDR credentials and outbound connections, Sigma download/build, custom rules, event ingestion, SQLite/JSON storage, response commands, administrative APIs and audit records.

Trust boundaries:

1. Browser → local administration server.
2. Administration server → OS credential store.
3. Connector → external EDR tenant.
4. Untrusted vendor/event content → normalization, matching, storage and display.
5. Sigma repository → catalogue/compiler.
6. User-authored detection JSON → local evaluator.
7. Recommended command text → human analyst; it never crosses into an execution API.

## Confirmed issues fixed

### Localhost/DNS-rebinding exposure

**Risk:** Binding to `127.0.0.1` alone did not validate the HTTP `Host`. A hostile domain resolving to loopback could potentially reach GET APIs under its own origin.

**Fix:** Strictly allow only `127.0.0.1:8765` and `localhost:8765`; reject other hosts with 421. Require the per-run token for every `/api/*` GET and POST. Require an exact same-origin value for writes.

### CSRF and browser policy

**Risk:** Writes had a token, but reads did not. The original CSP allowed all inline scripts.

**Fix:** Cryptographic token comparison, token-protected reads, same-origin writes, nonce-restricted JavaScript, frame denial, MIME sniffing prevention, no-referrer policy, restrictive browser permissions and no caching.

### SSRF through EDR console configuration

**Risk:** An administrator-supplied SentinelOne or Falcon URL could make the process request local/cloud-metadata/internal services.

**Fix:** Require HTTPS, a hostname, no embedded credentials/fragments, DNS resolution and public addresses by default. Block redirects. SentinelOne paths must remain under `/web/api/`. Approved on-premises consoles require the explicit `ALLOW_PRIVATE_EDR_URLS=1` deployment decision.

### Regular-expression denial of service

**Risk:** Python's standard regular-expression engine has no built-in execution timeout. A custom or imported pattern could cause catastrophic backtracking.

**Fix:** Removed `re` from the locally executable modifier set. Regex Sigma rules remain catalogue-only/rejected unless a future bounded regex engine is adopted.

### Unbounded API/data processing

**Risk:** Full JSON libraries, large analysis files, excessive events and unlimited request threads could exhaust memory/CPU.

**Fix:** JSON-library pagination (maximum 100 records per response), 10 MB/10,000-event analysis limits, 64 KB request bodies, bounded 16-request concurrency and existing serialization of administrative mutations.

### Sensitive-data exposure

**Risk:** Vendor payloads and public error messages could expose tokens, credentials, cookies, connection strings, paths or excessive command-line data.

**Fix:** Recursive secret-field redaction before vendor imports are written or stored, redaction again on display, bounded strings/depth/collection sizes and sanitized public errors. Credential values remain in the OS credential store.

### Missing administrative audit trail

**Risk:** Catalogue refresh, connector changes, imports, custom rules and analyses were not recorded centrally.

**Fix:** Successful and failed write actions append secret-redacted entries to `data/security-audit.jsonl`. Each entry incorporates the prior hash to expose modification/reordering.

### Legacy setup server

**Risk:** `connector_setup.py` remained a weaker alternate localhost surface.

**Fix:** Added the same Host, Origin and constant-time token validation to its sensitive routes. The unified app remains the recommended entry point.

## Backdoor assessment

No intentional backdoor was identified:

- no hard-coded EDR credentials;
- connectors request/read alerts and do not invoke vendor response actions;
- response objects specify `auto_execute: false`;
- the web API exposes no endpoint for arbitrary shell commands;
- subprocess calls use argument arrays and fixed program names/URLs rather than a shell;
- local analysis paths are restricted to simple filenames in the application folder;
- SQLite operations use parameters;
- YAML uses `safe_load_all`;
- unknown/unsupported detection syntax fails closed.

This assessment is source-based and not a substitute for dynamic testing, dependency scanning or an independent penetration test.

## Remaining high-priority deployment risks

1. **No authentication/RBAC:** Loopback access assumes one trusted local operator. Do not expose the port on a LAN, proxy or container ingress.
2. **Development HTTP server:** Python documents `http.server` as unsuitable for production. Replace it with an authenticated framework and hardened reverse proxy/service boundary.
3. **No encryption at rest:** SQLite, JSONL and catalogue files are plaintext. Use encrypted volumes/database controls and least-privilege filesystem ACLs.
4. **Local audit deletion:** Hash chaining exposes edits but cannot stop a local administrator deleting the entire file. Forward audit events to protected remote storage.
5. **Supply chain:** Sigma updates track the remote repository rather than an internally reviewed/pinned commit. Record, approve and pin release/commit provenance before production promotion.
6. **Dependency assurance:** Add locked hashes, SBOM, vulnerability scanning, signature/provenance checks and controlled updates for Python, PyYAML, Keyring and FalconPy.
7. **Connector resilience:** Add durable checkpoints, retry budgets, rate-limit handling, clock-skew monitoring, dead-letter storage and health alerts.
8. **Forensic fidelity vs redaction:** The lab now redacts likely secrets. A production evidence vault should preserve necessary originals under stricter encryption/access/retention controls while exposing redacted analyst views.
9. **Multi-tenant/data authorization:** There is no tenant or device-group authorization layer.
10. **Dynamic assurance:** Fuzz parsers and APIs, test browser attacks, scan dependencies, run static analysis and perform an independent penetration test.

## Safe deployment statement

Use Argus only as a local learning lab on a trusted workstation. Keep it bound to loopback, run without unnecessary administrator privileges, use read-only EDR scopes, protect the project directory, and never expose port 8765 externally.
