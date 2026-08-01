# Security policy

## Intended use

EDRRR Portfolio Edition is a local, analyst-operated learning and demonstration
SIEM. It binds to loopback, never executes response commands, and treats imported
logs and rules as untrusted input.

It is not a production SOC platform, autonomous remediation system, malware
sandbox, or replacement for a supported EDR/SIEM product.

## Safe operation

- Run it as a standard user, not Administrator or root.
- Keep it bound to `127.0.0.1`.
- Use only synthetic or properly anonymized portfolio data.
- Do not commit connector profiles, secrets, databases, imported logs, Cases or
  audit history.
- Review placeholders, scope, authorization, impact and rollback before copying
  any response command into a terminal.
- Response commands are advisory; EDRRR does not execute them.
- Use read-only vendor API credentials with the minimum required scope.

## Controls implemented

- Loopback-only HTTP listener and Host/Origin validation.
- Per-process random CSRF/API token.
- Restrictive Content Security Policy and browser security headers.
- Upload size, archive-count, expansion-ratio and path-containment checks.
- JSON/JSONL validation with bounded event counts.
- HTTPS-only remote connectors and private-address restrictions by default.
- OS credential-store integration rather than plaintext secret files.
- Redaction and hash-chained local security audit events.
- Human approval warnings and no automatic command execution.
- Unsupported foreign detection syntax is rejected rather than silently enabled.

## Reporting a vulnerability

Do not include credentials, private logs or exploit data in a public issue. Share
the smallest synthetic reproduction, affected version, expected behaviour and
observed behaviour with the repository owner through a private channel first.

