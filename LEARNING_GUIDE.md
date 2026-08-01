# Line-by-line learning guide

Read this beside `app.py`. Blank lines only separate ideas, so they have no runtime effect. Triple-quoted text is a **docstring**: documentation stored on a module, class, or function.

## Lines 1–15: runtime and imports

- `#!/usr/bin/env python3` is a Unix launcher hint. Windows ignores it when you run `python app.py`.
- `from __future__ import annotations` makes type annotations easier to evaluate and permits forward-looking typing behavior. `__future__` ships with Python.
- `import argparse` loads Python's command-line parser.
- `csv` reads CSV exports; `json` reads/writes JSON; `subprocess` starts Git. All three are standard-library modules.
- `from dataclasses import asdict, dataclass`: `@dataclass` generates boilerplate such as initialization; `asdict` recursively converts instances to dictionaries.
- `datetime` represents time; `timezone.utc` represents UTC.
- `Path` is the standard object-oriented filesystem-path type from `pathlib`.
- `Any` means any value type. `Iterable[T]` means something that can yield values of type `T`. They come from `typing` and are mainly for readers and type checkers.

## Constants

- Uppercase names signal constants by convention. `{...}` creates a `set`, optimized for membership tests such as `child in SHELLS`.
- These sets hold lowercase executable names. They are intentionally small, auditable teaching inputs rather than an alleged universal whitelist.

## `ProcessEvent`

- `@dataclass(frozen=True)` asks Python to generate `__init__`, equality, and representation methods and prevents field reassignment after creation.
- `class` defines a new type. `ProcessEvent` is the normalized record shared by all parsers and rules.
- A line such as `host: str` declares a required field whose expected type is text.
- A line such as `hashes: str = ""` gives the field an empty-string default, so it is optional when constructing an instance.
- `@property` lets callers use `event.identity` like data although Python computes it by calling the method.
- `tuple[str, int, str]` documents a three-item return value. The identity prefers `ProcessGuid`; otherwise it combines host, PID, and timestamp because operating systems reuse PIDs.

## `Alert`

- This second immutable data class separates detection metadata from the original telemetry.
- `event: ProcessEvent` nests the evidence inside the alert, preserving what caused the match.

## Helper functions

- `def` defines a function. Text inside parentheses names inputs; `-> str` documents the return type.
- `leaf`: `replace` normalizes Windows separators; `rsplit(..., 1)` splits once from the right; `[-1]` chooses the final component; `lower()` makes matching case-insensitive.
- `integer`: `str(value or "0")` supplies zero for empty values. `int(..., 0)` recognizes decimal and prefixes such as hexadecimal `0x`. `try/except ValueError` converts malformed IDs to zero rather than stopping ingestion.
- `first`: `*names` collects any number of field-name arguments into a tuple. The loop returns the first present, non-empty value. This is how different vendor field names converge on one schema.

## `normalize`

- `raw: dict[str, Any]` means a dictionary with string keys and values of any type.
- `executable` and `parent_executable` try ECS, Sysmon, Windows 4688, and Auditd-style names in priority order.
- `str(...)` ensures fields have a predictable text type.
- The timestamp fallback uses an aware UTC time; naive local timestamps are dangerous in cross-host investigations.
- `return ProcessEvent(...)` constructs the normalized record. Each keyword on the left is our schema field; each expression on the right extracts or derives its value.
- `process.name`, PID, command line, parent name/path/PID, GUID, hashes, source, user, host, and time are retained because together they support investigation. Parent-child names alone are weak evidence.

## `load_events`

- `path.suffix.lower()` chooses a parser using the filename extension.
- `with path.open(...) as handle` is a context manager; it closes the file even when an error occurs.
- `utf-8-sig` accepts ordinary UTF-8 and harmlessly removes a spreadsheet-style byte-order mark.
- `csv.DictReader` yields each row as a field dictionary.
- `json.loads` converts JSON text to Python values. JSON can contain a list or one object; JSONL parses each nonblank line separately.
- The list comprehension calls `normalize` once per row and returns all normalized events.

## `detect`

- `child` and `parent` reduce full paths to comparable executable names.
- `alerts: list[Alert] = []` creates an empty result list.
- The nested `add` function avoids repeating construction code. `append` adds an alert.
- `if parent in OFFICE and child in SHELLS` expresses Boolean AND: both conditions must hold.
- `SHELLS | {"whoami", ...}` uses set union, meaning either a shell or one of the added discovery tools.
- LSASS and svchost checks demonstrate expected-parent detection. Missing parent data also alerts; analysts must distinguish suspicious ancestry from telemetry loss.
- The untrusted-path expression demonstrates string containment and `or`. A browser/mail parent plus a user-writable temporary child produces an alert.
- MITRE IDs describe behaviors; they do not prove maliciousness. `T1059` is command/script interpretation, while `T1036` covers masquerading.

## `build_lineage`

- The dictionary key is `(host, parent_pid)`, not PPID alone, because identical PIDs exist on different machines.
- `setdefault(key, [])` creates a child list on first use; `append(event)` adds the child.
- This index answers “what did PID X launch?” For historical accuracy, mature implementations also constrain by start/end time or use GUID/entity relationships.

## Sigma functions

- `sync_sigma` fixes the official HTTPS repository URL in code. If `.git` exists, Git performs a fast-forward-only update. That refuses history rewriting. A nonempty unrelated destination is rejected to prevent overwriting user files.
- `subprocess.run([...], check=True)` passes arguments as a list rather than a shell string. `check=True` raises an error if Git fails.
- `sigma_export` imports `yaml` locally because only this optional command needs PyYAML. PyYAML is a third-party library listed in `requirements.txt`.
- Both `rglob("*.yml")` and `rglob("*.yaml")` recursively find every rule file. `sorted` makes output repeatable.
- `yaml.safe_load_all` safely reads files containing one or multiple YAML documents without enabling arbitrary Python-object construction.
- `isinstance(rule, dict)` rejects blank or non-mapping documents. `{**rule}` copies every original Sigma field, while `_export` records provenance.
- `write_sigma_json` creates the output directory, writes a temporary file, and replaces the destination only after serialization succeeds. This reduces the chance of leaving a half-written JSON file.
- Exporting is not executing. Sigma conditions can contain modifiers, correlations, and backend-specific mappings; use pySigma plus an appropriate SIEM backend for faithful conversion and deployment.

## `main` and program entry

- `ArgumentParser` defines the help screen. Subparsers create the `analyze`, `sigma-sync`, and `sigma-catalog` commands.
- `required=True` requires a command. `type=Path` converts text arguments to paths. `nargs="?"` makes an argument optional, and `default` supplies its value.
- `args = parser.parse_args()` reads the actual command line.
- Each command branch performs its work, prints a human/machine-readable result, and returns status code `0`, meaning success.
- The nested list comprehension runs every event through `detect` and flattens the resulting alert lists.
- `asdict` makes dataclasses JSON-serializable; `indent=2` makes output readable.
- `if __name__ == "__main__"` is true only when the file is run directly, not imported for tests.
- `raise SystemExit(main())` exposes `main`'s return value as the operating-system exit code.

## Vocabulary that matters on the job

- **Telemetry:** raw observations produced by endpoints, servers, identity systems, and network controls.
- **Parser:** converts a source format into typed fields.
- **Normalization:** maps many vendor field names into one stable schema.
- **Enrichment:** adds context such as asset role, signer, reputation, owner, or threat intelligence.
- **Detection:** logic that selects behavior worth reviewing.
- **Alert:** a detection result plus evidence and metadata.
- **Correlation:** links observations across time, hosts, users, and data sources.
- **False positive:** rule logic matched, but investigation finds no malicious behavior.
- **Baseline:** measured normal behavior for this particular environment—not a generic internet list.
- **Triage:** quick evidence-led assessment that prioritizes or closes an alert.
