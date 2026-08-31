# DriftSentry review checklist

Failure modes specific to this codebase. Skip sections the diff doesn't touch.

## Contents

- [Sensitive data](#sensitive-data)
- [Scan correctness](#scan-correctness)
- [Error handling and blast radius](#error-handling-and-blast-radius)
- [Generated output: HCL, scripts, reports](#generated-output-hcl-scripts-reports)
- [Cross-platform](#cross-platform)
- [CLI contract](#cli-contract)
- [State parsing](#state-parsing)
- [Tests](#tests)

---

## Sensitive data

Terraform state routinely holds passwords, private keys, and tokens in
`sensitive_attributes`. Every path out of the process is a potential leak.

- Is redaction applied at **every** sink, or only the one the PR touched? The
  sinks are: the Rich table, the JSON formatter, the HTML report, the Markdown
  report, `--save`, any file persisted to the working directory, log lines, and
  exception messages.
- Redaction applied at render time only still leaks if some other code path dumps
  `result.model_dump()` straight to disk. Trace the model, not the formatter.
- Does the redaction survive nesting — lists, dicts, and dotted paths into both?
- Does an exception traceback carry attribute values? `f"...: {e}"` on a boto3
  error can include response bodies.
- Anything written to the repo root needs a matching `.gitignore` entry, or the
  next contributor commits their infrastructure state.

## Scan correctness

The core promise is that reported drift is real drift. False positives here send
people chasing phantom `terraform import` runs.

- When an AWS API call fails, the resource type must be **absent** from results,
  not empty. An empty list makes every managed resource of that type look
  `DELETED`.
- Conversely, a partial failure must not be silently swallowed — it belongs in
  `errors` and should surface in the summary.
- Does the change affect `UNMANAGED` detection? Missing a resource type in the
  cloud listing hides shadow IT rather than reporting it.
- Attribution (CloudTrail) is best-effort: it should degrade, never fail the scan.
- Filters and policy rules should apply consistently across table, JSON, and HTML,
  or the same scan tells three stories.

## Error handling and blast radius

- A change from `return []` to `raise` moves the failure boundary. Ask: **who
  catches it now?** Per-resource-type is usually right; per-item usually is not,
  because one malformed resource then kills an entire type.
- Bare `except Exception` that logs at `debug` level hides real problems.
- Retries and pagination: does a failure mid-pagination return a partial list that
  gets treated as complete?

## Generated output: HCL, scripts, reports

DriftSentry writes files that people then run.

- HCL string escaping: `"`, `\`, `${` (Terraform interpolation), and newlines. An
  unescaped `${` in a tag value turns into an interpolation and breaks or, worse,
  resolves.
- `import.sh` is chmod 755 and executed by the user. Resource IDs interpolated
  into shell commands need quoting; an ID containing a space or `;` is a command
  injection into the maintainer's own terminal.
- Generated resource names must be valid Terraform identifiers — no leading
  digits, no hyphens.
- Files are opened in append mode in places. Does a second run duplicate content
  instead of replacing it?
- HTML reports are self-contained: attribute values go into HTML and need
  escaping, or a resource tag becomes stored XSS in a report someone shares.

## Cross-platform

CI runs on Ubuntu; users run Windows and macOS.

- Every `open()` and `read_text()`/`write_text()` needs `encoding="utf-8"`. The
  codebase emits em-dashes and emoji, and Windows defaults to cp1252 — this fails
  hard, not gracefully.
- `Path` over string concatenation; no hardcoded `/`.
- `Path.cwd()` for artifacts is a deliberate choice with consequences — check it
  is intentional and documented, not incidental.
- `chmod(0o755)` is a no-op on Windows; not a bug, but don't rely on it.

## CLI contract

- Exit codes are part of the API for CI users. `scan` failing on drift vs failing
  on error must stay distinguishable.
- Renamed or removed flags and config keys are breaking changes and need a note in
  the PR.
- New required config keys break existing `.driftsentry.yaml` files. Defaults?
- Does `--output json` still emit *only* JSON? Rich console output leaking into
  stdout breaks pipelines.
- State shared between `scan`, `report`, and `remediate` via module globals only
  works within one process. Persisting it to disk changes the security surface —
  see [Sensitive data](#sensitive-data).

## State parsing

- Terraform and OpenTofu state format versions differ; check version handling
  wasn't narrowed.
- S3 backend: does the change assume local file access anywhere?
- Missing or malformed state should give a clear error, not a `KeyError`.

## Tests

- Do new tests fail on `main`? Verify rather than assume.
- Are AWS interactions mocked? Any test needing live credentials or network is a
  blocker.
- Redaction tests should assert the secret value is **absent** from the whole
  output string, not just that the marker is present.
- Do tests clean up files they write, and does the suite still pass when run in a
  different order or from a different working directory?
