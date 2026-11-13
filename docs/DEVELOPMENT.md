# Development guide

General setup, quality gates and pull-request rules are in
[CONTRIBUTING.md](../CONTRIBUTING.md). This page covers the code layout and how to extend
the security modules.

## Environment

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e '.[dev]'        # add ,ml for scikit-learn (Isolation Forest)
# or: uv sync --extra dev --extra ml --locked
```

Without the `ml` extra the anomaly module uses its deterministic robust z-score
fallback, and the tests for both paths still run (scikit-learn tests are skipped when it
is missing).

Quality gates (all must pass before a merge):

```bash
ruff check . && ruff format --check .
mypy                       # strict, configured for src/
pytest -q --cov=runtime_engine
```

A `COLUMNS` value exported in your shell changes Rich's terminal width and can break
rendering assertions; run the tests with it unset.

## Layout

| Path | Purpose |
|---|---|
| `collector/` | `/proc` process collector, replay collector, `/proc/net` socket reader |
| `pipeline.py` | ancestry, rules, correlation, storage; `process_finding` for security findings |
| `monitor/` | session threads and queue, dashboard state, investigation queries |
| `security/` | the six modules, `findings.py` (Finding, policy, coverage, state), `scheduler.py`, `fsutil.py` (safe walking and hashing), `modules.py` (construction from settings) |
| `terminal/` | Rich dashboard, inspection pages (`interactions.py`), standalone security commands (`security_app.py`), views |
| `config/settings.py` | validated settings, including `security:` per module |
| `storage/database.py` | SQLite schema, including `security_findings` and `security_baselines` |

## Adding or changing a security module

1. Implement a class with `name`, `interval` and `scan() -> ScanReport`. Never raise for
   expected conditions: unreadable paths go into `Coverage.denied`, missing telemetry into
   `Coverage.unavailable`, and a failed precondition sets the status (`no-baseline`,
   `unavailable`, ...). Unexpected exceptions are turned into an `error` report by
   `safe_scan`, which the terminal shows as "not a clean result".
2. Create findings with `Finding.create(module, rule_id, resource, ...)` and set
   `finding.revision` from only the evidence whose change should be re-reported. Rule IDs
   are two or three capitals plus three digits (`PM001`, `RW001`) so allowlist entries
   like `RW001:/path/*` work.
3. Apply `SeverityPolicy.apply()` to the raw findings and report the suppressed count.
4. Add a settings class deriving from `ModuleSettings`, register it in
   `SecuritySettings`, and construct the module in `security/modules.py`, returning a
   reason when it is off.
5. Add a view in `terminal/views/` built from `security_common` (header, coverage panel,
   findings table) and a standalone command in `terminal/security_app.py` and `main.py`.
   Add the module to `MODULES` in `security/findings.py` and to `TITLES`/`RENDERERS` in
   `terminal/views/security_view.py` so the `s` page lists it.
6. Tests must use fixtures under `tmp_path`, fake `/proc` trees or synthetic series;
   never real malware, root or changes outside the test directory.

Safety rules for module code: open files with `O_NOFOLLOW` (see `fsutil`), never follow
symlinks out of a scanned root, never read private-key contents, password hashes or
packet payloads, never change permissions or configuration, and bound every buffer,
cache and per-scan amount of work.

## Running the monitor during development

```bash
python -m runtime_engine.main --db dev.db monitor --duration 30          # dashboard, all modules
python -m runtime_engine.main --db dev.db monitor --no-security-modules  # core engine only
python -m runtime_engine.main --db dev.db monitor --no-dashboard --duration 20  # line output
```

Use a throw-away database; monitoring databases contain host telemetry and must not be
committed (`*.db`, `models/` and generated reports are ignored by git).
