# Testing and validation

Install development dependencies in Python 3.11+ (`pip install -e '.[dev]'`).

```bash
ruff check .
ruff format --check .
mypy src
pytest -q --cov=runtime_engine --cov-report=term-missing --cov-fail-under=90
python -m build
python scripts/benchmark.py --events 2000
```

## What is exercised

- Unit: strict PID/UID validity, aware UTC normalization, absent telemetry, identity
  namespaces, every default rule's positive/negative/disabled cases, YAML safety,
  root-path boundaries, ancestry reconstruction/missing parents/cycles/exits/PID reuse,
  exact and conflicting event duplicates, evidence-preserving alert deduplication,
  event-time window boundaries and late events, severity, SQL parameterization and
  transaction rollback, metrics, settings and terminal control-character escaping.
- Reliability: malformed JSONL lines, missing fields, out-of-order replay, permission
  errors, disappearing/malformed `/proc` entries, parent reuse, stat races, missing UID,
  and verification that a synthetic `/proc` fixture is not modified by collection.
- Replay: benign, office-parent shell, correlated multi-rule chain, sensitive access,
  repeated events and unrelated processes. Benign data yields no incidents.
- Integration: collector through SQLite and reports, all CLI commands, missing report
  IDs, non-overwriting JSON export, invalid configuration/input exit codes, package
  resources and a real read-only `/proc` monitor smoke test on Linux.
- Packaging: wheel installation into a fresh environment and execution from outside
  the source checkout, so the bundled YAML must actually ship in the wheel.
- Live terminal (`tests/terminal/`, no real terminal or suspicious activity required):
  dashboard initialization and refresh, event/severity formatting, no-colour output,
  long command-line truncation vs. full detail, control-character escaping, empty
  stream/incident states, rendering at 20x6 up to 300x100 for every verbosity, renderer
  failure and fallback to line output, broken pipes, metrics/alerts/help pages, process
  inspection (live and historical with a reused PID against a fake `/proc`), incident
  inspection and non-overwriting 0600 export, event filters, `q`, Ctrl+C on the
  dashboard and inside a page, a second interrupt during shutdown, non-interactive
  fallback, `--json`, queue overflow with backpressure and no drops, drops only after an
  abort, concurrent snapshots during updates, collector and storage failures, no event
  loss and no duplicate incidents on shutdown, session persistence/history commands,
  final summary values against pipeline metrics, and real `/proc` subprocess runs
  stopped by `--duration`, SIGTERM and SIGINT.

See `validation.txt` for captured local outputs. The measured result is 78 tests passed
on Python 3.11.17 and separately 78 on 3.13.17. The Python 3.11 coverage run measured
97.15% statement coverage (not branch coverage). Ruff lint/format and strict mypy
passed. The wheel and source distribution built, and the wheel's installed CLI
loaded the bundled rules outside the checkout. These are local results, not a hosted
GitHub Actions claim. The configured CI runs on ubuntu-24.04 for Python 3.11 and 3.13.
With the live terminal interface the local suite is 142 tests on Python 3.12.3 with
96.07% statement coverage; Python 3.11/3.13 were not re-run locally for this change.
The interactive dashboard was additionally exercised manually through a pseudo-terminal
against the real `/proc` collector (key commands, pages, resize, `q` and Ctrl+C).

### Security modules

`tests/security/` covers each module without real malware, root or host changes: fake
`/proc` and filesystem trees under `tmp_path`, synthetic connection and timing series,
synthetic anomaly datasets and the ransomware simulator in a temporary lab.

- Persistence: baseline/scan diffs for every watched category, SUID and capability
  changes, unreadable paths reported as coverage gaps, allowlists, severity overrides,
  promotion into correlation exactly once per revision, the session queue, shutdown
  while modules run (including a scan that hangs past the grace period) and counters.
- Network: `/proc/net` parsing (IPv4/IPv6, states), unique/ambiguous/unattributed
  attribution, beacon coefficient-of-variation on periodic vs. jittered series,
  exclusions and live NETWORK_CONNECTION events reaching rule RT006.
- Anomaly: feature extraction, robust scaling, Isolation Forest and robust-z fallback
  agreement on injected outliers, thresholds, explanations and model artifact hash checks.
- Integrity: Merkle leaf/node encoding, odd-node promotion, empty tree, proofs, tamper
  and baseline-replacement detection through signed anchors, symlink and permission
  handling, `--full` bypassing the hash cache.
- Exposure: each EX rule on fixture files, risk scoring and grades, the accepted
  baseline and incremental scans.
- Ransomware: entropy values, sampling bounds and rate limit, high entropy alone not
  alerting, mass modification alone not alerting, encryption-like activity alerting,
  window and memory bounds, polling fallback, missing directories reported as degraded,
  simulator refusals outside its lab and cleanup removing only its own files.
- Terminal: the `s` menu, module pages, filters, finding details from live and stored
  data, the dashboard header line, the footer key and the session summary section.

With the six modules the local suite is 231 tests on Python 3.12.3, 94% statement
coverage, Ruff and strict mypy clean. The full-screen dashboard with all modules was
also run through a pseudo-terminal against the real host until `--duration` stopped it.
Counts above are earlier milestones. The current suite is the release measurement below.

## Release integration (2026-11-15)

Measured on Python 3.11.15 with `pip install -e '.[dev]'` and no `ml` extra, which is
what GitHub Actions installs:

- `ruff check .` and `ruff format --check .` passed.
- `mypy src` passed under the strict configuration.
- `pytest -q --cov=runtime_engine --cov-report=term-missing --cov-fail-under=90`:
  288 passed, 2 skipped, 90.61% statement coverage. The skips are the Isolation Forest
  cases. With `pip install -e '.[dev,ml]'` those anomaly tests passed (10 passed in
  `tests/security/test_anomaly.py`).
- `python -m build` produced the sdist and wheel. Installed outside the source tree,
  the wheel imported as version 0.1.0 and `runtime-engine rules` printed the six
  bundled rules.
- `atomic live-accept` submitted two synthetic events through `MonitorSession` and the
  shared pipeline. The report grade was DETECTED for RT002, RT005 and RT006, one
  incident was correlated, and `evidence_label` was SYNTHETIC. No Atomic test was
  executed. The harness does not start the six module schedulers; their component
  grades were NOT APPLICABLE and the report says their telemetry was unavailable.
- Dashboard, security menu, network investigation and Atomic run list were rendered at
  150×50, 100×35, 80×24 and 60×15. The three full layouts fill the screen; 60×15 uses
  the compact view and does not exceed the height.

## Reproduce a complete demo

```bash
python scripts/generate_scenario.py
python -m runtime_engine.main --db demo-fresh.db replay --input datasets/sample_events.jsonl
python -m runtime_engine.main --db demo-fresh.db incidents
python -m runtime_engine.main --db demo-fresh.db incident --id INC-0002
python -m runtime_engine.main --db demo-fresh.db export --id INC-0002 --format json
python -m runtime_engine.main --db demo-fresh.db metrics
```

On a **fresh** database, combined replay processes 15 unique events, evaluates 13
rule matches, creates six incidents, suppresses two repeated alerts and ignores one
identical event-ID duplicate. INC-0002 is the multi-step chain: six distinct rules,
five matched supporting events and a separate benign ancestor context event.
`sample_incident.json` is an actual synthetic report from that replay. Reusing the
same database skips its already-stored events, so use a different filename for a
fresh run. A rule match does not prove that the represented behavior was malicious.

CLI exit codes: 0 success; 1 I/O/configuration/storage/platform failure; 2 invalid CLI
arguments or replay completed with rejected records; 3 requested incident not found.
Collectors count invalid JSON records without storing their raw content. Permission
errors contribute collector-error metrics and can be inspected with `--verbose`.
Ctrl-C during monitor polling ends cleanly and persists that session's metrics.

## Benchmark

`scripts/benchmark.py` writes an actual temporary JSONL dataset, replays it with the
same collector/pipeline and an on-disk SQLite database, then removes its temporary
files. It never simulates a throughput number. The committed `benchmark.json` records
one 2,000-event run with 100 matching events, full environment and timings. Wall
throughput includes parsing and storage; pipeline throughput excludes collector work.
Filesystem, journal/fsync latency, event mix, cache state and evidence size affect the
result. This is not a maximum-rate, accuracy or production-readiness claim.

## Known test boundaries

There is no real malicious workload, independent security audit, kernel instrumentation
validation, exhaustive Linux distribution matrix, multi-writer concurrency test or
long-duration soak test. A passing suite proves these covered expectations, not that
all bugs or attacks are detectable. See LIMITATIONS.md.
