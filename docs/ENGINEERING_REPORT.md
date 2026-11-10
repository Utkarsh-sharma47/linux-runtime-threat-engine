# Engineering report

Validation date: November 9, 2026. Version: 0.1.0.

## 1. Implemented features

A working Python 3.11+ package and CLI implement the complete replay-to-incident
pipeline. Two collectors supply the same validated Pydantic schema: sequential or
sorted JSONL replay and read-only Linux `/proc` process discovery. Six YAML rules
produce explainable detections. Start-time-qualified ancestry supports process chains,
missing nodes, replay exits and cycle guards. Identity/ancestry plus bounded event-time
correlation groups related alerts while preserving all matched events and separate
observed ancestor context. SQLite persists events, alerts, incidents, relationships and
session metrics. Human terminal reports and JSON exports are functional.

No existing threat engine was used. There is no remediation, execution of telemetry
arguments, network client, firewall operation or privileged instrumentation in the runtime.

## 2. Repository structure

```text
src/runtime_engine/
  collector/       Protocol, /proc snapshots and JSONL replay
  events/          Pydantic schema and shared normalization
  detection/       YAML loader, safe conditions and rule evaluation
  process/         Start-time-qualified ancestry graph
  correlation/     Bounded-window incidents and alert deduplication
  incidents/       Evidence-backed report generation and rendering
  storage/         SQLite persistence and evidence retrieval
  metrics/         Real counters and processing-time measurements
  config/          Validated YAML settings
  data/            Installed-package default rules
  pipeline.py      Component composition
  main.py          argparse CLI
rules/ config/ datasets/ scripts/
tests/unit/ tests/replay/ tests/integration/
docs/ .github/workflows/ .github/ISSUE_TEMPLATE/
README.md CONTRIBUTING.md SECURITY.md LICENSE pyproject.toml uv.lock
```

## 3. Architectural decisions

- The process identity includes host/boot namespace, PID and start token, not PID alone.
  `/proc` start ticks are retained as ticks, not mislabeled as creation timestamps.
- Ancestry is updated before rule matching to make observed parent names available.
  Explicit parent start identity is required for graph edges; missing data stays missing.
- JSONL replay has explicit sorting because late evidence cannot safely be assumed to
  be in chronological order. Sorting buffers input, which is documented.
- Rules use a small declarative AND language loaded with safe YAML, not Python eval.
  Missing values fail every condition. The shell rule has a verified behavior-level
  T1059.004 reference; other rules make no unsupported ATT&CK mapping.
- Correlation uses qualified identity or ancestor links and a maximum total time span.
  File equality/time proximity alone cannot merge unrelated processes. Multiple rules
  on one exact event share an incident even when process identity is unavailable.
- Repeated alerts keep every original event ID; identical event-ID repeats do not
  duplicate evidence. Conflicting ID reuse is rejected without replacing the original.
- Event/alert/incident changes are one transaction. A storage error aborts a run.
  Session state is intentionally not restored after restart; prior reports remain stored.
- Command lines are opt-in. New SQLite files use mode 0600. Terminal values are escaped.

## 4. Install and run

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m runtime_engine.main rules
python -m runtime_engine.main --db demo.db replay --input datasets/chain.jsonl
python -m runtime_engine.main --db demo.db incidents
python -m runtime_engine.main --db demo.db incident --id INC-0001
python -m runtime_engine.main --db demo.db export --id INC-0001 --format json
python -m runtime_engine.main --db demo.db metrics
python -m runtime_engine.main --db monitor.db monitor --duration 10
```

Global flags precede the subcommand. Use `--config config/default.yaml` or a custom
`--rules` file when needed. The installed `runtime-engine` entry point is equivalent.
A fresh database is needed for each independent repeat of the demos.

## 5. Scenario commands

First run `python scripts/generate_scenario.py`. Then run one replay per dataset:

```bash
python -m runtime_engine.main --db benign.db replay --input datasets/benign.jsonl
python -m runtime_engine.main --db shell.db replay --input datasets/shell.jsonl
python -m runtime_engine.main --db chain.db replay --input datasets/chain.jsonl
python -m runtime_engine.main --db sensitive.db replay --input datasets/sensitive.jsonl
python -m runtime_engine.main --db repeated.db replay --input datasets/repeated.jsonl
python -m runtime_engine.main --db unrelated.db replay --input datasets/unrelated.jsonl
```

Expected incident counts are 0, 1, 1, 1, 1 and 2 respectively. All records are marked
synthetic. No represented program, file access, privilege change or network connection
is actually performed. Combined replay produced 15 unique events, 13 rule matches,
six incidents, two suppressed repeated alerts and one suppressed event-ID duplicate.

## 6. Actual validation results

- Python 3.11.17: **78 tests passed**; statement coverage **97.15%**.
- Python 3.13.17: **78 tests passed** independently.
- Ruff lint and format check: passed across 39 Python files.
- Strict mypy: passed across 28 runtime source files on both tested interpreters.
- Source distribution and wheel: built successfully; installed wheel imported and its
  CLI loaded bundled rules from outside the source tree.
- Real Linux `/proc`: bounded read-only monitor smoke test passed as part of each suite.
- Synthetic full-pipeline replay, incident retrieval, metrics and JSON/terminal reports:
  executed successfully. Synthetic sample report and captured validation output are included.

GitHub Actions is configured for pushes to main, pull requests and manual dispatch,
using ubuntu-24.04 and Python 3.11/3.13. This report records local validation only;
remote publication/hosted CI status must be checked separately, not inferred.

## 7. Actual performance measurement

The final local 2,000-event JSONL replay benchmark (5% alerting events) recorded:

- Full replay wall time: **1.3569 seconds**.
- Full replay throughput: **1,473.9 events/second**.
- Mean pipeline latency: **0.6452 ms**; maximum: **11.1985 ms**.
- 100 rule matches and 100 incidents, zero invalid records or collector errors.

Environment: Linux x86_64, kernel 6.1.189+, two logical CPUs, Python 3.11.17,
SQLite 3.53.1, Pydantic 2.14.3. See `benchmark.json` for unrounded measurements.
This is a single small local run, not a production-capacity or accuracy claim. It
includes normal SQLite persistence; filesystem/cache behavior can dominate timings.

## 8. Known limitations

Polling misses short-lived processes and same-lifetime exec changes. Observations are
not atomic and permissions/namespaces reduce visibility. Live file/network/privilege
telemetry, audit and eBPF are not implemented. Rules can false-positive. Correlation
is session-local and order-dependent, with no retrospective incident merging. Memory
and SQLite retention are unbounded; monitor in bounded sessions. There is no concurrency
support, input authentication, database encryption, tamper resistance or production SLA.
All limitations and privacy practices are detailed in `LIMITATIONS.md`.

## 9. Git status

Implementation branch: `feat/linux-runtime-threat-engine-prototype`.
Core implementation commit: `357896f` (`feat: implement read-only runtime detection
and correlation prototype`). Documentation/CI and any subsequent import/merge commits
are discoverable with `git log --oneline --all`. The source archive includes working
source; the accompanying git bundle retains local commit history. No force-push or
existing-repository overwrite is part of this work.

The owner later authorized creating a new personal private repository and merging/
pushing tested work to main. Remote status is deliberately not asserted in this static
local report. The completion message must name the verified repository and CI result,
or the exact remaining authentication/publication blocker.

## 10. Next engineering work

Implement an authorized audit adapter and optional eBPF collector, bounded graph/
incident caches, explicit retention, schema migrations and reliable cross-session
restoration. Add authenticated telemetry provenance, richer allowlists, controlled
load/soak studies, broader Linux tests and an independent security review. Any future
remediation would require a separate design and explicit authorization; this prototype
remains a detection/reporting system.
