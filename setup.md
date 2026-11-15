# Linux Runtime Threat Detection Engine — Setup & Testing Guide

Definitive install and demonstration guide for the canonical repository. Every
command below exists in this tree and was verified against the implementation.

---

## 1. Project overview

This project is a **read-only** Linux runtime threat detection / EDR-style
prototype. It:

- Polls `/proc` for process discovery (not eBPF, not auditd).
- Runs six security modules (persistence, network, anomaly, integrity, exposure,
  ransomware) against configurable paths.
- Correlates rule matches into incidents by **stable process identity**
  (`host_id`, `pid`, `process_start_time`), not PID alone.
- Provides a Rich terminal dashboard for live investigation.
- Supports **offline** Atomic Red Team evaluation and an optional **live**
  Atomic bridge (approval-gated; synthetic acceptance tests for CI).

It does **not** modify system security policy, invent detections, or claim
packet-level visibility when only socket / interface snapshots are available.

---

## 2. Architecture

```
Collectors (/proc, /proc/net, iface counters)
        → Event normalizer → Pipeline (rules + correlation)
        → SQLite + DashboardState
        → Rich terminal (overview / modules / network / Atomic)
```

Security lab demos write under `/tmp/rte-security-lab/` only. Provenance labels:

| Label | Meaning |
|---|---|
| **REAL HOST TELEMETRY** | Observed from this laptop (`/proc`, sockets, NIC counters) |
| **SYNTHETIC LAB FIXTURE** | Files/metadata created under the temp lab only |
| **ATOMIC EXECUTION EVIDENCE** | Offline Atomic run (strace/`/proc` capture) |
| **OFFLINE EVALUATION** | Graded offline; **not** live dashboard telemetry |

See `docs/ARCHITECTURE.md` and `docs/LIMITATIONS.md` for depth.

---

## 3. Requirements

- Ubuntu/Linux with Python **3.11+**
- `git`, `python3-venv`, `strace` (recommended for Atomic tracing)
- Optional Atomic Red Team: `pwsh` + `Invoke-AtomicRedTeam` module +
  `~/AtomicRedTeam/atomics` (see `testing/atomic-red-team/install.md`)
- A TTY for the interactive dashboard (pipes fall back to line mode)

---

## 4. Installation

```bash
git clone https://github.com/Utkarsh-sharma47/linux-runtime-threat-engine.git
cd linux-runtime-threat-engine
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

---

## 5. Environment activation

```bash
cd linux-runtime-threat-engine
source .venv/bin/activate
```

Confirm the CLI:

```bash
python -m runtime_engine.main --help
```

---

## 6. Starting live monitoring

**First demonstration workflow — Terminal 1:**

```bash
./scripts/start-monitor.sh
```

This prepares an isolated lab session under `/tmp/rte-security-lab/`, writes a
lab-scoped `monitor.yaml` (security modules **on**, pointed at the temp tree),
and starts the Rich dashboard.

Equivalent:

```bash
./scripts/security-lab/start-monitor.sh
```

Manual (without lab session):

```bash
python -m runtime_engine.main --db monitor.db monitor --include-cmdline
```

Disable modules only if needed: pass `--no-security-modules` to `monitor`.

---

## 7. Terminal navigation

| Key | Page |
|---|---|
| `1` / `h` | Help / overview hints |
| `2` / `l` | Live event log |
| `3` / `p` | Processes |
| `4` / `t` | Process ancestry |
| `5` / `n` | **Host network interfaces + connections** |
| `6` / `s` | Security modules (all six) |
| `7` / `i` | Incidents |
| `8` / `a` | Atomic / lab sessions |
| `9` / `m` | Metrics / system health |
| `e` | Event filters |
| `r` | Alerts |
| `q` / Ctrl+C | Graceful stop + session report |

Inside module pages, follow on-screen prompts (`b` / Enter to return).

---

## 8. Network interface monitoring

**REAL HOST TELEMETRY** from `/sys/class/net` + `/proc/net/dev` + `/proc/net/route`.

Press **`5`** or **`n`** while monitoring. You should see:

- Interface name, type, state, MAC, MTU, IPv4/IPv6 (when readable)
- RX/TX **throughput** (bytes/sec between samples — **not** cumulative counters
  labeled as throughput)
- Cumulative RX/TX bytes and error/drop counters
- Default route interface + gateway
- Active TCP/UDP sockets attributed to processes where `/proc` allows

**Limitations:** socket snapshots miss short-lived connections; this is **not**
packet capture; some addresses need privileges; docker/veth/VPN interfaces appear
when the kernel exposes them.

---

## 9. Process monitoring

Press **`3`/`p`** for the process explorer and **`4`/`t`** for ancestry.

Identity is `(host, pid, start_time)`. PID reuse is handled by re-checking
`/proc` start ticks. CPU/memory appear when readable from `/proc`.

---

## 10. Running each individual security simulation

**Terminal 2** (monitor must already be running from Terminal 1):

```bash
./scripts/security-lab/run-process-test.sh
./scripts/security-lab/run-network-test.sh
./scripts/security-lab/run-persistence-test.sh
./scripts/security-lab/run-integrity-test.sh
./scripts/security-lab/run-exposure-test.sh
./scripts/security-lab/run-anomaly-test.sh
./scripts/security-lab/run-ransomware-test.sh
```

| Script | What it demonstrates | Provenance |
|---|---|---|
| `run-process-test.sh` | Shell → child under lab bin; ancestry; RT002 when rules match | REAL + lab path |
| `run-network-test.sh` | Local HTTP server + curl clients; process↔socket attribution | REAL |
| `run-persistence-test.sh` | Cron/systemd/SUID **fixtures** under the lab only | SYNTHETIC |
| `run-integrity-test.sh` | Merkle baseline create/modify/delete under lab paths | SYNTHETIC |
| `run-exposure-test.sh` | Unexpected lab SUID / posture findings | SYNTHETIC |
| `run-anomaly-test.sh` | Isolation Forest status; **UNTRAINED** if no model | REAL status |
| `run-ransomware-test.sh` | Safe simulator in `rte-ransomware-lab*`; RW001 | SYNTHETIC |

Orchestrator equivalent:

```bash
./scripts/security-lab/run-security-lab.sh --scenario process
# … same names: network, persistence, integrity, exposure, anomaly, ransomware
```

---

## 11. Running the complete demonstration lab

**Terminal 2:**

```bash
./scripts/security-lab/run-security-lab.sh --scenario all
```

or:

```bash
./scripts/run-security-lab.sh --scenario all
```

`--scenario all` runs the **safe** set only. It does **not** execute real Atomic
tests.

Useful flags:

```bash
./scripts/security-lab/run-security-lab.sh --list
./scripts/security-lab/run-security-lab.sh --dry-run --scenario all
./scripts/security-lab/run-security-lab.sh --scenario network --json
```

Each scenario reports name, status, times, telemetry sources, provenance,
events/findings/incidents observed, gaps, and cleanup status (also written under
the lab `evidence/` directory).

---

## 12. Running Atomic Red Team tests

Interactive reviewed-profile menu (inspect → explicit approval → offline run):

```bash
./scripts/security-lab/run-atomic-test.sh
./scripts/security-lab/run-atomic-test.sh --dry-run
```

Profiles offered: T1059.004 #8, T1033 #2, T1036.003 #2, T1071.001 #3
(domain `203.0.113.10` only), T1222.002 #1.

Synthetic live-path acceptance (**not** a real attack):

```bash
./scripts/security-lab/run-atomic-test.sh --live-accept
```

Lab orchestrator Atomic inspect (not in `all`):

```bash
./scripts/security-lab/run-security-lab.sh --scenario atomic
# Optional offline execute after reviewing the token:
RTE_LAB_ATOMIC_APPROVE=<token> ./scripts/security-lab/run-security-lab.sh --scenario atomic
```

CLI (full offline workflow):

```bash
python -m runtime_engine.main atomic inspect T1059.004 --test-number 8
python -m runtime_engine.main atomic run T1059.004 --test-number 8 --approve <token>
python -m runtime_engine.main atomic analyze --run-id <id>
python -m runtime_engine.main atomic live-accept
```

**Never** confuse offline Atomic evidence with live dashboard monitoring.

---

## 13. Viewing detections and incidents

In the live dashboard:

- `r` — alerts (rule matches)
- `i` — incidents (correlated by process identity / ancestry)
- `e` — filtered event stream
- `6`/`s` — per-module findings (persistence, network, anomaly, integrity,
  exposure, ransomware)
- `5`/`n` — connections ↔ processes ↔ Atomic sessions

CLI:

```bash
python -m runtime_engine.main --db "$RTE_LAB_DB" incidents
python -m runtime_engine.main --db "$RTE_LAB_DB" incident INC-0001
python -m runtime_engine.main --db "$RTE_LAB_DB" events --limit 50
```

---

## 14. Generating reports

```bash
python -m runtime_engine.main --db "$RTE_LAB_DB" export INC-0001
python -m runtime_engine.main --db "$RTE_LAB_DB" session <session-id>
python -m runtime_engine.main atomic report --run-id <atomic-run-id>
```

Incident inspection in the TUI can export JSON/text into the reports directory.

Lab evidence summary (after scenarios):

```bash
ls /tmp/rte-security-lab/*/evidence/
```

---

## 15. Cleanup

```bash
./scripts/security-lab/cleanup-lab.sh
# or
./scripts/cleanup-lab.sh
```

Requires explicit confirmation. Only removes paths under the lab root and the
sibling ransomware simulator directory. Never touches home directories, system
services, sudoers, or `authorized_keys`.

---

## 16. Troubleshooting

| Symptom | Check |
|---|---|
| `database not found` / monitor check fails | Start `./scripts/start-monitor.sh` first |
| Empty network interfaces | Modules enabled? Wait ≥2 polls for RX/TX rates |
| Anomaly always UNTRAINED | Train a model first (`anomaly train`); do not invent scores |
| Atomic refused risk B/C | Read inspect output; pass required flags; never as root |
| Dashboard falls back to lines | Need a real TTY; avoid piping stdout |
| Permission gaps on `/proc` | Expected for other users' processes; shown as telemetry gaps |
| Short connections missing | `/proc/net` snapshots; not packet capture |

Quality gates:

```bash
pytest -q
ruff check .
mypy src
```

---

## 17. Limitations

- `/proc` polling misses processes that start and exit between polls.
- Network monitoring is **socket snapshots**, not packet-level or flow export.
- Interface throughput is a **counter delta / elapsed time**, not wire speed.
- Anomaly detection requires a **valid trained model**; otherwise report UNTRAINED.
- Default rules are indicators for review, not proof of compromise.
- Offline Atomic evaluation ≠ live EDR dashboard evidence.
- Lab fixtures never weaken the real laptop's security configuration.

Full detail: `docs/LIMITATIONS.md`.
