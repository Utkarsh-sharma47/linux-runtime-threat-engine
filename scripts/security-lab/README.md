# Security Demonstration Lab

Two terminals. Two commands. Real telemetry — not fabricated alerts.

## Quick start

**Terminal 1 — live EDR dashboard**

```bash
cd /home/utkarsh/Documents/Class/xISSC-Project/rte-security
./scripts/start-monitor.sh
```

**Terminal 2 — run all safe scenarios**

```bash
cd /home/utkarsh/Documents/Class/xISSC-Project/rte-security
./scripts/run-security-lab.sh --scenario all
```

Then investigate in Terminal 1:

| Key | What to inspect |
|---|---|
| `p` | Processes / identity |
| `t` | Process ancestry |
| `n` | Network investigation |
| `s` | Security modules (all six) |
| `i` | Incidents |
| `r` | Alerts |
| `e` | Live events |
| `a` | Atomic sessions |
| `q` | Quit monitor |

Cleanup (explicit confirmation):

```bash
./scripts/cleanup-lab.sh
```

## Individual scenarios

```bash
./scripts/run-security-lab.sh --list
./scripts/run-security-lab.sh --dry-run --scenario all
./scripts/run-security-lab.sh --scenario process
./scripts/run-security-lab.sh --scenario network
./scripts/run-security-lab.sh --scenario persistence
./scripts/run-security-lab.sh --scenario integrity
./scripts/run-security-lab.sh --scenario exposure
./scripts/run-security-lab.sh --scenario anomaly
./scripts/run-security-lab.sh --scenario ransomware
```

Atomic (inspect by default; **not** part of `--scenario all`):

```bash
./scripts/run-security-lab.sh --scenario atomic
# Optional offline execute after reviewing the token:
RTE_LAB_ATOMIC_APPROVE=<token> ./scripts/run-security-lab.sh --scenario atomic
```

## Provenance labels

| Label | Meaning |
|---|---|
| `REAL_HOST_TELEMETRY` | Observed on this host by live collectors (`/proc`, `/proc/net`) |
| `SYNTHETIC_LAB_FIXTURE` | Isolated under `<tmp>/rte-security-lab/` (or ransomware sibling) |
| `ATOMIC_EXECUTION_EVIDENCE` | From an approved Atomic Red Team run |

The dashboard header shows a **SECURITY LAB** panel while a session is active.

## Layout

```
scripts/
  start-monitor.sh
  run-security-lab.sh
  cleanup-lab.sh
  security-lab/
    README.md
    start-monitor.sh
    run-security-lab.sh
    cleanup-lab.sh
    config/          # active-monitor.yaml symlink
    scenarios/       # docs pointers
src/runtime_engine/lab/   # importable orchestrator + scenarios
```

Lab data lives only under:

- `<tmp>/rte-security-lab/<session>/`
- `<tmp>/rte-ransomware-lab-<session>/` (ransomware simulator only)
