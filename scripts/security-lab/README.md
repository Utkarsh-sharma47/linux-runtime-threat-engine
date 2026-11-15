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

Then investigate in Terminal 1 (`1`–`9` numeric aliases work too):

| Key | What to inspect |
|---|---|
| `3`/`p` | Processes / identity |
| `4`/`t` | Process ancestry |
| `5`/`n` | Host NICs (RX/TX) + connections |
| `6`/`s` | Security modules (all six) |
| `7`/`i` | Incidents |
| `r` | Alerts |
| `2`/`l` | Live events |
| `8`/`a` | Atomic sessions |
| `q` | Quit monitor |

Cleanup (explicit confirmation):

```bash
./scripts/cleanup-lab.sh
```

## Individual scenario scripts

```bash
./scripts/security-lab/run-process-test.sh
./scripts/security-lab/run-network-test.sh
./scripts/security-lab/run-persistence-test.sh
./scripts/security-lab/run-integrity-test.sh
./scripts/security-lab/run-exposure-test.sh
./scripts/security-lab/run-anomaly-test.sh
./scripts/security-lab/run-ransomware-test.sh
./scripts/security-lab/run-atomic-test.sh          # interactive, approval-gated
./scripts/security-lab/run-atomic-test.sh --dry-run
./scripts/security-lab/run-atomic-test.sh --live-accept   # SYNTHETIC only
```

Orchestrator equivalents:

```bash
./scripts/run-security-lab.sh --list
./scripts/run-security-lab.sh --dry-run --scenario all
./scripts/run-security-lab.sh --scenario process
# … network | persistence | integrity | exposure | anomaly | ransomware
```

Atomic via orchestrator (inspect by default; **not** part of `--scenario all`):

```bash
./scripts/run-security-lab.sh --scenario atomic
RTE_LAB_ATOMIC_APPROVE=<token> ./scripts/run-security-lab.sh --scenario atomic
```

Full guide: [`setup.md`](../../setup.md).

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
    run-*-test.sh    # thin wrappers per scenario
    run-atomic-test.sh
    cleanup-lab.sh
src/runtime_engine/lab/   # importable orchestrator + scenarios
```

Lab data lives only under:

- `<tmp>/rte-security-lab/<session>/`
- `<tmp>/rte-ransomware-lab-<session>/` (ransomware simulator only)
