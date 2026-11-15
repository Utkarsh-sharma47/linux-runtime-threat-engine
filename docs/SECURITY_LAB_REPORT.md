# Security Demonstration Lab — Deliverable Report

**Branch:** `feat/live-atomic-edr-integration` (worktree `rte-security`)  
**Shared checkout:** untouched

## Scripts created

| Path | Role |
|---|---|
| `scripts/start-monitor.sh` | User-facing wrapper |
| `scripts/run-security-lab.sh` | User-facing wrapper |
| `scripts/cleanup-lab.sh` | User-facing wrapper |
| `scripts/security-lab/start-monitor.sh` | Prepare session + start live monitor |
| `scripts/security-lab/run-security-lab.sh` | Orchestrate scenarios |
| `scripts/security-lab/cleanup-lab.sh` | Safe cleanup with confirmation |
| `scripts/security-lab/README.md` | Quick-start workflow |
| `src/runtime_engine/lab/` | Importable lab package |

## Exact commands

```bash
cd /home/utkarsh/Documents/Class/xISSC-Project/rte-security
./scripts/start-monitor.sh
# other terminal:
./scripts/run-security-lab.sh --scenario all
./scripts/cleanup-lab.sh
```

Individual: `--scenario process|network|persistence|integrity|exposure|anomaly|ransomware|atomic`  
Also: `--list`, `--dry-run`

## Scenario provenance

| Scenario | Provenance | Expected signals (honest; not forced) |
|---|---|---|
| process | REAL + SYNTHETIC fixture path | RT002 via ProcCollector |
| network | REAL | RT005; NetworkMonitor if snapshot catches sockets |
| persistence | SYNTHETIC lab fixtures | PM* after PersistenceMonitor scan |
| integrity | SYNTHETIC | FI* after IntegrityMonitor re-scan |
| exposure | SYNTHETIC | EX* for unexpected lab SUID |
| anomaly | SYNTHETIC | UNTRAINED unless a model exists |
| ransomware | SYNTHETIC (`rte-ransomware-lab*`) | RW001 via RansomwareMonitor |
| atomic | ATOMIC (opt-in approve) | Offline evaluation; **not** in `--scenario all` |

## Dashboard pages

Process `p`/`t`, network `n`, security `s`, incidents `i`, alerts `r`, events `e`, Atomic `a`, plus **SECURITY LAB** header panel.

## Known limitations

- Network visibility is snapshot-based; short connections may be missed.
- Module findings appear after configured intervals (lab config uses short intervals).
- Anomaly stays UNTRAINED until a real model is trained — scores are never invented.
- Cross-process Atomic live bridge still requires `LiveAtomicBridge` / `live-accept` for synthetic in-process demos; `atomic` scenario defaults to inspect/offline.
- Real Atomic execution needs `RTE_LAB_ATOMIC_APPROVE=<token>`.
