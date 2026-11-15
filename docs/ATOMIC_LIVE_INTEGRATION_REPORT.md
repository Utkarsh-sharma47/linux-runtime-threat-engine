# Final Report: Live Atomic Red Team ↔ EDR Integration

**Branch:** `feat/live-atomic-edr-integration` (worktree `rte-security`)  
**Base tip before work:** `6140f95` on `feat/offline-atomic-edr-evaluation`  
**Named branch from the task:** `feat/complete-security-terminal-dashboard` @ `1a5a080` (= `main`, **0 unique commits**; left untouched with dirty footer remap + active opencode)

---

## Exact branch base and commit

| Item | Value |
|---|---|
| Implementation branch | `feat/live-atomic-edr-integration` |
| Forked from | `feat/offline-atomic-edr-evaluation` @ `6140f95` |
| Audit of named branch | `feat/complete-security-terminal-dashboard` == `main` @ `1a5a080` |
| Shared checkout | Preserved dirty; not modified by this work |

---

## Missing functionality discovered (audit)

1. Named dashboard branch had **no** security modules, Atomic package, or live bridge—only an uncommitted key remap.
2. Offline Atomic path deliberately set `live_monitor_used: False` and used a **separate** Pipeline/DB.
3. Legacy PS1 lab correlated by **time window** against an external monitor DB (forbidden).
4. No persistent Atomic execution session on `MonitorSession` / SQLite.
5. No process-key attribution of Atomic evidence into the live dashboard.
6. Network module page existed, but no dedicated investigation view with Atomic session linkage / first-last seen / confidence callouts for ambiguous & unattributed.
7. Module status labels used `no-model` / `no-baseline` rather than **UNTRAINED** / **NOT BASELINED** display names.

Full audit: `docs/ATOMIC_LIVE_INTEGRATION_AUDIT.md`.

---

## Files changed

**New**

- `src/runtime_engine/atomic/live.py` — `LiveAtomicBridge`, synthetic builders, process-key correlation
- `src/runtime_engine/terminal/views/network_investigation.py` — dedicated network investigation view
- `tests/atomic/test_live_integration.py` — synthetic end-to-end acceptance
- `docs/ATOMIC_LIVE_INTEGRATION_AUDIT.md`
- `docs/ATOMIC_LIVE_INTEGRATION_REPORT.md`

**Modified**

- `storage/database.py` — `atomic_sessions` table + save/load
- `monitor/state.py` — Atomic session mirror + snapshot field
- `terminal/interactions.py` — keys `n` (network), `a` (Atomic sessions)
- `terminal/dashboard.py` — footer/header for Atomic sessions; compact command labels
- `terminal/atomic_app.py` — `atomic live-accept` synthetic harness
- `terminal/views/security_common.py` / `security_view.py` — UNTRAINED / NOT BASELINED / DISABLED / UNAVAILABLE labels
- `terminal/views/metrics_view.py` — help entries for `n` / `a`
- Terminal tests updated for new footer commands

---

## Existing components reused (no second detection engine)

- `MonitorSession.submit_event` / pipeline processor thread
- `Pipeline` + `DetectionEngine` (RT001–RT006) + `CorrelationEngine`
- `normalize()` / Event schema / `process_key` identity
- `SecurityScheduler` + six modules (when enabled on the monitor)
- Offline `grade_component` / `overall` for evaluation reports
- NetworkMonitor snapshot path (still the live network source when modules are on)

**Not done:** fabricating detections from ATT&CK IDs; time-window-only association.

---

## Actual live data flow

```
Fake/approved Atomic profile
  → LiveAtomicBridge.register()  (SQLite atomic_sessions + DashboardState)
  → verify collectors (ProcCollector / pipeline / security scheduler status)
  → synthetic or traced events normalized to Event schema
  → metadata: atomic_run_id, synthetic/SYNTHETIC label
  → MonitorSession.submit_event()
  → existing Pipeline (rules → correlation → SQLite events/alerts/incidents)
  → SecurityScheduler continues independently (modules → findings → promote)
  → Bridge.correlate() by process_key ∪ event_id only
  → Dashboard [a]/[n]/[s] + header ATOMIC SESSIONS line
  → Bridge.evaluate() → persisted evaluation on atomic_sessions
```

Acceptance demonstration: `python -m runtime_engine.main atomic live-accept --json`

---

## Network investigation

- Key **`n`**: PID, process name, executable, proto, local/remote, state, first/last seen, attribution confidence, related detections/incidents, Atomic session.
- Ambiguous / unattributed rows highlighted; snapshot-only rows marked.
- Banner: **not system-wide continuous capture** ( `/proc/net` snapshots + injected NETWORK_CONNECTION events).

---

## Six module investigation status

| Module | Inspectable | State display |
|---|---|---|
| Persistence | `s` → persistence | DISABLED when config off |
| Network | `s` → network **and** `n` | snapshot limits disclosed |
| Anomaly | `s` → anomaly | **UNTRAINED** (`no-model`) |
| Integrity | `s` → integrity | **NOT BASELINED** (`no-baseline`) |
| Exposure | `s` → exposure | DISABLED / UNAVAILABLE as applicable |
| Ransomware | `s` → ransomware | DISABLED when watch dirs unset |

Drill-down pages show evidence, timestamps, severity, process attribution, related incidents. Overview alone is not the only path.

---

## Test / quality results

| Gate | Result |
|---|---|
| Full suite | **285 passed** |
| Ruff | All checks passed |
| Mypy | Success: **0 issues** in 81 files (base was 0; **no new errors**) |
| PTY / terminal interactions + session | **27 passed** |
| Live acceptance (`atomic live-accept`) | Exit 0, grade **DETECTED**, label **SYNTHETIC**, 1 incident |
| Real Atomic attacks in tests | **None** |

The two prior footer assertion failures were due to truncated command labels after adding `n`/`a`; assertions updated to match the intentional shorter footer (`[q] Quit`, `[n] Network`, `[a] Atomic`).

---

## Known telemetry limitations

- Live `/proc` polling misses short-lived processes between polls.
- NetworkMonitor is **snapshot** based; connections between scans are invisible.
- Without `--security-modules`, module findings stay empty (rules path still works).
- Offline strace path remains available and does **not** auto-attach to a separate monitor process; live bridge is in-process via `LiveAtomicBridge`.
- True Invoke-AtomicTest under a live bridge still requires explicit human approval (not exercised here).

---

## Remaining incomplete requirements

1. Interactive in-dashboard “run approved Atomic now” wizard (CLI/API + synthetic accept exist; full TUI runner for real tests not added).
2. Auto-feed of strace JSONL into a **already-running** external monitor process (cross-process IPC) — current design is in-process `submit_event`.
3. `feat/complete-security-terminal-dashboard` still points at empty `main`; recommend resetting that branch tip to this work after opencode finishes, or renaming this branch.
4. Enabling all six modules inside `live-accept` by default (currently reports scheduler disabled unless the host monitor starts with modules).

**Completion claim:** the acceptance path demonstrates full end-to-end integration with **synthetic** evidence through the live monitor pipeline, correlation, dashboard, persistence, and evaluation report. Real Atomic host execution remains opt-in and approved separately.
