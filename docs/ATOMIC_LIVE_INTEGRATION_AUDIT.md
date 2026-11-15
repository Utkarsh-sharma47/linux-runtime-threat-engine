# Audit: Live Atomic Red Team ↔ EDR Integration

**Date:** 2026-11-15  
**Status:** Pre-implementation audit (no code changes yet at report time)  
**Working tree used for inspection:** a dedicated git worktree for the live Atomic branch (local path omitted)

---

## 1. Repository preservation snapshot

| Location | Branch | HEAD | Working tree |
|---|---|---|---|
| `linux-runtime-threat-engine` (shared) | `feat/complete-security-terminal-dashboard` | `1a5a080` | Dirty: `M src/runtime_engine/terminal/dashboard.py` only; `opencode` still active |
| `rte-security` (worktree) | `feat/offline-atomic-edr-evaluation` | `6140f95` | Clean |

**Preservation rules applied:** shared checkout left untouched (dirty footer remap + opencode). No reset/rebase/force-switch/merge/push.

### 1.1 `feat/complete-security-terminal-dashboard` is not what the task description assumes

| Claim | Reality |
|---|---|
| Branch added terminal navigation, security overview, Atomic CLI | **False.** Branch has **0 commits ahead of `main`**. `HEAD == main == 1a5a080`. |
| Security modules / Atomic packages present on that branch | **Absent.** Shared tree has no `src/runtime_engine/security/` or `src/runtime_engine/atomic/`. |
| Uncommitted work | Footer `COMMANDS` remapped to keys `1`–`9` (Live Monitoring … Historical Sessions) plus `SEVERITY_COLORS`. **No wiring** to those pages. |
| “Ready for further enhancement with live monitor integration” | Matches the **offline** Atomic design (`live_monitor_used: False`), not a completed live bridge. |

Base commit of the named branch: **`1a5a080`** (`Add process lifecycle management and tree visualization`) — identical to `main`.

### 1.2 Related branch history

| Branch | Tip | Relation |
|---|---|---|
| `integration/security-modules` | `886557d` | Six modules + Security Investigation (`s`) + scheduler → pipeline. **24 commits** not in `complete-security`. |
| `feat/offline-atomic-edr-evaluation` | `6140f95` | Ancestor: `integration/security-modules`. Offline Atomic catalog/strace/run/analyze/report. **36 commits** not in `complete-security`. |
| `feat/atomic-red-team-testing` | `d14cdf7` | Legacy **external** lab: PowerShell runner requires a **separate** live monitor writing to `-EngineDb`, then correlates by **time window** (forbidden by this task’s attribution rules). |

Merge-base(`complete-security`, `offline-atomic`) = `1a5a080`.

### 1.3 What is actually present (on `feat/offline-atomic-edr-evaluation`)

**Six security modules (live monitor path):**

| Module | Implementation | Scheduler hook | Terminal investigation |
|---|---|---|---|
| Persistence | `security/persistence.py` | `modules.build_modules` | `views/persistence_view.py` via `s` |
| Network | `security/network.py` | same; `emit_events=True` → `NETWORK_CONNECTION` | `views/network_view.py` + `security network` CLI |
| Anomaly | `security/anomaly.py` | same | `views/anomaly_view.py` |
| Integrity | `security/integrity.py` | same | `views/integrity_view.py` |
| Exposure | `security/exposure.py` | same | `views/exposure_view.py` |
| Ransomware | `security/ransomware.py` | same | `views/ransomware_view.py` |

Live wiring: `terminal/app.py` → `build_modules` → `MonitorSession(security_modules=…)` → `SecurityScheduler` → `submit_finding` / `submit_event` → `Pipeline` → SQLite (`security_findings`, events, incidents).

**Offline Atomic (deliberately not live):**

| Stage | Files | Live monitor? |
|---|---|---|
| Profile / preflight / approval | `atomic/profiles.py`, `preflight.py`, `catalog.py` | No |
| Execution + strace /proc evidence | `atomic/runner.py`, `trace.py`, `evidence.py` | Explicitly `live_monitor_used: False` |
| Normalize + pipeline + grade | `atomic/analysis.py` + `ReplayCollector` into **run-local** DB | Separate offline Pipeline instance |
| CLI / views | `terminal/atomic_app.py`, `views/atomic_view.py` | Help text: “no live monitor needed” |

Quality at tip `6140f95`: **282 passed**, **ruff clean**, **mypy Success (79 files)**.

---

## 2. End-to-end path verification (as implemented today)

```
Atomic profile selection     ✅  profiles.py + expectations.yaml + inspect
-> explicit approval         ✅  --approve token / RunRefused
-> Atomic execution          ✅  runner.execute (offline only)
-> telemetry collection      ✅  strace or /proc poll → events.jsonl
-> event normalization       ✅  analysis → ReplayCollector → normalize()
-> shared EDR pipeline       ⚠️  Offline creates a NEW Pipeline+DB under the run dir.
                               Does NOT submit into an active MonitorSession.
-> detection rules           ✅  Offline Pipeline.detection
-> six security modules      ⚠️  Offline re-invokes module analyzers on captured
                               evidence; does not use the live SecurityScheduler.
-> incident correlation      ✅  Offline CorrelationEngine only
-> SQLite persistence        ⚠️  Run-local DB, not the live monitor session DB
-> live terminal dashboard   ❌  No Atomic execution session on DashboardState;
                               no live feed; `s` shows modules but not Atomic runs
```

**Do not infer from CLI:** `atomic run` / `atomic analyze` / `atomic report` exist and work offline. They do **not** prove live monitor observation.

### Legacy live lab (time-window correlation) — present but inadequate

`testing/atomic-red-team/scripts/run_atomic_test.ps1` + `atomic_report.py`:

1. Require external `monitor` writing to `-EngineDb`.
2. Run Invoke-AtomicTest.
3. Sleep one poll interval.
4. Query DB for events/alerts/incidents in `[start, end]`.

This **associates by time window**, which this task forbids. Process-stable attribution to an Atomic execution session is missing.

---

## 3. Missing functionality (implementation backlog)

1. **Persistent Atomic execution session** registered against a live `MonitorSession` / session DB (run_id, process_keys, event_ids, status, synthetic flag).
2. **Live event submission:** normalize Atomic/synthetic observations and `MonitorSession.submit_event` into the **same** pipeline the dashboard observes.
3. **Collector verification:** start/confirm ProcCollector + security modules (network emit, etc.) before/during the run.
4. **Process-key correlation** of detections/incidents/findings to the Atomic session (not wall-clock alone); preserve attribution confidence.
5. **Dashboard updates:** show active Atomic session(s); surface correlated process/connection/detection/incident.
6. **Dedicated network investigation view** (beyond module page): PID/exe, endpoints, ports/protocol/state, first/last seen, attribution confidence, related detections/incidents, Atomic session; ambiguous/unattributed called out; snapshot limits disclosed.
7. **Six-module inspectability audit** for UNTRAINED / NOT BASELINED / DISABLED / UNAVAILABLE accuracy under live + Atomic context.
8. **Acceptance harness** with fake profile + clearly labeled **synthetic** telemetry (no real Atomic attack).
9. **`feat/complete-security-terminal-dashboard` content gap:** either rebuild that branch from `offline-atomic` + live work, or document that the named branch was a mis-pointed empty tip.

**Out of scope / must not do:** second detection engine; detections fabricated from ATT&CK IDs; real Atomic execution inside unit/acceptance tests; merge/push without approval.

---

## 4. Network collector vs live monitoring

| Component | Role | Connected to live monitor? |
|---|---|---|
| `collector/net_collector.py` (`NetCollector`) | Low-level `/proc/net` + inode→PID | Used by NetworkMonitor; not a top-level MonitorSession collector by itself |
| `security/network.py` (`NetworkMonitor`) | Scheduled module; newly seen sockets → `NETWORK_CONNECTION` when `emit_events=True` | **Yes**, when `--security-modules` / `security_modules=True` |
| ProcCollector | Process start/exit polling | **Yes**, primary live collector |

**Limitation (must display):** network visibility is **snapshot polling**, not system-wide continuous capture. Short-lived connections between scans are missed; connect times are first-observed. Strace offline path can see `connect()` for the traced tree only.

Gaps in current network UI for this task:

- No Atomic execution session column/association.
- No first/last observed pair on the live investigation table (snapshot “taken_at” only).
- No dedicated dashboard key for network investigation (only via Security → network).
- Related detections/incidents partially present via `incidents` map; Atomic session absent.

---

## 5. Six modules — investigation status (pre-fix)

| # | Module | Stored findings inspectable? | State accuracy |
|---|---|---|---|
| 1 | Persistence | Yes (`s` → persistence) | enabled/disabled via config |
| 2 | Network | Yes (`s` → network / CLI) | snapshot caveats in view |
| 3 | Anomaly | Yes | UNTRAINED when no model — verify wording |
| 4 | Integrity | Yes | NOT BASELINED / baseline-created |
| 5 | Exposure | Yes | |
| 6 | Ransomware | Yes | DISABLED when dirs unset |

Overview page (`security_view`) is not sufficient alone — drill-down pages exist; Atomic correlation on findings is still missing.

---

## 6. Test / quality notes

- Full suite on `6140f95`: 282 passed; ruff OK; mypy clean (0 errors).
- Shared-branch uncommitted footer change is **not** covered by tests on that tip (security/atomic tests do not exist there).
- Expected “2 failures” mentioned by opencode for intentional log-panel message changes refer to **incomplete opencode work on the empty branch**, not to `offline-atomic`.
- Baseline for “no new mypy errors”: compare against `6140f95` (0) or `integration/security-modules` — not against empty `complete-security`.

---

## 7. Implementation plan (post-audit)

Worktree: **`rte-security` only**. New branch from `feat/offline-atomic-edr-evaluation`:

`feat/live-atomic-edr-integration`

Commits (atomic, independent):

1. Atomic execution session registry + live feed into `MonitorSession` / Pipeline.
2. Network investigation page + Atomic/process attribution fields + limitation banners.
3. Live Atomic CLI/API + synthetic acceptance test (fake profile, no real Atomic).
4. Docs + final report; fix any quality-gate regressions.

Reuse: `MonitorSession.submit_event`, `Pipeline`, `SecurityScheduler`, `ReplayCollector`/`normalize`, `atomic/analysis.grade_component`, existing module views, process_key identity.

---

## 8. Verdict

**Live Atomic Red Team integration is not implemented** on `feat/complete-security-terminal-dashboard` (empty tip) nor as a bridge on `feat/offline-atomic-edr-evaluation` (offline-by-design). Security modules and offline Atomic evaluation are complete and green in the worktree. The critical missing piece is an in-process (or otherwise process-attributed) live session that feeds the **existing** monitor pipeline and dashboard without time-window-only correlation.
