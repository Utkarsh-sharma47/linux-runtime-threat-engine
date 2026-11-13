# Atomic Red Team lab for the Linux Runtime Threat Detection Engine

A controlled adversary-emulation workflow that runs **one reviewed Atomic test at a
time** while the engine monitors, then compares what the engine actually stored with
the test's execution window. It lives outside the engine: nothing here changes how the
engine collects, detects or correlates, and the integration reads the engine database
read-only.

**Nothing in this lab runs a test by itself.** Installation, catalog building, preflight
and `-DryRun` execute no Atomic test. A real run requires typing an approval for the
exact test, and cleanup requires a second approval.

## 1. What Atomic Red Team is

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (Red Canary) is a
library of small, scripted tests ("atomics"), each mapped to a
[MITRE ATT&CK](https://attack.mitre.org/) technique. Each technique folder
(`atomics/T1059.004/T1059.004.yaml`) lists tests with: `name`, `auto_generated_guid`,
`description`, `supported_platforms`, `input_arguments` (with defaults), optional
`dependencies` (a `prereq_command` that checks and a `get_prereq_command` that installs or
downloads), and an `executor` (`sh`, `bash`, `powershell`, `manual`) with `command`,
`cleanup_command` and `elevation_required`. Linux tests are those whose
`supported_platforms` contains `linux`. The PowerShell module
[Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) executes them:
on Linux it runs `sh -c "<command>"` (or `bash -c`) as a child of `pwsh` and logs start
time, PID and exit code to a CSV.

## 2. Why this project uses it

Hand-written synthetic JSONL proves the rules work on idealized telemetry. Atomics produce
real process activity on a real host, so they test the whole live path: `/proc` polling,
identity and ancestry, rule matching, correlation, storage and reporting, including what
the engine cannot see.

## 3. Requirements

Linux x86_64 (verified: Ubuntu 24.04.5), a normal user account, git, ~100 MB disk, network
access for installation only, and this repository's `.venv` (`pip install -e '.[dev]'`).
Run tests only on a machine you are authorized to test, ideally a disposable VM.

## 4. Installation on Ubuntu

See [install.md](install.md) for the exact verified commands (PowerShell 7.6.6 LTS in
`~/.local`, Invoke-AtomicRedTeam 2.3.0 and powershell-yaml 0.4.12 with
`-Scope CurrentUser`, YAML-only atomics in `~/AtomicRedTeam/atomics`). Then run:

```bash
testing/atomic-red-team/scripts/preflight.sh
```

## 5. Inspect available tests (no execution)

```bash
# Linux tests from the official YAML, with this lab's risk class (A/B/C)
.venv/bin/python testing/atomic-red-team/scripts/catalog.py list
.venv/bin/python testing/atomic-red-team/scripts/catalog.py list --risk A
.venv/bin/python testing/atomic-red-team/scripts/catalog.py list --technique T1059.004

# The module's own listing for this platform (display only)
pwsh -NoProfile -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest T1059.004 -ShowDetailsBrief'
pwsh -NoProfile -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest All -ShowDetailsBrief'
```

`Invoke-AtomicTest All -ShowDetailsBrief` lists 509 tests here: the 435 host Linux tests
minus 6 `manual`-executor ones, plus 80 container and cloud tests (`containers`,
`azure-ad`, `iaas:*`, `office-365`) that this host-level engine cannot observe.

## 6. Identify Linux-compatible tests

[test-catalog.md](test-catalog.md) is generated from the YAML (`catalog.py build`) and
lists all 435 Linux tests (122 techniques) at the recorded atomics commit, with
technique, privileges, prerequisites, cleanup, expected behaviour, programs started,
what the engine can observe, which rules could match, suitability here and the triage
reasons. Classification (automated, conservative, from the actual commands):

| Class | Meaning | Count | Runner behaviour |
|---|---|---:|---|
| A | No writes, network, elevation, prerequisites, cleanup, sensitive reads or env dumps found | 22 | runs after typed approval |
| B | Temp files, sensitive paths, elevation, prerequisites, cleanup, background processes, obfuscation | 103 | needs `-AllowReviewRequired` after review |
| C | Persistence, credential access, privilege escalation, impact, exfiltration, network transfer, package installs, destructive commands | 310 | always refused |

The name of a test is not evidence of safety: for example T1082 #12 "Environment
variables discovery" runs `env` (prints secrets in the environment) and T1083 #4 walks
your whole home directory; both are class B. 3 of the 22 class-A tests use FreeBSD tools
(`kldstat`, `sockstat`) that are not installed here, so 19 are runnable on this host.

## 7. Inspect prerequisites

```bash
.venv/bin/python testing/atomic-red-team/scripts/catalog.py show --guid <GUID>
```

prints each dependency's description, its check command and its get command. Checking
prerequisites with `Invoke-AtomicTest <T#> -TestGuids <GUID> -CheckPrereqs` **executes**
the check commands, and `-GetPrereqs` executes download/install commands: never run
either before reading them. `run_atomic_test.ps1` refuses tests with prerequisites.

## 8. Inspect the exact test commands

```bash
pwsh -NoProfile -Command 'Import-Module invoke-atomicredteam;
  Invoke-AtomicTest T1059.004 -TestGuids b04ed73c-7d43-4dc8-b563-a2fc595cba1a -ShowDetails'
```

`-ShowDetails` prints description, executor, elevation, the command with input
arguments substituted, dependencies and the cleanup command. It executes nothing.

## 9. Execute one approved test

Terminal 1, start the engine (dashboard; `q` stops it):

```bash
.venv/bin/python -m runtime_engine.main --db testing/atomic-red-team/test-results/engine.db monitor
```

Terminal 2, from the repository root, as a normal user:

```bash
testing/atomic-red-team/scripts/preflight.sh --db testing/atomic-red-team/test-results/engine.db
pwsh -NoProfile -File testing/atomic-red-team/scripts/run_atomic_test.ps1 \
  -TestGuid b04ed73c-7d43-4dc8-b563-a2fc595cba1a \
  -EngineDb testing/atomic-red-team/test-results/engine.db
```

The runner (verified paths: refusals, dry run, approval gate) does, in order:

1. resolves the GUID in the catalog and in the official YAML (both must agree, Linux only);
2. prints `-ShowDetails` and the risk class, privileges, prerequisites and engine view;
3. refuses class C; refuses class B unless `-AllowReviewRequired`;
4. refuses `elevation_required` tests and tests with prerequisites; refuses to run as root;
5. refuses unless a live monitor session is writing to `-EngineDb` (verified by session
   row, engine PID and its command line);
6. snapshots persistence locations and temp directories, then asks you to type the first
   8 characters of the GUID (non-interactive stdin is refused);
7. records start time, runs **only** `Invoke-AtomicTest <T#> -TestGuids <GUID>`, records
   end time and the executor PID and exit code from the module's CSV log;
8. waits one poll interval, then cleanup (step 10);
9. writes `record.json` and the report.

Add `-DryRun` to exercise every step except the test and its cleanup.

## 10. Cleanup

When a test defines `cleanup_command`, the runner prints it and runs
`Invoke-AtomicTest <T#> -TestGuids <GUID> -Cleanup` only after you type `cleanup`. It then
always runs `scripts/verify_cleanup.sh verify`, which fails if the crontab, shell startup
files, `~/.ssh/authorized_keys`, user systemd units or autostart entries changed, or if a
path listed under `cleanup_paths` in [expectations.yaml](expectations.yaml) still exists,
and warns about new files you own in `/tmp`, `/var/tmp` and `/dev/shm`. Manual cleanup for
the recommended class-B candidate:

```bash
pwsh -NoProfile -Command 'Import-Module invoke-atomicredteam;
  Invoke-AtomicTest T1036.003 -TestGuids a315bfff-7a98-403b-b442-2ea1b255e556 -Cleanup'
```

(its cleanup command is `rm /tmp/crond`).

## 11. Running the engine at the same time

Use the dashboard (above) to watch live, or line output for logs:
`... monitor --no-dashboard --verbosity verbose`. Keep the default 2 s poll interval or
lower it with a config file (`poll_interval_seconds: 0.5`, `--config FILE`) to catch
shorter processes. Start the engine before the runner and stop it only after the report.

## 12. Inspect generated incidents

```bash
DB=testing/atomic-red-team/test-results/engine.db
.venv/bin/python -m runtime_engine.main --db $DB incidents
.venv/bin/python -m runtime_engine.main --db $DB incident --id INC-0001
.venv/bin/python -m runtime_engine.main --db $DB process --pid <PID from the report>
.venv/bin/python -m runtime_engine.main --db $DB events --filter "since=10m kind=match"
.venv/bin/python -m runtime_engine.main --db $DB sessions
```

In the dashboard: `i` (incident), `p` (process and ancestry), `e` (events).

## 13. The test report and exporting it

Each run writes `test-results/<UTC time>-<technique>-<guid8>/` (mode 0700, git-ignored):
`record.json` (test identity, command, window, runner identity, execution and cleanup
status, engine session), `execution-log.csv`, `test-output.txt`, cleanup verification,
`report.txt` and `report.json` (mode 0600). Regenerate a report from a record:

```bash
.venv/bin/python testing/atomic-red-team/scripts/atomic_report.py report \
  --record testing/atomic-red-team/test-results/<run>/record.json \
  --db testing/atomic-red-team/test-results/engine.db
```

Export the engine's incident evidence with
`... --db $DB export --id INC-0001 --format json --output incident.json`. Copy a reviewed
report into `testing/reports/` to keep it; that folder is git-ignored too because reports
contain host details.

### How the report decides

Events are **attributed** to the test only if their recorded parent chain reaches the
runner's `pwsh` process identity (boot ID + PID + start ticks), or, labelled weaker,
their PID/PPID is the executor PID from the module log. Other events in the window are
counted as unrelated and never used as evidence. The window opens at the test start
(discovery is never earlier than a process start) and closes one poll interval plus
1.5 s after the end. Grading uses the reviewed profile in `expectations.yaml`:

| Result | When |
|---|---|
| DETECTED | all expected rules matched attributed events |
| PARTIALLY DETECTED | some rule matched, but expected rules are missing (or the profile expects none) |
| NOT DETECTED | execution succeeded, the key processes were observed, no expected detection |
| INCONCLUSIVE | execution failed or did not happen, engine not active for the window, no profile, required telemetry not collected live, nothing attributable observed, or key processes missed |

A completed test is never counted as a detection by itself, and a test is never NOT
DETECTED when the engine did not collect the relevant event type.

### What the engine can observe (from the code)

| Behavior | Required telemetry | Current support | Expected result |
|---|---|---|---|
| Process execution | `/proc` collector (`ProcCollector`) | Live, polling every 2 s; emits `PROCESS_START` for newly visible identities only | Detectable if the process lives across a poll; RT001, RT002, RT005 can match |
| Process ancestry | PPID + parent start ticks | Live when the parent is visible in the same snapshot | Detectable; used for attribution and correlation |
| Command line | `/proc/PID/cmdline` | Live only with `--include-cmdline`; no rule uses it | Stored, not detected |
| Executable path / UID | `/proc/PID/exe`, `status` | Live; other users' `exe` often unreadable | RT002 needs a readable path |
| Process exit | exit events | Not emitted (disappearance is not exit evidence) | Not detectable |
| File access | audit / eBPF / fanotify | Not collected live; `FILE_ACCESS` replay only | RT003 replay only |
| Network connection | eBPF / audit / conntrack | Not collected live; `NETWORK_CONNECTION` replay only | RT006 replay only |
| Privilege change | audit / eBPF | Not collected live; `PRIVILEGE_CHANGE` replay only | RT004 replay only |

### First demonstration candidates (inspected, not executed)

| Test | Class | Commands | Cleanup | Engine can observe | Expected grade |
|---|---|---|---|---|---|
| T1059.004 #8 Command line scripts `b04ed73c-7d43-4dc8-b563-a2fc595cba1a` | A | `for i in $(seq 1 5); do echo "$i, Atomic Red Team was here!"; sleep 1; done` | none | executor `sh` (child of `pwsh`) lives ~5 s; `sleep` children | NOT DETECTED (no rule covers a shell loop: coverage gap) |
| T1033 #2 System Owner/User Discovery `2a9b677d-a230-44f4-ad86-782df1ef108c` | A | `users`, `w`, `who` | none | each exits in milliseconds; usually missed by 2 s polling | INCONCLUSIVE (telemetry gap) |
| T1036.003 #2 Masquerading as crond `a315bfff-7a98-403b-b442-2ea1b255e556` | B | `cp /bin/sh /tmp/crond; echo 'sleep 5' \| /tmp/crond` | `rm /tmp/crond` | process `crond` with exe `/tmp/crond` for ~5 s (dash stays alive as parent of `sleep`); the file write itself is not collected | DETECTED if RT002 matches |

Recommended first run: **T1059.004 #8**. It writes no files, needs no privileges,
prerequisites or cleanup, and validates telemetry and attribution end to end. Then
T1036.003 #2 (with `-AllowReviewRequired`) is the first test that the current rules can
actually detect.

**Verified run (2026-11-13, T1059.004 #8, operator-approved).** The test completed with
exit code 0. The engine (2 s polling) stored the executor `sh` (its PID matched the
module's execution log) and 2 of the 5 one-second `sleep` children, all attributed through
the runner identity chain; 4 concurrent unrelated events were excluded. No rule matched,
so the report graded it **NOT DETECTED (rule coverage gap)**, as predicted. Cleanup was
not required and verification passed. T1033 #2 and T1036.003 #2 have not been executed.

## 14. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `pwsh: command not found` | `~/.local/bin` not on `PATH`; log in again or `export PATH="$HOME/.local/bin:$PATH"` |
| `Install-Module` asks to trust PSGallery | expected; the documented command uses `-Force` for the prompt only |
| `The variable '$artConfig' cannot be retrieved` | `Set-StrictMode` is active in your session; the module's config does not support it |
| `PathToAtomicsFolder` errors | atomics not at `~/AtomicRedTeam/atomics`; pass `-AtomicsPath` / `-PathToAtomicsFolder` |
| `REFUSED: the engine is not monitoring` | start `monitor` with the same `--db`; a `kill -9`'d session stays `RUNNING` in the DB but is detected as dead by PID and command line |
| `REFUSED: stdin is not interactive` | approvals cannot be scripted; run the runner in a terminal |
| Run hangs after `PathToAtomicsFolder =` when driven through a pseudo-terminal | `Invoke-AtomicTest` progress bars stall on terminals without a size; the runner sets `$ProgressPreference = 'SilentlyContinue'`, do the same in your own sessions |
| Report `INCONCLUSIVE`, no attributed process | the processes exited between polls; use a longer-lived test or a shorter `poll_interval_seconds` |
| `database is locked` | the engine was committing; reports retry for 10 s, rerun the `report` command |
| Leftover `/tmp` files after cleanup | read `cleanup-verification.txt`; remove only files you can attribute to the test |

## 15. Security precautions

- Authorized hosts only; prefer a disposable VM or snapshot. Never run as root; the
  runner refuses elevated tests and root.
- Never use `IEX (IWR ...)`; install from the gallery and git as documented.
- Never run `-GetPrereqs`, class B or class C tests without reading every command.
  Network, persistence, credential and destructive tests are refused by design.
- `test-results/`, `testing/reports/` and `*.db` are git-ignored: execution logs contain
  hostname, IP address and username; engine databases contain process telemetry.
- The atomics folder is YAML-only; add payloads selectively and review them first.
- The engine is read-only and the integration opens its database read-only, so test
  results cannot alter detections.

## Cheat sheet

```bash
testing/atomic-red-team/scripts/preflight.sh                                  # readiness
.venv/bin/python testing/atomic-red-team/scripts/catalog.py list --risk A     # candidates
.venv/bin/python testing/atomic-red-team/scripts/catalog.py show --guid GUID  # triage
pwsh -NoProfile -Command 'Import-Module invoke-atomicredteam; Invoke-AtomicTest T1059.004 -TestGuids GUID -ShowDetails'
.venv/bin/python -m runtime_engine.main --db testing/atomic-red-team/test-results/engine.db monitor   # terminal 1
pwsh -NoProfile -File testing/atomic-red-team/scripts/run_atomic_test.ps1 -TestGuid GUID \
  -EngineDb testing/atomic-red-team/test-results/engine.db [-DryRun] [-AllowReviewRequired]          # terminal 2
.venv/bin/python -m runtime_engine.main --db testing/atomic-red-team/test-results/engine.db incidents
cat testing/atomic-red-team/test-results/<run>/report.txt
```

Files: `scripts/catalog.py` (catalog and triage), `scripts/run_atomic_test.ps1` (guarded
runner), `scripts/atomic_report.py` (read-only correlation and report),
`scripts/preflight.sh`, `scripts/verify_cleanup.sh`, `expectations.yaml` (reviewed grading
profiles), `test-catalog.md` (generated), `test-results/` (local, git-ignored).
