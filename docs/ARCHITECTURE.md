# Architecture

## Data flow and boundaries

Collectors return validated `Event` objects. Replay validates every nonblank JSONL
record through the shared normalizer. The `/proc` collector builds the same model
from observations, never from executed commands. Every timestamp is timezone-aware
UTC. Unknown fields and invalid records are rejected, not silently discarded.

`Pipeline.process` checks persistent event IDs, updates ancestry, evaluates declarative
rules, correlates detections and saves the event plus affected alerts/incidents in one
SQLite transaction. Storage failures abort a run; processing must not continue with
partly updated in-memory state after a storage error. The CLI closes the database and
returns nonzero. A new process is required to retry safely.

The event model distinguishes absent evidence (`None`) from known values. Process
identity is a JSON tuple `[host_id, pid, process_start_time]`. For `/proc`, `host_id`
is the boot UUID and the start token is field 22 of `/proc/PID/stat`, in boot ticks.
It is not presented as a wall-clock timestamp. Replay adapters must supply a stable,
source-consistent start token and host/boot namespace to get cross-event correlation.

## Ancestry

Edges require both PPID and explicit `parent_start_time`. A matching PID alone is
never enough. `/proc` fills those fields from one snapshot only if parent start ticks
are no later than child ticks. A second stat read rejects PID reuse during collection.
This reduces but cannot remove multi-file races, reparenting races or same-tick reuse.
Missing parent nodes are shown explicitly. Traversal uses a visited set, so malformed
cycles terminate. PROCESS_EXIT replay marks a known identity as terminated; history
remains available. Poll invisibility does not fabricate an exit event.

## Rules

YAML is loaded with `safe_load`. Rule fields/operators are allow-listed Pydantic
models; all conditions must match. Operators are equality, membership, non-membership
and path-root boundary checks. Missing fields fail every operator, including `not_in`.
There is no regex execution, Python eval, plugin code loading or arbitrary expression
language. Rule definitions and reasons remain attached to persisted detections.

## Correlation and deduplication

- An event can join an incident if its process identity equals an existing matched
  identity, or is an explicit ancestor/descendant in the known graph.
- The total span from the earliest to latest matched event must fit the configured
  window (120 seconds by default), including out-of-order timestamps.
- Time proximity, a shared file or common init/systemd parent is insufficient by itself.
- Repeated `(rule_id, process_identity, resource)` matches within that incident update
  one alert. Its first/last times and all distinct event IDs are kept. Changed resources
  remain distinct alerts. Missing process identity disables cross-event deduplication.
- Multiple rules on one event can create several alerts but only one event relationship.
- Event IDs already stored are skipped only when the normalized content is identical;
  conflicting reuse is rejected without replacing the original evidence.
- If late evidence links two existing incidents, it joins the earliest-created compatible
  incident. Reports are not retroactively merged. Sorting replay first improves results.
- Correlation state is session-local. New invocations retain evidence/IDs in SQLite, but
  do not resume ancestry or correlation from old sessions. Exact-event dedup still works.

A shell-child transfer tool is a LOW indicator in isolation. Additional rule matches
raise incident severity to the maximum severity among its detections. No numeric
threat probability, attribution or success-of-attack claim is calculated.

## Persistence and reporting

Tables: `events`, `alerts`, `incidents`, `incident_events`, `metric_sessions`.
Foreign keys protect incident evidence relationships. Values are bound parameters.
Events include a process-key index for retrieving observed ancestor context. Reports
contain matched supporting events, separate context events, related process metadata,
reasons, rules, first/last observation, status and event timeline. Terminal strings are
escaped to avoid executing untrusted ANSI controls. JSON reports preserve normalized
telemetry; they do not contain a copy of the invalid input lines.

New database files are created with mode 0600. Existing file modes are not changed.
There is no daemon, remote server or network traffic. SQLite/report output is the
engine's own local state, not modification of monitored processes or system policy.

## Metrics

Metrics are per completed CLI session and persisted as separate snapshots. Rule-match
counts include repeated matches before suppression; alert rows count deduplicated
alerts. Average/max pipeline latency includes SQLite work but not collector parsing,
polling sleep or duplicate/rejected early-return handling. Pipeline throughput divides
processed events by measured pipeline time. The benchmark separately records full
replay wall time, including JSONL parsing. These are different denominators on purpose.
