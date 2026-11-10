# Event schema

All events have `event_id` (nonempty string, generated UUID if absent), `timestamp`
(timezone required, normalized to UTC), `event_type`, `source`, `host_id` (default
`replay`) and a `metadata` object. Unknown top-level fields are rejected.

Optional fields: PID (positive integer), PPID (nonnegative integer), process name,
absolute executable path when known, command-line argument list, nonnegative real UID,
process start token, parent start token, parent process name, file path, network
destination, previous UID. Missing fields stay null. Command lines are arrays, never
shell programs to execute. `metadata` is evidence, not instructions to the engine.

Supported event types: PROCESS_START, PROCESS_EXIT, FILE_ACCESS, PRIVILEGE_CHANGE,
NETWORK_CONNECTION. Names are uppercase and case-sensitive. Inputs from other
sources must adapt their event names before normalization; we do not guess aliases.

```json
{"event_id":"example-1","timestamp":"2026-01-01T00:00:02Z","event_type":"PROCESS_START","pid":110,"ppid":100,"process_name":"bash","process_start_time":"1100","parent_start_time":"1000","host_id":"synthetic-chain","source":"synthetic","metadata":{"synthetic":true}}
```

`process_start_time` is an opaque nonempty string used only for identity. For `/proc`
it holds integer boot ticks and metadata declares `start_time_unit: boot_ticks`.
It is not fabricated into an epoch timestamp. Replay producers must use the same
host and start tokens consistently across all event types. Without a start token
an event may still match a rule, but it cannot safely join a different event by PID.

`parent_process_name` is optional collector-provided evidence. When the matching
parent identity was observed, ancestry uses that node's name instead. We do not
resolve absent parents by reusing a PID from another lifetime.

No schema field proves file contents, successful exfiltration or intent. The sample
network destination and file names are inert JSON strings, not collection requests.
