# Limitations and privacy

## Telemetry and evidence

- `/proc` polling can miss any process that starts and exits between snapshots. It
  discovers visible identities, not every exec, fork or exit. Exec replacing an image
  in the same PID/start lifetime is not emitted as a new discovery. First observations
  describe discovery time, not kernel creation time.
- Permissions, hidepid, containers, namespaces, kernel threads and process races reduce
  visibility. One inaccessible/malformed process increments errors and does not crash
  the snapshot. Failure to read the `/proc` root or boot ID is a configuration error.
- Stat rechecking and start-time-qualified identities reduce PID reuse mistakes but do
  not give atomic kernel snapshots. Very rare same-PID/same-start-tick reuse remains
  ambiguous. Parent metadata can race with reparenting; no absolute guarantee is made.
- There is no live file, network, privilege-change, audit or eBPF collector. The related
  rules use replay telemetry. Disappearance during polling never becomes a fake exit.
- Default rules are small indicators, not a detection-accuracy study. Legitimate
  automation, maintenance and sudo can match. Tune them to authorized workloads.
- Names and replay fields can be forged. A same-host compromised observer can evade
  or falsify telemetry. There is no tamper resistance, signature verification or rootkit
  detection. The engine is not an EDR, SIEM or safety boundary.

## Correlation and performance

- Correlation is session-local and order-dependent. Late parent observations do not
  reevaluate old rules or merge existing incidents. `--sort` buffers the whole input.
- An exact parent-start identity is required for ancestry. Missing metadata reduces
  correlation rather than inviting PID guesses. Shared resources are not identity.
- Graphs, seen process identities and session incidents are retained in memory. There
  is no long-running cache bound or automatic retention. SQLite grows with all valid
  events, including benign evidence. Monitor for bounded periods in this prototype.
- Correlation scans existing session incidents. Evidence-heavy repeated incidents
  rewrite report JSON; large or adversarial input can be expensive. No untrusted-input
  byte limits, asynchronous ingestion, streaming sort or load shedding are implemented.
- Single-process/single-writer use only. No schema migrations, concurrent ingestion,
  cross-session incident restoration, retention daemon or management UI is included.
  Within one `monitor` process, the pipeline thread is the only writer and the terminal
  thread reads through the same lock-protected connection.

## Live terminal

- The dashboard is a view of the polling collector, so it inherits every polling gap
  above. A quiet stream means nothing new was *discovered*, not that nothing happened.
- When the bounded queue is full the collector waits instead of dropping, which delays
  the next poll (visible as backpressure). Events are only left unprocessed after a
  forced stop or an engine failure, and the report counts them. `kill -9` loses the
  final summary; the session then stays `INCOMPLETE` in the history.
- Display buffers are bounded; evicted stream entries and the oldest of the 5,000
  buffered events for the `e` page are still in SQLite (use the `events` command).
  Session state (processes, alerts, incidents) grows like the correlation state.
- Collector error counts are cumulative reads over all polls, because every poll rereads
  every process; the dashboard shows per-poll gaps instead.
- Single-key input needs a POSIX terminal (termios). Without one, or under pipes and CI,
  the engine uses line output and has no interactive pages.
- Incident "ACTIVE" means the correlation window is still open, not that an attack is
  ongoing. A derived start time uses boot time plus start ticks and is only shown for
  processes from the current boot.
- A storage error aborts the run. Do not catch it and continue using the same Pipeline;
  in-memory state may be ahead of its rolled-back database transaction.

## Privacy and safe use

Only monitor systems and ingest telemetry you are permitted to inspect. Prefer a
normal user, not root. Argument collection is off by default because argv can expose
passwords, tokens, URLs and personal data. Process names, UIDs, paths and even synthetic
metadata can be sensitive when real sources replace the examples.

The engine does not collect file contents or environment variables. It has no network
client and no telemetry upload. New database files use mode 0600; existing permissions
are preserved and SQLite is not encrypted. Use a protected local directory (for example
`mkdir -m 700 private-reports`), restrict access to exports and use device encryption.
No automatic retention or deletion exists: choose an authorized retention period,
stop the engine, then remove its database and reports when that period expires. Follow
your organization policy for secure disposal and backups. `.gitignore` excludes local
databases, environment files, coverage and generated reports, but you still must review
staged files and exported reports before sharing. The engine never edits monitored
processes, sends signals, changes firewall rules or remediates incidents.
