# Network behaviour and process attribution

Module `network` (`src/runtime_engine/security/network.py`), collector
`src/runtime_engine/collector/net_collector.py`. Read-only; no packets, payloads or
credentials are collected.

## Collection mechanism: snapshot polling

Evaluated options: `/proc/net` + `/proc/PID/fd` (no privileges, no dependencies,
snapshots), `ss`/netlink `sock_diag` (snapshots, same attribution limits), audit
`connect()` rules (needs root and auditd), eBPF (lifecycle events with PIDs; needs
privileges and a toolchain). This engine uses the first: the simplest reliable option.

Every `interval_seconds` (default 5) the collector:

1. parses `/proc/net/{tcp,tcp6,udp,udp6}`: local/remote address and port (hex, host
   byte order per 32-bit word; IPv4-mapped IPv6 normalized), TCP state, UID, inode;
2. reads every readable `/proc/PID/fd` and maps `socket:[inode]` to PIDs;
3. resolves each PID to its identity (boot ID + PID + start ticks from
   `/proc/PID/stat`), with parent identity when the parent did not start after it.

Attribution labels: `unique`; `ambiguous: shared by N processes` (fork or fd passing);
`unattributed: owner's descriptors not readable (needs root)`; `unattributed: no owning
socket` (inode 0, e.g. TIME_WAIT). The collector interface is one method
(`snapshot()`), so an eBPF or audit source can replace it.

**This is not lifecycle capture.** Connections that open and close between snapshots
are never seen; "first observed" is the snapshot time, not the connect time.

## Pipeline integration

Sockets connected to a non-excluded remote (loopback, link-local and `exclude_cidrs`
skipped by default) that were not in the previous snapshot become `NETWORK_CONNECTION`
events (`network_destination` = remote IP; port, protocol, state and attribution in
metadata). They pass through the existing pipeline, so YAML rules apply live (the
bundled RT006 watchlist rule now fires on real traffic) and attributed events join
process incidents by identity and ancestry. The first snapshot is a baseline: existing
connections are not reported as new.

## Analysis

Per (process identity, destination) the analyzer keeps the last `history_per_flow`
(default 50) first-observed times, for at most `max_tracked_flows` (default 5000) flows
(LRU eviction, counted).

* **NB002, repeated destination**: at least `repeat_threshold` (30) new connections to one
  endpoint within `repeat_window_seconds` (600). LOW.
* **NB001, periodicity**: inter-arrival times Δtᵢ = tᵢ₊₁ − tᵢ; mean μ = (1/n)ΣΔtᵢ;
  population standard deviation σ = sqrt((1/n)Σ(Δtᵢ − μ)²); coefficient of variation
  CV = σ/μ. Flagged when there are at least `beacon_min_connections` (6) observations,
  CV ≤ `beacon_cv_threshold` (0.25) and `beacon_min_interval_seconds` (10) ≤ μ ≤
  `beacon_max_interval_seconds` (3600). LOW by default, so stored but not promoted.

A low CV only means regular timing. NTP, update checks, health probes and telemetry are
regular too (`network analyze --demo` flags a legitimate NTP-like client on purpose).
Polling quantizes Δt to the scan interval, adding up to ±interval of error, and misses
short connections; long-lived connections count once.

## Commands

```bash
python -m runtime_engine.main network connections [--json]          # current sockets
python -m runtime_engine.main network process --pid PID [--json]    # one process + stored events
python -m runtime_engine.main network analyze --demo                # synthetic timelines
python -m runtime_engine.main network analyze --input timeline.jsonl  # {"time","destination","process"}
python -m runtime_engine.main --db DB network show [--id FINDING]
```

## Privileges

Without root, other users' descriptors are unreadable (375 of ~530 processes on the test
host), so system daemons' sockets are listed but unattributed; coverage reports it. Root
attributes everything but is not recommended for routine monitoring.

## Measured on this host

~250-300 sockets, ~5,400 readable descriptors: 48-110 ms per snapshot (single core).
At the 5 s default that is roughly 1-2% of one core. Verified live: a test connection to
1.1.1.1:443 held for 8 s appeared as a `NETWORK_CONNECTION` event attributed to the exact
PID that opened it; the snapshot matched `ss -tnp` for attributed sockets.
