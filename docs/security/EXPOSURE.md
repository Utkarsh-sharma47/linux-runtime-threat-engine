# Attack surface and exposure analysis

Module `exposure` (`src/runtime_engine/security/exposure.py`). Read-only: it never
changes permissions or configuration; each finding carries a remediation for a human.

## Checks

| Rule | Check | Severity logic |
|---|---|---|
| EX001 | SUID/SGID files under `suid_paths` (depth `suid_max_depth`) | CRITICAL if others can modify it (world-writable file, or world-writable non-sticky directory) or it is a known shell-escape program (bash, find, vim, python, ...) with SUID; LOW if its name is in `expected_suid`; MEDIUM if SUID to a non-root user; else HIGH |
| EX002 | file capabilities (`security.capability` xattr) | LOW for expected helpers or network-only caps (`cap_net_raw`, `cap_net_bind_service`); HIGH if any dangerous cap (`cap_setuid`, `cap_sys_admin`, `cap_dac_override`, ...); else MEDIUM |
| EX003 | PATH entries | HIGH world-writable dir, MEDIUM if sticky or group-writable by a foreign group, MEDIUM for `.` or empty entries |
| EX004 | sensitive files | `/etc/passwd`/`group` must not be world-writable (passwd: CRITICAL), `/etc/shadow`/`gshadow` not world-readable (CRITICAL), sudoers not world-readable, `sshd_config`/crontab/cron.d not world-writable, SSH host keys and `~/.ssh` private keys private, `~/.ssh` 700, authorized_keys not group-writable. Private keys are recognized by file name; their contents are never read |
| EX005 | root-owned listening sockets (`/proc/net`, socket UID 0) not in `expected_listen_ports` | MEDIUM on all interfaces (risk ×1.5), LOW on a local address; IPv4/IPv6 sockets of one port are one finding |
| EX006 | admin-installed units in `/etc/systemd/system` without `User=`/`DynamicUser=` | LOW (review) |
| EX007 | processes whose executable is in `/tmp`, `/var/tmp`, `/dev/shm` or deleted | CRITICAL as root, else HIGH; LOW if a system binary was replaced on disk after start (update, restart pending) |
| EX008 | sudoers rules (only if readable) | CRITICAL `env_keep` of `LD_PRELOAD`/`LD_LIBRARY_PATH`; HIGH `NOPASSWD: ALL`, `!authenticate`, shell-escape programs; MEDIUM wildcards |

Without root, `/etc/sudoers` is unreadable: EX008 is reported as not assessed, never as
clean. Other users' process executables are read from `argv[0]`, labelled as spoofable.

## Risk model

`risk = weight[severity] x multiplier`, with default weights CRITICAL 40, HIGH 15,
MEDIUM 5, LOW 0.5 (configurable `weights`) and multiplier 1.5 for services on all
interfaces. The posture score sums the risks of findings that are **not accepted** in
the baseline. Grade: GOOD < 10 ≤ FAIR < 30 ≤ POOR < 70 ≤ CRITICAL; any new CRITICAL
finding makes it at least POOR. LOW is weighted 0.5 so that expected helpers stay
visible without dominating the score.

## Baseline, full and incremental scans

`exposure baseline` accepts the current findings as known posture. Accepted findings
are still listed but excluded from the score and never promoted into incidents, so only
new exposure alerts. A **full** scan walks every SUID path. An **incremental** scan
re-lists only directories whose mtime changed and re-checks known privileged files;
capability lookups are cached by inode and ctime. Every `full_scan_every`-th scan (4) is
full. Trade-off: a SUID bit added to an existing file in an unchanged directory is found
at the next full scan (covered by a test).

## Commands

```bash
python -m runtime_engine.main exposure scan [--incremental] [--severity medium] [--rule EX001] [--json]
python -m runtime_engine.main exposure baseline
python -m runtime_engine.main exposure report [--severity high] [--json]
python -m runtime_engine.main exposure show --id FINDING
```

## Measured on this host (non-root)

Full scan 0.24-0.27 s (~16,800 entries including `/usr/lib` to depth 3); incremental
0.08 s. First real scan: 46 findings (42 LOW: expected SUID helpers, network-only
capabilities, binaries replaced by updates; 4 MEDIUM: root services on ports 80, 5432,
8000 and 8080 on all interfaces), posture POOR (51). Early versions flagged
`gnome-shell (deleted)` after an update and a `known_hosts` file as a key; both false
positives are fixed and covered by tests. After `exposure baseline`, the posture is GOOD
and only new exposure is scored.

## Limitations

The checks are a selected, explainable set, not a CIS benchmark. Capabilities and SUID
bits outside `suid_paths` are not seen. Root services are identified by socket UID;
their process is only attributable as root. sudoers analysis is pattern-based and needs
root to read the files.
