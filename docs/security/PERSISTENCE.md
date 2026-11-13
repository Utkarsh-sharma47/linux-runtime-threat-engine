# Persistence and privilege-escalation monitoring

Module `persistence` (`src/runtime_engine/security/persistence.py`). Read-only.

## What it watches (configurable under `security.persistence`)

| Category | Default locations | Compared |
|---|---|---|
| systemd | `/etc/systemd/system`, `/etc/systemd/user`, `~/.config/systemd/user`, `/usr/lib/systemd/system` (`*.service`, `*.timer`, `*.socket`, `*.path`, `*.target`, depth 2) | presence, SHA-256, mode/owner, symlink target |
| cron | `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.{d,hourly,daily,weekly,monthly}`, `/var/spool/cron/crontabs` | same |
| SSH | `~/.ssh/authorized_keys{,2}`, `/root/.ssh/authorized_keys` | SHA-256 and key count only |
| sudoers | `/etc/sudoers`, `/etc/sudoers.d` | SHA-256 when readable, else metadata |
| privileged | SUID/SGID files and files with capabilities in `/usr/bin`, `/usr/sbin`, `/usr/local/{bin,sbin}`, `/usr/libexec`, `/usr/lib/openssh`, `/usr/lib/dbus-1.0` (depth 1) | privilege bits, capabilities, SHA-256 |
| executable | executables in `/usr/local/{bin,sbin}`, `~/.local/bin` | new files |

## Method

1. **Baseline**: `persistence baseline` records, per item, `lstat` metadata (mode,
   owner, size, mtime/ctime, inode, symlink target), a SHA-256 digest (files up to
   `max_hash_bytes`, default 1 MiB; `O_NOFOLLOW`) and the decoded `security.capability`
   xattr. authorized_keys is reduced to a digest plus the number of key lines: key
   material, password hashes and file contents are never stored or displayed.
2. **Scan**: the same collection, compared item by item with the baseline. Unchanged
   files are not re-read: digests are cached by (device, inode, size, mtime, ctime).
3. **Rules** (default severity, overridable with `severity_overrides`):

| Rule | Meaning | Severity | ATT&CK |
|---|---|---|---|
| PM001 | systemd unit added/modified (vendor `/usr/lib` units: LOW) | MEDIUM | T1543.002 |
| PM002 | cron job added/modified | MEDIUM | T1053.003 |
| PM003 | authorized_keys changed (digest/key count) | HIGH | T1098.004 |
| PM004 | sudoers changed | HIGH | T1548.003 |
| PM005 | new SUID/SGID executable, bit added (HIGH) or privileged binary changed (MEDIUM) | HIGH | T1548.001 |
| PM006 | capabilities added/changed (MEDIUM unless a dangerous capability such as `cap_setuid`, `cap_sys_admin`) | HIGH | T1548 |
| PM007 | new executable in a sensitive directory | LOW | T1036 |
| PM008 | became world/group-writable or root ownership lost | HIGH | T1222.002 |
| PM009 | monitored item removed | LOW | T1070 |

4. **Policy**: `allow` entries (`glob` or `RULE:glob`) suppress expected resources and
   are counted; findings at or above `security.promote_min_severity` (default MEDIUM)
   are promoted into incident correlation, others are stored only. Every finding is
   evidence for review, not a verdict: package upgrades and administration change these
   files legitimately.

Evidence contains the changed resource, previous and current metadata, owner and
permission changes, the detection time, the rule and the attribution status.

## Live monitoring

`monitor` scans every `interval_seconds` (default 60) in its own thread. With a stored
baseline it compares against it; without one, the first scan becomes an in-memory
session baseline (`baseline-created`) and later scans report changes since start.
Findings travel through the engine's bounded queue to the pipeline thread.

## Privileges and telemetry gaps

As a normal user, `/etc/sudoers`, `/etc/sudoers.d/*`, `/var/spool/cron/crontabs` and
`/root/.ssh` are unreadable. They are listed under coverage (status `degraded`) and
sudoers is compared by metadata only; nothing unreadable is reported as unchanged.
**Process attribution is unavailable**: polling cannot tell which process wrote a file.
That needs audit or eBPF telemetry, which this engine does not collect.

## Limitations

- Changes between two scans that are reverted before the next scan are not seen.
- The baseline lives in the engine database on the same host; root (or anyone who can
  write the database) can replace it. Keep an off-host copy for tamper evidence.
- Files larger than `max_hash_bytes` are compared by size/mtime only.
- Only listed directories are scanned (depth 1 for privileged dirs); SUID files elsewhere
  are found by the attack surface analyzer, not by this module.

## Measured on this host (Ubuntu 24.04, non-root)

706 baselined items out of 3,658 checked; 4 locations unreadable. Baseline 0.75 s
(process start included); repeat scan 0.08-0.10 s, because unchanged files are not
re-hashed.

## Reproduce safely

```bash
python -m runtime_engine.main --db /tmp/p.db persistence baseline
python -m runtime_engine.main --db /tmp/p.db persistence scan
python -m runtime_engine.main --db /tmp/p.db persistence show [--id FINDING] [--json]
pytest -q tests/security/test_persistence.py   # synthetic dirs: new units, cron edits,
                                                # key changes, SUID bits, capabilities,
                                                # permission denial, allowlists
```
