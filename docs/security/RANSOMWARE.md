# Ransomware early warning

Part of the host-security and file-behaviour subsystem. It is independent of the
attack-surface analyzer: it watches *behaviour* in directories you choose, not configuration.

It is **off until you configure directories** (`security.ransomware.directories`); nothing in
your home directory is watched or read by default. Findings use rule `RW001` and flow through
the same pipeline as every other security finding (storage, severity policy, incident
correlation, dashboard).

## How detection works

File events come from **inotify** (via `ctypes`, no extra dependency) on each configured
directory and its subdirectories. If inotify cannot be initialised the module falls back to
**polling** `(inode, size, mtime)` snapshots and matches renames by inode. The mechanism in use
is always shown in the report.

Events are kept in a sliding window (`window_seconds`, default 30 s, bounded by
`max_events_per_window`). Each scan computes six indicators in `[0, 1]`:

| Indicator | Full at (default, per window) | Weight |
| --- | --- | --- |
| modifications | 30 file writes | 0.25 |
| renames | 15 renames | 0.20 |
| files | 20 distinct files touched | 0.15 |
| directories | 3 distinct directories | 0.10 |
| entropy | 50 % of sampled writes jump from <= 6.0 to >= 7.2 bits/byte | 0.20 |
| extensions | 60 % of renames share one new extension | 0.10 |

`score = 100 * sum(weight * indicator)`. An alert needs **score >= 50 and at least two fully
triggered indicators**. Severity is HIGH at score >= 75, otherwise MEDIUM. Because entropy is
worth at most 20 points and needs a second indicator, compressed or encrypted files saved
normally never alert on entropy alone.

### Entropy sampling

Shannon entropy is computed over at most `sample_bytes` (64 KiB) from the start of the file,
opened read-only with `O_NOFOLLOW`. Reads are rate-limited by a token bucket
(`entropy_reads_per_second`, default 50); skipped samples are counted and reported. The
remembered per-file entropy table is capped at 20 000 entries. Existing files are sampled once
at start-up (bounded by the same rate limit) so later rewrites have a "before" value.

Events are processed in batches each interval, so a file that is rewritten and renamed between
two scans is sampled under its new name; its previous entropy is then shown as `unknown` and
it still counts as an entropy rise if the new content is high-entropy.

### Process attribution

inotify and polling do not report which process changed a file. When an alert fires, the module
lists processes whose working directory or open file descriptors are inside the directory
**at that moment**. If exactly one process matches it is attached to the finding (and therefore
to process correlation); otherwise attribution is reported as unavailable with the candidate
list. A process that has already exited, or that writes via a path outside the directory, will
not be found. This is labelled as heuristic everywhere it appears.

## Safe simulator

`runtime_engine.security.ransomware_sim` imitates the behaviour without touching user data:

- It only operates in a lab directory **directly under the system temp directory** whose name
  starts with `rte-ransomware-lab`, and which is new, empty, or carries the simulator marker
  file. Symlinks, other paths and non-empty foreign directories are refused (exit code 2).
- It creates its own low-entropy dummy files (`lab-file-NNN.txt`), XORs them with random
  bytes (not real encryption, no key is kept) and renames them to `.locked`.
- The number of files is bounded (default 20 to 30, maximum 200).
- `cleanup` removes only the files the simulator created and the lab directory when it is empty.

## Commands

```bash
runtime-engine ransomware demo                    # lab + simulator subprocess + detection + cleanup
runtime-engine ransomware demo --files 50 --keep  # keep the lab to inspect it
runtime-engine ransomware simulate --files 30     # run only the simulator (no detection)
runtime-engine ransomware cleanup --lab-dir /tmp/rte-ransomware-lab-XXXX
runtime-engine ransomware watch --dir ~/Projects/scratch --duration 60
runtime-engine ransomware report [--json]         # last stored report and RW001 findings
```

To monitor continuously inside `runtime-engine monitor`, add directories to the configuration:

```yaml
security:
  ransomware:
    directories: ["~/Documents/shared-drive"]
    exclude: ["*.swp", "*~", "*.tmp", ".git"]
```

`monitor --no-security-modules` disables all security modules.

## Measured on this host (non-root, inotify)

`ransomware demo --files 40`, three consecutive runs: score 88 (HIGH) each time, triggered
`extensions, files, modifications, renames`, simulator attributed by working directory, lab
removed afterwards. A scan of a quiet directory (50 files, inotify) takes about 0.06 ms; an
alerting scan takes tens of milliseconds because it walks `/proc` for candidate processes.

## Limitations

- Early warning only: it does not block, kill or roll back anything.
- Attribution is heuristic (see above); there is no eBPF or fanotify per-event PID.
- inotify watches are bounded by `max_watches` and the kernel limit
  (`fs.inotify.max_user_watches`); queue overflows are counted and mark the report `degraded`.
- Polling sees only the net change between two scans: a file created, rewritten and renamed
  within one interval appears only as a new file, so fast activity on files that did not exist
  at the previous scan is under-counted. Existing files encrypted in place are detected.
- Backups, archivers, sync clients and build tools can produce similar patterns; use the
  allowlist (`RW001:/path/*`) for directories where this is expected.
- Only files readable by the engine's user can be entropy-sampled.
