# File integrity monitoring with a SHA-256 Merkle tree

Module `integrity` (`src/runtime_engine/security/integrity.py`). Read-only.

## Construction (`sha256-merkle-v1`)

| Element | Definition |
|---|---|
| Order | leaves sorted by the path's bytes (`os.fsencode`): deterministic |
| Leaf | `SHA256(0x00 ‖ lp(path) ‖ lp(kind) ‖ u32 mode ‖ u32 uid ‖ u32 gid ‖ lp(content digest))`, where `lp(x)` = 4-byte big-endian length ‖ x |
| Content digest | regular file: SHA-256 of its bytes; symlink: `SHA256("link:" ‖ target)` (never followed); file larger than `max_file_bytes`: `SHA256("meta:size:mtime")` (kind `large`); unreadable: empty (kind `unreadable`) |
| Node | `SHA256(0x01 ‖ left ‖ right)` |
| Odd level | the last node is promoted unchanged, never duplicated (duplication would let `[a,b,c]` and `[a,b,c,c]` share a root) |
| Empty tree | `SHA256("")` |
| Proof | sibling hashes from leaf to root with their side; verify by re-hashing upward |

The `0x00`/`0x01` prefixes separate leaves from nodes, so a node cannot be presented as a
leaf. Length prefixes make the encoding unambiguous. Mode and ownership are inside the
leaf, so `chmod`/`chown` change the root; they are reported separately from content
changes.

## Scope and safety

Only configured paths are scanned (`security.integrity.paths`; default `/etc/passwd`,
`/etc/group`, `/etc/hosts`, `/etc/ssh/sshd_config`, `/etc/systemd/system`,
`/usr/local/bin`, `/usr/local/sbin`). Walks go at most `max_depth` (8) deep, never
follow symlinks or leave the configured roots, skip `exclude` patterns (`*.swp`, `*~`,
`*.tmp`, `*.pid`, `*.lock`, `*.log`, `*.cache`) and stop at `max_files` (50,000), noting
it in coverage. Files are opened with `O_NOFOLLOW`. There is no full-filesystem scan.

## Verification

`verify` recomputes leaves for the paths recorded in the baseline. Unchanged files
(same size, mtime, ctime and inode) reuse their stored digest; `--full` re-reads
everything. It reports added, deleted, content-modified and metadata-changed files, the
current and baseline roots, and the Merkle path (the node hashes up to the root) of each
changed leaf. Findings: FI001 content modified (MEDIUM), FI002 added (LOW), FI003 deleted
(MEDIUM), FI004 permissions/ownership (MEDIUM), FI005 baseline differs from its external
anchor or the anchor signature is invalid (HIGH).

## Baseline trust and anchoring

The baseline lives in the engine database. **Anyone who can write that file, including
root, can replace it** and make tampered files look intact. To detect that:

1. `integrity keygen --output /media/usb/key`: a random 32-byte HMAC key (0600),
   kept off the host.
2. `integrity baseline --export /media/usb/anchor.json --key-file /media/usb/key`:
   writes `{format, algorithm, root, leaf_count, created_at, host, paths}` plus
   `hmac_sha256` over its canonical JSON.
3. `integrity verify --anchor /media/usb/anchor.json --key-file /media/usb/key`: checks
   the HMAC and compares the stored baseline root with the anchored root.

This is tamper evidence, not tamper proofing. If the key and the anchor are stored on
the monitored host, an attacker with root can re-sign a forged anchor. An unsigned
anchor is only as trustworthy as the place it was copied to.

## Commands

```bash
python -m runtime_engine.main integrity baseline [--path P ...] [--export FILE [--key-file K]]
python -m runtime_engine.main integrity verify [--full] [--anchor FILE [--key-file K]] [--json]
python -m runtime_engine.main integrity show [--json]
python -m runtime_engine.main integrity proof --file PATH [--baseline] [--json]
python -m runtime_engine.main integrity keygen --output FILE
python -m runtime_engine.main integrity demo [--json]     # temporary files only
```

Live monitoring verifies every `interval_seconds` (300) against the stored baseline; it
reports `no-baseline` until one exists.

## Measured

On the test host the default paths contained 247 files: baseline 0.55 s, incremental
verification 8 ms (nothing re-read). The demo changes temporary files and shows that the
root changes, that the modified, deleted, added and `chmod`-ed files are classified
correctly, and that a proof for the modified file verifies against the current root but
not the baseline root. In the CLI test, an attacker-style replacement of the stored
baseline passed the local check but was caught by the external anchor (FI005).

## Limitations

Changes made and reverted between two verifications are not seen. Files over
`max_file_bytes` are compared by size and mtime only. The writing process is unknown.
Root can also tamper with the engine itself; anchoring only helps if the verifier and
the anchor are trusted.
