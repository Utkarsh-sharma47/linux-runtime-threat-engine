# Final Integration Plan (Phase 0)

**Date:** 2026-11-16  
**Primary worktree:** `/home/utkarsh/Documents/Class/xISSC-Project/rte-security` (`feat/live-atomic-edr-integration` @ `4af8eef`)  
**Do not touch:** shared checkout `linux-runtime-threat-engine` (dirty `dashboard.py`, branch empty tip)

## Worktrees

| Path | Branch / HEAD | Notes |
|---|---|---|
| `rte-security` | `feat/live-atomic-edr-integration` `4af8eef` | Lab + LiveAtomicBridge; **work here** |
| `linux-runtime-threat-engine` | `feat/complete-security-terminal-dashboard` `1a5a080` | Dirty; leave alone |
| `rte-release` | `main` `a1d38ec` | Tracks `origin/main` |
| `rte-verify` | detached `a1d38ec` | Prior CI verify |

## Remote

- `origin` → `https://github.com/Utkarsh-sharma47/linux-runtime-threat-engine.git`
- `origin/main` = `a1d38ec` (already contains security modules, offline Atomic, LiveAtomicBridge, network investigation)
- **Missing from main:** security-lab package/scripts (`e605a6e`, `4af8eef`)
- **Missing entirely:** host NIC overview / RX-TX throughput dashboard; individual `run-*-test.sh` wrappers; definitive `setup.md`

## Branch decisions

| Branch | Action |
|---|---|
| `feat/live-atomic-edr-integration` | Continue; merge `origin/main` in; add Phases 1–4 |
| `origin/main` | Target of PR after validation |
| `feat/complete-security-terminal-dashboard` | Empty tip (= old main); **skip** |
| Feature module branches | Already in `origin/main` via prior integration |
| `feat/threat-process-ancestry-visualization` | Ancestry already on main (`t` key / tree); verify no unique commits beyond |

## Execution order

1. Merge `origin/main` → live branch (no conflicts expected).
2. Phase 1: thin `run-*-test.sh` wrappers + interactive Atomic script.
3. Phase 2: interface collector + network dashboard page + numeric nav aliases.
4. Phase 3: rewrite `setup.md`.
5. Phase 4: tests + quality gates.
6. Phase 5: push branch → PR → merge to main (no force-push) → fresh verify worktree.

## Safety

No `reset --hard`, no `clean -fd`, no force-push, no blind ours/theirs, no editing shared dirty worktree.
