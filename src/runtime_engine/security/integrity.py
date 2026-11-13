"""Cryptographic file integrity monitoring with a SHA-256 Merkle tree.

Construction (version `sha256-merkle-v1`):

* leaves are sorted by the path's bytes (os.fsencode), so the tree is deterministic;
* leaf  = SHA256(0x00 || lp(path) || lp(kind) || u32 mode || u32 uid || u32 gid ||
          lp(content digest)), where lp(x) = u32 big-endian length || x. The content
          digest is SHA256(file bytes) for files, SHA256("link:" || target) for symlinks
          (never followed), SHA256("meta:" || size || mtime) for files above the size
          limit and empty for unreadable files. Mode and ownership are part of the leaf,
          so permission changes change the root;
* node  = SHA256(0x01 || left || right); the 0x00/0x01 prefixes keep leaves and nodes
          from being confused (second-preimage resistance);
* an odd node at the end of a level is promoted unchanged to the next level (never
  duplicated, which would let two different leaf lists share a root);
* the root of an empty tree is SHA256("").

A membership proof is the list of sibling hashes from a leaf to the root with their side.

Security boundary: a baseline stored on the monitored host can be replaced by anyone who
can write the engine database (for example root). Export the root to separate media,
optionally with an HMAC from a key kept off the host, and verify against that anchor.
"""

import hashlib
import hmac
import json
import os
import socket
import struct
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtime_engine.config.settings import IntegritySettings
from runtime_engine.events.schema import Severity
from runtime_engine.security.findings import Coverage, Finding, ScanReport, SeverityPolicy
from runtime_engine.security.fsutil import FileHasher, FileMeta, excluded, expand, lstat, walk

MODULE = "integrity"
ALGORITHM = "sha256-merkle-v1"
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


@dataclass(frozen=True)
class Leaf:
    path: str
    kind: str  # file, symlink, large, unreadable, other
    mode: int
    uid: int
    gid: int
    digest: str  # content digest (hex), "" when unreadable
    size: int | None
    mtime_ns: int | None
    ctime_ns: int | None
    inode: int | None

    def hash(self) -> bytes:
        return hashlib.sha256(
            b"\x00"
            + lp(os.fsencode(self.path))
            + lp(self.kind.encode())
            + struct.pack(">III", self.mode & 0xFFFFFFFF, self.uid, self.gid)
            + lp(bytes.fromhex(self.digest))
        ).digest()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self) | {"leaf": self.hash().hex()}


def node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    def __init__(self, leaves: list[Leaf]) -> None:
        self.leaves = sorted(leaves, key=lambda leaf: os.fsencode(leaf.path))
        self.index = {leaf.path: i for i, leaf in enumerate(self.leaves)}
        level = [leaf.hash() for leaf in self.leaves]
        self.levels: list[list[bytes]] = [level]
        while len(level) > 1:
            nxt = [node(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
            if len(level) % 2:
                nxt.append(level[-1])  # odd node promoted unchanged
            self.levels.append(nxt)
            level = nxt

    @property
    def root(self) -> str:
        return self.levels[-1][0].hex() if self.leaves else EMPTY_ROOT

    def proof(self, path: str) -> list[dict[str, str]]:
        position = self.index[path]
        steps: list[dict[str, str]] = []
        for level in self.levels[:-1]:
            sibling = position ^ 1
            if sibling < len(level):
                steps.append(
                    {
                        "side": "left" if sibling < position else "right",
                        "hash": level[sibling].hex(),
                    }
                )
            position //= 2
        return steps

    def path_to_root(self, path: str) -> list[str]:
        """The node hashes recomputed when this leaf changes (its Merkle path)."""
        position = self.index[path]
        hashes = []
        for level in self.levels:
            hashes.append(level[position].hex())
            position //= 2
        return hashes


def verify_proof(leaf_hash: str, steps: list[dict[str, str]], root: str) -> bool:
    current = bytes.fromhex(leaf_hash)
    for step in steps:
        sibling = bytes.fromhex(step["hash"])
        current = node(sibling, current) if step["side"] == "left" else node(current, sibling)
    return hmac.compare_digest(current.hex(), root)


# ----- collection -----


def leaf_for(meta: FileMeta, hasher: FileHasher, previous: Leaf | None, full: bool) -> Leaf:
    mode, uid, gid = meta.mode or 0, meta.uid or 0, meta.gid or 0
    common = (meta.size, meta.mtime_ns, meta.ctime_ns, meta.inode)
    if meta.kind == "symlink":
        target = hashlib.sha256(b"link:" + os.fsencode(meta.link_target or "")).hexdigest()
        return Leaf(meta.path, "symlink", mode, uid, gid, target, *common)
    if meta.kind != "file":
        return Leaf(meta.path, "other", mode, uid, gid, "", *common)
    if (
        not full
        and previous is not None
        and previous.kind == "file"
        and (previous.size, previous.mtime_ns, previous.ctime_ns, previous.inode) == common
    ):
        return Leaf(meta.path, "file", mode, uid, gid, previous.digest, *common)  # incremental
    digest, status = hasher.digest(meta, use_cache=not full)
    if digest is not None:
        return Leaf(meta.path, "file", mode, uid, gid, digest, *common)
    if status == "too-large":
        marker = hashlib.sha256(f"meta:{meta.size}:{meta.mtime_ns}".encode()).hexdigest()
        return Leaf(meta.path, "large", mode, uid, gid, marker, *common)
    return Leaf(meta.path, "unreadable", mode, uid, gid, "", *common)


def collect(
    paths: list[str],
    settings: IntegritySettings,
    previous: dict[str, Leaf] | None = None,
    *,
    full: bool = False,
    hasher: FileHasher | None = None,
) -> tuple[list[Leaf], Coverage]:
    """Leaves for the configured files and directories; never leaves those roots."""
    hasher = hasher or FileHasher(settings.max_file_bytes)
    coverage = Coverage()
    leaves: dict[str, Leaf] = {}
    previous = previous or {}
    for raw in paths:
        root = expand(raw)
        meta = lstat(root)
        if meta.kind == "missing":
            coverage.unavailable.append(f"{root} does not exist")
            continue
        if meta.kind == "denied":
            coverage.deny(root)
            continue
        items = [meta] if meta.kind != "dir" else []
        if meta.kind == "dir":
            errors: list[str] = []
            items = [
                m
                for m in walk(
                    root, max_depth=settings.max_depth, exclude=settings.exclude, errors=errors
                )
                if m.kind != "dir"
            ]
            for path in errors:
                coverage.deny(path)
        for item in items:
            if excluded(item.path, settings.exclude) or item.path in leaves:
                continue
            if len(leaves) >= settings.max_files:
                coverage.unavailable.append(
                    f"file limit {settings.max_files} reached; rest not hashed"
                )
                break
            leaf = leaf_for(item, hasher, previous.get(item.path), full)
            if leaf.kind == "unreadable":
                coverage.deny(item.path)
            leaves[item.path] = leaf
            coverage.checked += 1
    return list(leaves.values()), coverage


# ----- baseline, verification, anchoring -----


def baseline_body(paths: list[str], leaves: list[Leaf], coverage: Coverage) -> dict[str, Any]:
    tree = MerkleTree(leaves)
    return {
        "algorithm": ALGORITHM,
        "created_at": datetime.now(UTC).isoformat(),
        "host": socket.gethostname(),
        "paths": paths,
        "root": tree.root,
        "leaf_count": len(leaves),
        "leaves": [leaf.as_dict() for leaf in tree.leaves],
        "coverage": coverage.as_dict(),
    }


def leaves_from_body(body: dict[str, Any]) -> dict[str, Leaf]:
    result = {}
    for item in body["leaves"]:
        values = {k: v for k, v in item.items() if k != "leaf"}
        result[item["path"]] = Leaf(**values)
    return result


def compare(baseline: dict[str, Leaf], current: dict[str, Leaf]) -> dict[str, list[dict[str, Any]]]:
    added = [current[p].as_dict() for p in sorted(set(current) - set(baseline))]
    deleted = [baseline[p].as_dict() for p in sorted(set(baseline) - set(current))]
    modified: list[dict[str, Any]] = []
    metadata: list[dict[str, Any]] = []
    for path in sorted(set(current) & set(baseline)):
        before, after = baseline[path], current[path]
        if before.hash() == after.hash():
            continue
        change = {
            "path": path,
            "before": before.as_dict(),
            "after": after.as_dict(),
            "content_changed": before.digest != after.digest or before.kind != after.kind,
        }
        (modified if change["content_changed"] else metadata).append(change)
    return {"added": added, "deleted": deleted, "modified": modified, "metadata_changed": metadata}


def canonical(manifest: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in manifest.items() if k != "hmac_sha256"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()


def export_manifest(body: dict[str, Any], key: bytes | None) -> dict[str, Any]:
    manifest = {
        "format": "rte-integrity-anchor-v1",
        "algorithm": body["algorithm"],
        "root": body["root"],
        "leaf_count": body["leaf_count"],
        "created_at": body["created_at"],
        "host": body["host"],
        "paths": body["paths"],
    }
    if key is not None:
        manifest["hmac_sha256"] = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
    return manifest


def check_anchor(
    manifest: dict[str, Any], key: bytes | None, baseline_root: str | None
) -> dict[str, Any]:
    """Signature status plus whether the stored baseline still matches the anchored root."""
    if "hmac_sha256" not in manifest:
        signature = "unsigned manifest (only as trustworthy as where it was stored)"
        valid = None
    elif key is None:
        signature = "signed, but no key given: signature not checked"
        valid = None
    else:
        expected = hmac.new(key, canonical(manifest), hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(expected, manifest["hmac_sha256"])
        signature = "valid HMAC-SHA256" if valid else "INVALID HMAC: manifest altered or wrong key"
    return {
        "anchored_root": manifest.get("root"),
        "signature": signature,
        "signature_valid": valid,
        "baseline_root": baseline_root,
        "baseline_matches_anchor": baseline_root == manifest.get("root"),
    }


FINDING_RULES = {
    "FI001": ("Monitored file content modified", Severity.MEDIUM),
    "FI002": ("New file in a monitored location", Severity.LOW),
    "FI003": ("Monitored file deleted", Severity.MEDIUM),
    "FI004": ("Monitored file permissions or ownership changed", Severity.MEDIUM),
    "FI005": ("Integrity baseline does not match its external anchor", Severity.HIGH),
}


def findings_for(result: dict[str, list[dict[str, Any]]], detected: datetime) -> list[Finding]:
    findings = []
    groups = (
        ("modified", "FI001"),
        ("added", "FI002"),
        ("deleted", "FI003"),
        ("metadata_changed", "FI004"),
    )
    for group, rule in groups:
        for item in result[group]:
            path = item["path"]
            title, severity = FINDING_RULES[rule]
            evidence = {
                "change": group.replace("_", " "),
                "before": item.get("before"),
                "after": item.get("after") if group != "added" else item,
            }
            if group in ("added", "deleted"):
                evidence = {"change": group, "leaf": item}
            findings.append(
                Finding.create(
                    MODULE,
                    rule,
                    path,
                    title=title,
                    severity=severity,
                    evidence=evidence,
                    explanation=(
                        f"{title}: the file's Merkle leaf differs from the baseline. The leaf "
                        "covers content (SHA-256), type, mode and ownership. Updates and "
                        "administration also change files; the writing process is not known."
                    ),
                    attribution="unavailable: hashing cannot identify the writer",
                    detected_at=detected,
                )
            )
    return findings


class IntegrityMonitor:
    name = MODULE

    def __init__(
        self,
        settings: IntegritySettings,
        baseline: dict[str, Any] | None,
        policy: SeverityPolicy | None = None,
    ) -> None:
        self.settings = settings
        self.interval = settings.interval_seconds
        self.baseline = baseline
        self.policy = policy or SeverityPolicy(
            overrides=settings.severity_overrides, allow=settings.allow
        )
        self.hasher = FileHasher(settings.max_file_bytes)
        self.previous: dict[str, Leaf] = leaves_from_body(baseline) if baseline else {}
        self.last_result: dict[str, Any] | None = None

    def verify(self, *, full: bool = False) -> tuple[dict[str, Any], Coverage]:
        if self.baseline is None:
            raise ValueError("no integrity baseline")
        base = leaves_from_body(self.baseline)
        leaves, coverage = collect(
            self.baseline["paths"], self.settings, self.previous, full=full, hasher=self.hasher
        )
        self.previous = {leaf.path: leaf for leaf in leaves}
        tree = MerkleTree(leaves)
        changes = compare(base, self.previous)
        for item in changes["modified"] + changes["metadata_changed"]:
            item["merkle_path_current"] = tree.path_to_root(item["path"])
        result = {
            "baseline_root": self.baseline["root"],
            "current_root": tree.root,
            "root_matches": tree.root == self.baseline["root"],
            "files_verified": len(leaves),
            "baseline_files": len(base),
            "hash_reads": self.hasher.reads,
            "verified_at": datetime.now(UTC).isoformat(),
            **changes,
        }
        return result, coverage

    def scan(self, full: bool = False) -> ScanReport:
        started = datetime.now(UTC)
        clock = time.perf_counter()
        if self.baseline is None:
            return ScanReport(
                MODULE, "no-baseline", started, 0.0, summary={"note": "run: integrity baseline"}
            )
        result, coverage = self.verify(full=full)
        self.last_result = result
        findings, suppressed = self.policy.apply(findings_for(result, started))
        status = "degraded" if coverage.denied_count or coverage.unavailable else "ok"
        summary = {
            k: v
            for k, v in result.items()
            if k not in ("added", "deleted", "modified", "metadata_changed")
        }
        summary["counts"] = {
            k: len(result[k]) for k in ("added", "deleted", "modified", "metadata_changed")
        }
        summary["changes"] = {k: [i.get("path") for i in result[k]][:50] for k in summary["counts"]}
        summary["baseline_created_at"] = self.baseline["created_at"]
        summary["paths"] = self.baseline["paths"]
        return ScanReport(
            MODULE,
            status,
            started,
            time.perf_counter() - clock,
            findings,
            coverage,
            summary,
            suppressed,
        )


def baseline_proof(body: dict[str, Any], path: str) -> dict[str, Any]:
    tree = MerkleTree(list(leaves_from_body(body).values()))
    if path not in tree.index:
        raise KeyError(path)
    leaf = tree.leaves[tree.index[path]].hash().hex()
    steps = tree.proof(path)
    return {
        "path": path,
        "leaf": leaf,
        "root": tree.root,
        "proof": steps,
        "verified": verify_proof(leaf, steps, tree.root),
    }


def demo(directory: Path, settings: IntegritySettings) -> dict[str, Any]:
    """Self-contained demonstration in a temporary directory: baseline, change, verify."""
    directory.mkdir(parents=True, exist_ok=True)
    for index in range(5):
        (directory / f"config-{index}.conf").write_text(f"setting_{index} = {index}\n")
    paths = [str(directory)]
    leaves, coverage = collect(paths, settings)
    body = baseline_body(paths, leaves, coverage)
    before = baseline_proof(body, str(directory / "config-0.conf"))
    (directory / "config-1.conf").write_text("setting_1 = changed\n")
    (directory / "config-4.conf").unlink()
    (directory / "added.conf").write_text("new = 1\n")
    (directory / "config-2.conf").chmod(0o666)
    monitor = IntegrityMonitor(settings, body)
    result, _ = monitor.verify()
    current = MerkleTree(list(monitor.previous.values()))
    unchanged = str(directory / "config-0.conf")
    changed = str(directory / "config-1.conf")
    changed_leaf = current.leaves[current.index[changed]].hash().hex()
    return {
        "directory": str(directory),
        "baseline_root": body["root"],
        "current_root": result["current_root"],
        "root_changed": not result["root_matches"],
        "added": [i["path"] for i in result["added"]],
        "deleted": [i["path"] for i in result["deleted"]],
        "modified": [i["path"] for i in result["modified"]],
        "metadata_changed": [i["path"] for i in result["metadata_changed"]],
        "proof_unchanged_file_against_baseline": before["verified"],
        "proof_unchanged_file_against_current": verify_proof(
            current.leaves[current.index[unchanged]].hash().hex(),
            current.proof(unchanged),
            current.root,
        ),
        "proof_modified_file_against_baseline_root": verify_proof(
            changed_leaf, current.proof(changed), body["root"]
        ),
        "proof_modified_file_against_current_root": verify_proof(
            changed_leaf, current.proof(changed), current.root
        ),
    }
