"""Merkle tree construction, proofs, file changes, anchoring and the integrity CLI."""

import hashlib
import json
import os

import pytest

from runtime_engine.config.settings import IntegritySettings
from runtime_engine.main import main
from runtime_engine.security.fsutil import FileHasher
from runtime_engine.security.integrity import (
    EMPTY_ROOT,
    IntegrityMonitor,
    Leaf,
    MerkleTree,
    baseline_body,
    check_anchor,
    collect,
    export_manifest,
    node,
    verify_proof,
)

ROOT_USER = os.geteuid() == 0


def leaf(path, digest="aa"):
    return Leaf(path, "file", 0o100644, 0, 0, digest * 32, 1, 1, 1, 1)


def test_tree_shape_odd_leaves_and_empty():
    a, b, c = leaf("/a", "01"), leaf("/b", "02"), leaf("/c", "03")
    assert MerkleTree([]).root == EMPTY_ROOT == hashlib.sha256(b"").hexdigest()
    assert MerkleTree([a]).root == a.hash().hex()
    expected = node(node(a.hash(), b.hash()), c.hash()).hex()  # odd node promoted, not duplicated
    assert MerkleTree([c, a, b]).root == expected  # order of input does not matter
    duplicated = MerkleTree([a, b, c, leaf("/d", "03")]).root
    assert duplicated != expected
    # Domain separation: a leaf hash is never equal to a node over the same bytes.
    assert a.hash() != hashlib.sha256(b"\x01" + a.hash()).digest()


@pytest.mark.parametrize("count", range(1, 10))
def test_proofs_verify_for_every_leaf(count):
    leaves = [leaf(f"/f{i}", f"{i:02x}") for i in range(count)]
    tree = MerkleTree(leaves)
    for item in leaves:
        steps = tree.proof(item.path)
        assert verify_proof(item.hash().hex(), steps, tree.root)
        assert len(tree.path_to_root(item.path)) == len(tree.levels)
        if steps:
            forged = [dict(steps[0], hash="00" * 32)] + steps[1:]
            assert not verify_proof(item.hash().hex(), forged, tree.root)
    assert not verify_proof(leaf("/zz", "ff").hash().hex(), tree.proof("/f0"), tree.root)


def test_leaf_includes_metadata_and_unambiguous_paths():
    base = leaf("/a")
    assert base.hash() != Leaf("/a", "file", 0o100666, 0, 0, "aa" * 32, 1, 1, 1, 1).hash()
    assert base.hash() != Leaf("/a", "file", 0o100644, 1000, 0, "aa" * 32, 1, 1, 1, 1).hash()
    assert base.hash() != Leaf("/a", "symlink", 0o100644, 0, 0, "aa" * 32, 1, 1, 1, 1).hash()
    # Length prefixes: moving bytes between path and kind cannot give the same leaf.
    assert (
        Leaf("/ab", "file", 0, 0, 0, "", 1, 1, 1, 1).hash()
        != Leaf("/a", "bfile", 0, 0, 0, "", 1, 1, 1, 1).hash()
    )


@pytest.fixture
def lab(tmp_path):
    root = tmp_path / "lab"
    (root / "sub").mkdir(parents=True)
    for name in ("a.conf", "b.conf", "sub/c.conf"):
        (root / name).write_text(name)
        (root / name).chmod(0o644)
    (root / "noise.swp").write_text("x")
    outside = tmp_path / "outside.conf"
    outside.write_text("secret")
    (root / "link").symlink_to(outside)
    return root, outside


def verify(monitor, **kw):
    result, coverage = monitor.verify(**kw)
    return (
        {
            k: [i["path"] for i in result[k]]
            for k in ("added", "deleted", "modified", "metadata_changed")
        },
        result,
        coverage,
    )


def test_detects_file_creation_modification_deletion_and_metadata(lab):
    root, outside = lab
    settings = IntegritySettings()
    leaves, coverage = collect([str(root)], settings)
    paths = {item.path for item in leaves}
    assert str(root / "noise.swp") not in paths  # excluded volatile file
    assert {item.kind for item in leaves if item.path.endswith("link")} == {"symlink"}
    body = baseline_body([str(root)], leaves, coverage)
    monitor = IntegrityMonitor(settings, body)
    changes, result, _ = verify(monitor)
    assert result["root_matches"] and not any(changes.values())
    outside.write_text("changed outside the monitored directory")  # symlink is not followed
    assert verify(monitor)[1]["root_matches"]
    (root / "a.conf").write_text("modified")
    (root / "b.conf").unlink()
    (root / "new.conf").write_text("added")
    (root / "sub/c.conf").chmod(0o600)
    changes, result, _ = verify(monitor)
    assert changes["modified"] == [str(root / "a.conf")]
    assert changes["deleted"] == [str(root / "b.conf")]
    assert changes["added"] == [str(root / "new.conf")]
    assert changes["metadata_changed"] == [str(root / "sub/c.conf")]
    assert not result["root_matches"]
    assert result["modified"][0]["merkle_path_current"][-1] == result["current_root"]


def test_incremental_hashing_and_full_rehash(lab):
    root, _ = lab
    settings = IntegritySettings()
    leaves, coverage = collect([str(root)], settings)
    monitor = IntegrityMonitor(settings, baseline_body([str(root)], leaves, coverage))
    monitor.verify()
    assert monitor.hasher.reads == 0  # unchanged files are not re-read
    (root / "a.conf").write_text("modified")
    monitor.verify()
    assert monitor.hasher.reads == 1
    monitor.verify(full=True)
    assert monitor.hasher.reads == 1 + 3  # --full re-reads all three regular files


def test_large_and_unreadable_files(lab):
    root, _ = lab
    (root / "big.bin").write_bytes(b"x" * 100)
    leaves, coverage = collect([str(root)], IntegritySettings(max_file_bytes=50))
    kinds = {item.path.rsplit("/", 1)[-1]: item.kind for item in leaves}
    assert kinds["big.bin"] == "large"
    assert any(
        "does not exist" in note
        for note in collect(["/nonexistent-rte"], IntegritySettings())[1].unavailable
    )
    limited = collect([str(root)], IntegritySettings(max_files=2))[1]
    assert any("file limit" in note for note in limited.unavailable)
    if not ROOT_USER:
        (root / "a.conf").chmod(0)
        try:
            leaves, coverage = collect([str(root)], IntegritySettings())
            assert str(root / "a.conf") in coverage.denied
            assert {i.path: i.kind for i in leaves}[str(root / "a.conf")] == "unreadable"
        finally:
            (root / "a.conf").chmod(0o644)


def test_anchor_signing_and_baseline_replacement(lab):
    root, _ = lab
    leaves, coverage = collect([str(root)], IntegritySettings())
    body = baseline_body([str(root)], leaves, coverage)
    key = b"k" * 32
    manifest = export_manifest(body, key)
    assert check_anchor(manifest, key, body["root"])["signature_valid"] is True
    assert check_anchor(manifest, None, body["root"])["signature_valid"] is None
    assert check_anchor(manifest, b"wrong" * 8, body["root"])["signature_valid"] is False
    tampered = dict(manifest, root="00" * 32)
    assert check_anchor(tampered, key, body["root"])["signature_valid"] is False
    assert not check_anchor(manifest, key, "ff" * 32)["baseline_matches_anchor"]
    unsigned = export_manifest(body, None)
    assert "unsigned" in check_anchor(unsigned, key, body["root"])["signature"]


def test_live_module_statuses(lab):
    root, _ = lab
    settings = IntegritySettings(paths=[str(root)])
    assert IntegrityMonitor(settings, None).scan().status == "no-baseline"
    leaves, coverage = collect([str(root)], settings)
    monitor = IntegrityMonitor(settings, baseline_body([str(root)], leaves, coverage))
    (root / "a.conf").write_text("modified")
    report = monitor.scan()
    assert {f.rule_id for f in report.findings} == {"FI001"}
    assert report.summary["counts"]["modified"] == 1 and not report.summary["root_matches"]
    assert FileHasher(10).max_bytes == 10


def test_integrity_cli(lab, tmp_path, capsys):
    root, _ = lab
    run = ["--db", str(tmp_path / "e.db"), "integrity"]
    assert main(run + ["verify"]) == 3
    assert "no integrity baseline" in capsys.readouterr().err
    key, anchor = tmp_path / "key", tmp_path / "anchor.json"
    assert main(run + ["keygen", "--output", str(key)]) == 0
    assert oct(key.stat().st_mode & 0o777) == "0o600" and len(key.read_bytes()) == 32
    assert "Keep it off this host" in capsys.readouterr().out
    assert (
        main(
            run
            + [
                "baseline",
                "--path",
                str(root),
                "--export",
                str(anchor),
                "--key-file",
                str(key),
                "--json",
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["anchor_signed"] and json.loads(anchor.read_text())["root"] == created["root"]
    assert (
        main(run + ["baseline", "--path", str(root), "--export", str(anchor)]) == 1
    )  # no overwrite
    capsys.readouterr()
    (root / "a.conf").write_text("modified")
    assert main(run + ["verify", "--anchor", str(anchor), "--key-file", str(key), "--json"]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert [f["rule_id"] for f in verified["findings"]] == ["FI001"]
    assert verified["anchor"]["baseline_matches_anchor"] is True
    assert main(run + ["proof", "--file", str(root / "b.conf"), "--json"]) == 0
    proof = json.loads(capsys.readouterr().out)
    assert proof["verified"] and proof["matches_baseline_root"]
    assert main(run + ["proof", "--file", str(root / "a.conf"), "--baseline"]) == 0
    assert "MERKLE MEMBERSHIP PROOF" in capsys.readouterr().out
    assert main(run + ["proof", "--file", "/not/monitored"]) == 3
    # An attacker who can write the database replaces the baseline: the anchor catches it.
    assert main(run + ["baseline", "--path", str(root)]) == 0
    capsys.readouterr()
    assert main(run + ["verify", "--anchor", str(anchor), "--key-file", str(key), "--json"]) == 0
    replaced = json.loads(capsys.readouterr().out)
    assert replaced["root_matches"] is True  # the local check alone is fooled
    assert [(f["rule_id"], f["severity"]) for f in replaced["findings"]] == [("FI005", "HIGH")]
    assert main(run + ["show"]) == 0
    assert "BASELINE VS ANCHOR" in capsys.readouterr().out
    assert main(run + ["show", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["baseline"]["leaf_count"] == 4
    assert main(run + ["demo", "--json"]) == 0
    demo = json.loads(capsys.readouterr().out)
    assert demo["root_changed"] and demo["proof_modified_file_against_current_root"]
    assert not demo["proof_modified_file_against_baseline_root"]
    assert main(run + ["demo"]) == 0
    assert "temporary files only" in capsys.readouterr().out
