"""Lab-scoped detection rules: avoid ambient laptop noise becoming incidents.

Default RT002 matches any executable under /tmp. On a real workstation that fires
constantly (browsers, Electron apps, GitHub Desktop, etc.). Lab demos only care about
binaries under the isolated security-lab tree.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from runtime_engine.detection.rule_loader import load_rules
from runtime_engine.lab.paths import lab_root, ransomware_lab_path


def lab_rule_roots(session: Path, *, ransomware_dir: Path | None = None) -> list[str]:
    """Absolute path roots RT002 (and similar) may match during a lab session."""
    ransom = ransomware_dir or ransomware_lab_path(session.name)
    roots = [str(lab_root()), str(session), str(ransom)]
    # Preserve order, drop duplicates.
    seen: set[str] = set()
    ordered: list[str] = []
    for root in roots:
        if root not in seen:
            seen.add(root)
            ordered.append(root)
    return ordered


def write_lab_rules(
    session: Path,
    path: Path | None = None,
    *,
    ransomware_dir: Path | None = None,
) -> Path:
    """Write a YAML rules file derived from bundled defaults with lab-scoped RT002."""
    out = path or (session / "lab-rules.yaml")
    roots = lab_rule_roots(session, ransomware_dir=ransomware_dir)
    rules = [rule.model_dump(mode="json") for rule in load_rules()]
    for rule in rules:
        if rule.get("rule_id") != "RT002":
            continue
        for condition in rule.get("conditions") or []:
            if condition.get("field") == "executable_path" and condition.get("op") == "path_under":
                condition["value"] = roots
        rule["description"] = (
            "Executable image is under the isolated security-lab tree "
            "(not every process under /tmp on the laptop)."
        )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(rules, sort_keys=False), encoding="utf-8")
    out.chmod(0o600)
    return out


__all__ = ["lab_rule_roots", "write_lab_rules"]
