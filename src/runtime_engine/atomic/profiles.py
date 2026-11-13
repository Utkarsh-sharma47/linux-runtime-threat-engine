"""Reviewed expectation profiles: what the engine should observe for one Atomic test.

Profiles live in `testing/atomic-red-team/expectations.yaml`, keyed by test GUID. The
original keys (key_processes, expected_rules, telemetry, cleanup_paths, rationale) are
still read by the lab's PowerShell runner; the offline evaluation adds optional keys. A
test without a profile is always graded INCONCLUSIVE: relevance needs a human review.
"""

import os
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

LAB_ROOT = "/tmp/rte-atomic-lab"
MODULE_PATH_KEYS = (
    "persistence.privileged_dirs",
    "persistence.sensitive_exec_dirs",
    "exposure.suid_paths",
    "integrity.paths",
)
COMPONENTS = ("rules", "persistence", "network", "anomaly", "integrity", "exposure", "ransomware")
DEFAULT_PATH = Path("testing/atomic-red-team/expectations.yaml")
ARGUMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class ModuleExpectation(BaseModel):
    """`rules: []` means the module applies but no current rule is expected to match."""

    model_config = ConfigDict(extra="forbid")
    rules: list[str] = Field(default_factory=list)
    requires_readable: list[str] = Field(default_factory=list)
    note: str = ""


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique: str
    name: str
    key_processes: list[str] = Field(default_factory=list)
    expected_rules: list[str] = Field(default_factory=list)
    telemetry: list[str] = Field(default_factory=lambda: ["PROCESS_START"])
    cleanup_paths: list[str] = Field(default_factory=list)
    rationale: str = ""
    # Offline evaluation (all optional).
    input_args: dict[str, str] = Field(default_factory=dict)
    reviewed_risk: Literal["A", "B"] | None = None
    review_note: str = ""
    environment: Literal["workstation", "isolated-vm"] = "workstation"
    cleanup_safe: bool = True
    cleanup_note: str = ""
    watch_integrity: list[str] = Field(default_factory=list)
    watch_ransomware: list[str] = Field(default_factory=list)
    # Lab-only test targets created by the workflow (never by the test's prerequisites).
    fixtures: dict[str, str] = Field(default_factory=dict)
    # Reviewed additions to module configuration for this run, e.g. the lab directory.
    module_paths: dict[str, list[str]] = Field(default_factory=dict)
    benign: bool = False
    modules: dict[str, ModuleExpectation] = Field(default_factory=dict)

    @field_validator("input_args")
    @classmethod
    def argument_names(cls, value: dict[str, str]) -> dict[str, str]:
        for name in value:
            if not ARGUMENT.match(name):
                raise ValueError(f"invalid input argument name {name!r}")
        return {k: str(v) for k, v in value.items()}

    @field_validator("fixtures")
    @classmethod
    def lab_fixtures(cls, value: dict[str, str]) -> dict[str, str]:
        for path in value:
            normalized = os.path.normpath(path)
            if not normalized.startswith(LAB_ROOT + "/") or normalized != path:
                raise ValueError(f"fixtures must be normalized paths under {LAB_ROOT}/: {path}")
        return value

    @field_validator("module_paths")
    @classmethod
    def known_module_paths(cls, value: dict[str, list[str]]) -> dict[str, list[str]]:
        unknown = set(value) - set(MODULE_PATH_KEYS)
        if unknown:
            raise ValueError(f"module_paths keys must be among {MODULE_PATH_KEYS}: {unknown}")
        return value

    @field_validator("modules")
    @classmethod
    def known_components(cls, value: dict[str, ModuleExpectation]) -> dict[str, ModuleExpectation]:
        unknown = set(value) - set(COMPONENTS)
        if unknown:
            raise ValueError(f"unknown components: {sorted(unknown)}")
        return value

    def expectations(self) -> dict[str, ModuleExpectation]:
        """Per-component expectations; older profiles only describe the rule engine."""
        if self.modules:
            return self.modules
        return {"rules": ModuleExpectation(rules=self.expected_rules)}

    def risk_for(self, overrides: dict[str, str]) -> str | None:
        """The reviewed risk class, valid only with exactly the reviewed input arguments."""
        if self.reviewed_risk is None or overrides != self.input_args:
            return None
        return self.reviewed_risk


def load_profiles(path: Path | None = None) -> dict[str, Profile]:
    path = path or DEFAULT_PATH
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping of test GUIDs to profiles")
    return {str(guid).lower(): Profile.model_validate(body) for guid, body in raw.items()}


def parse_overrides(pairs: list[str]) -> dict[str, str]:
    """`name=value` command-line pairs for reviewed Atomic input arguments."""
    result: dict[str, str] = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if not sep or not ARGUMENT.match(name):
            raise ValueError(f"input arguments must look like name=value, got {pair!r}")
        result[name] = value
    return result
