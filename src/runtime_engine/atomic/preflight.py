"""Stage A: validate the installation and the selected test before anything runs.

Nothing here executes the test, its prerequisites or its cleanup. The result lists every
reason to refuse, warnings the operator must read, and the exact rendered commands.
"""

import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from runtime_engine.atomic.catalog import (
    RISK_LABELS,
    AtomicTest,
    atomics_commit,
    find_test,
    mitre_url,
    programs,
    render,
)
from runtime_engine.atomic.profiles import Profile
from runtime_engine.security.fsutil import file_capabilities

DEFAULT_ATOMICS = Path(os.environ.get("ATOMICS_PATH", Path.home() / "AtomicRedTeam" / "atomics"))
MODULE_NAME = "invoke-atomicredteam"


@dataclass
class Environment:
    atomics: str
    atomics_present: bool
    atomics_commit: str
    pwsh: str | None
    module_version: str | None
    strace: str | None
    ptrace_scope: int | None
    virtualization: str
    uid: int

    @property
    def tracing(self) -> bool:
        return self.strace is not None and self.ptrace_scope is not None and self.ptrace_scope <= 1


@dataclass
class Preflight:
    environment: Environment
    test: AtomicTest | None
    profile: Profile | None
    overrides: dict[str, str]
    command: str = ""
    cleanup: str = ""
    risk: str = "C"
    risk_source: str = "automatic triage"
    refusals: list[str] = field(default_factory=list)
    review_flags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    setuid_programs: list[str] = field(default_factory=list)

    @property
    def token(self) -> str:
        """What the operator types (or passes to --approve) to execute exactly this test."""
        if self.test is None:
            return ""
        guid = self.test.guid
        return guid[:8] if re.match(r"^[0-9a-f]{8}-", guid) else guid

    def as_dict(self) -> dict[str, Any]:
        test = self.test
        return {
            "environment": vars(self.environment) | {"tracing": self.environment.tracing},
            "test": None
            if test is None
            else {
                "technique": test.technique,
                "technique_name": test.technique_name,
                "mitre_url": mitre_url(test.technique),
                "number": test.number,
                "name": test.name,
                "guid": test.guid,
                "description": test.description,
                "executor": test.executor,
                "elevation_required": test.elevation_required,
                "prerequisites": test.dependencies,
                "input_arguments": test.input_arguments,
                "triage_risk": test.risk,
                "triage_reasons": test.reasons,
            },
            "overrides": self.overrides,
            "command": self.command,
            "cleanup": self.cleanup,
            "risk": self.risk,
            "risk_label": RISK_LABELS.get(self.risk, "?"),
            "risk_source": self.risk_source,
            "profile": self.profile.model_dump() if self.profile else None,
            "refusals": self.refusals,
            "review_flags": self.review_flags,
            "warnings": self.warnings,
            "setuid_programs": self.setuid_programs,
            "approval_token": self.token,
        }


def run_quiet(argv: list[str], timeout: float = 20) -> str | None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def environment(atomics: Path, *, probe_module: bool = True) -> Environment:
    pwsh = shutil.which("pwsh")
    version = None
    if pwsh and probe_module:
        query = f"(Get-Module -ListAvailable {MODULE_NAME} | Select-Object -First 1).Version"
        version = (
            run_quiet(
                [
                    pwsh,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    query + ".ToString()",
                ]
            )
            or None
        )
    try:
        scope: int | None = int(Path("/proc/sys/kernel/yama/ptrace_scope").read_text())
    except (OSError, ValueError):
        scope = 0 if Path("/proc/self").exists() else None  # no Yama: classic ptrace rules
    virt = run_quiet(["systemd-detect-virt"]) if shutil.which("systemd-detect-virt") else None
    return Environment(
        atomics=str(atomics),
        atomics_present=atomics.is_dir(),
        atomics_commit=atomics_commit(atomics) if atomics.is_dir() else "unknown",
        pwsh=pwsh,
        module_version=version,
        strace=shutil.which("strace"),
        ptrace_scope=scope,
        virtualization=virt or "none",
        uid=os.getuid(),
    )


def privileged_helpers(command: str) -> list[str]:
    """Programs in the command that are set-ID or carry file capabilities."""
    found = []
    for name in programs(command):
        path = name if name.startswith("/") else shutil.which(name)
        if not path:
            continue
        try:
            mode = os.stat(path).st_mode
        except OSError:
            continue
        if mode & (stat.S_ISUID | stat.S_ISGID) or file_capabilities(path):
            found.append(path)
    return sorted(set(found))


def check(
    env: Environment,
    technique: str,
    number: int,
    profiles: dict[str, Profile],
    overrides: dict[str, str] | None = None,
    *,
    allow_review_required: bool = False,
    isolated_vm: bool = False,
    prereqs_reviewed: bool = False,
) -> Preflight:
    overrides = dict(overrides or {})
    result = Preflight(env, None, None, overrides)
    if env.uid == 0:
        result.refusals.append("running as root: the workflow never runs Atomic tests as root")
    if not env.atomics_present:
        result.refusals.append(f"atomics folder not found: {env.atomics} (see install.md)")
        return result
    test = find_test(Path(env.atomics), technique, number)
    if test is None:
        result.refusals.append(f"no Linux Atomic test {technique.upper()} #{number}")
        return result
    result.test = test
    profile = profiles.get(test.guid)
    result.profile = profile
    unknown = sorted(set(overrides) - set(test.input_arguments))
    if unknown:
        result.refusals.append(f"unknown input arguments for this test: {', '.join(unknown)}")
    atomics = Path(env.atomics)
    result.command = render(test.command, test.input_arguments, overrides, atomics)
    result.cleanup = render(test.cleanup, test.input_arguments, overrides, atomics)
    reviewed = profile.risk_for(overrides) if profile else None
    if reviewed is not None and profile is not None:
        result.risk, result.risk_source = reviewed, f"reviewed profile: {profile.review_note}"
    else:
        result.risk = test.risk
        if profile and profile.reviewed_risk and overrides != profile.input_args:
            result.warnings.append(
                "the profile's reviewed risk only applies with its reviewed input arguments "
                f"{profile.input_args}; automatic triage is used instead"
            )
    result.review_flags = list(test.reasons)
    if not env.pwsh:
        result.refusals.append("pwsh not found (see testing/atomic-red-team/install.md)")
    elif env.module_version is None:
        result.refusals.append(f"PowerShell module {MODULE_NAME} is not installed")
    if test.elevation_required:
        result.refusals.append(
            "the test requires root (elevation_required); this workflow never elevates. "
            "Run it only in an isolated VM, manually, after a separate review"
        )
    if test.dependencies and not prereqs_reviewed:
        result.refusals.append(
            "the test has prerequisites; they are never run automatically. Review them, satisfy "
            "them yourself if acceptable, then pass --prereqs-reviewed"
        )
    if result.risk == "C":
        if env.virtualization == "none" or not isolated_vm:
            result.refusals.append(
                "risk class C (destructive, persistence or unsafe): only allowed inside a "
                f"detected virtual machine with --isolated-vm (detected: {env.virtualization})"
            )
    elif result.risk == "B" and not allow_review_required:
        result.refusals.append(
            "risk class B: read the commands and cleanup above, then pass --allow-review-required"
        )
    if profile is None:
        result.warnings.append(
            "no reviewed expectation profile: the run will be graded INCONCLUSIVE "
            "(add one to testing/atomic-red-team/expectations.yaml)"
        )
    elif profile.environment == "isolated-vm" and env.virtualization == "none":
        result.refusals.append("the profile requires an isolated VM for this test")
    if profile is not None and not profile.cleanup_safe:
        result.warnings.append(f"cleanup reviewed as UNSAFE: {profile.cleanup_note}")
    if not env.tracing:
        result.warnings.append(
            "strace tracing unavailable (not installed or ptrace_scope > 1): only /proc polling "
            "will be used; short-lived processes, file and network activity will be missing"
        )
    result.setuid_programs = privileged_helpers(result.command)
    if result.setuid_programs and env.tracing:
        result.warnings.append(
            "set-ID/capability programs run WITHOUT their privileges when traced, so the test "
            "may not behave as it would untraced: " + ", ".join(result.setuid_programs)
        )
    return result
