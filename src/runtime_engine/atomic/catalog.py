"""Read-only catalog of Linux Atomic Red Team tests with a conservative risk triage.

Used by `runtime-engine atomic` and by the lab script
`testing/atomic-red-team/scripts/catalog.py`, which re-exports this module.

Parses the official atomics YAML (never executes anything) and classifies each Linux
test from its actual attack, prerequisite and cleanup commands:

  A  SAFE FOR INITIAL TESTING  no elevation, prerequisites, cleanup, file writes,
                               network, sensitive reads or environment dumps found
  B  REQUIRES REVIEW           temporary files, sensitive paths, elevation, prerequisites,
                               cleanup, obfuscation, manual/PowerShell executors
  C  DESTRUCTIVE OR UNSAFE     persistence, credential access, privilege escalation,
                               impact, exfiltration, lateral movement, network transfer,
                               destructive or security-control changes

The triage is pattern-based and deliberately conservative. Class A is a shortlist for
human review, not an approval: always read -ShowDetails output before running a test.

Usage:
  catalog.py build [--atomics DIR] [--markdown FILE] [--json FILE]
  catalog.py show --guid GUID [--json]
  catalog.py list [--risk A|B|C] [--technique T1059.004]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

DEFAULT_ATOMICS = Path(os.environ.get("ATOMICS_PATH", Path.home() / "AtomicRedTeam" / "atomics"))
RISK_LABELS = {
    "A": "SAFE FOR INITIAL TESTING",
    "B": "REQUIRES REVIEW",
    "C": "DESTRUCTIVE OR UNSAFE",
}

# Technique families whose purpose is unsafe on a workstation, whatever the command looks like.
UNSAFE_TECHNIQUES = {
    "T1003": "credential dumping",
    "T1040": "network sniffing",
    "T1056": "input capture",
    "T1110": "brute force",
    "T1552": "unsecured credentials",
    "T1555": "credential stores",
    "T1557": "adversary-in-the-middle",
    "T1558": "Kerberos tickets",
    "T1037": "boot/logon scripts (persistence)",
    "T1053": "scheduled task/job (persistence)",
    "T1098": "account manipulation",
    "T1136": "create account",
    "T1543": "system process creation (persistence)",
    "T1546": "event-triggered execution (persistence)",
    "T1547": "autostart execution (persistence)",
    "T1548": "elevation control abuse (privilege escalation)",
    "T1554": "compromise host software binary",
    "T1556": "modify authentication process",
    "T1574": "hijack execution flow",
    "T1068": "exploitation for privilege escalation",
    "T1611": "escape to host",
    "T1014": "rootkit",
    "T1070": "indicator removal",
    "T1562": "impair defenses",
    "T1485": "data destruction",
    "T1486": "data encrypted for impact",
    "T1489": "service stop",
    "T1490": "inhibit system recovery",
    "T1491": "defacement",
    "T1495": "firmware corruption",
    "T1496": "resource hijacking",
    "T1499": "endpoint denial of service",
    "T1529": "system shutdown/reboot",
    "T1531": "account access removal",
    "T1561": "disk wipe",
    "T1565": "data manipulation",
    "T1020": "automated exfiltration",
    "T1030": "data transfer size limits (exfiltration)",
    "T1041": "exfiltration over C2",
    "T1048": "exfiltration over alternative protocol",
    "T1567": "exfiltration over web service",
    "T1105": "ingress tool transfer (downloads)",
    "T1071": "application layer protocol (C2)",
    "T1090": "proxy",
    "T1095": "non-application layer protocol",
    "T1572": "protocol tunneling",
    "T1219": "remote access software",
    "T1021": "remote services (lateral movement)",
    "T1570": "lateral tool transfer",
}

UNSAFE_PATTERNS = [
    (r"\brm\s+-\w*[rR]\w*f|\brm\s+-\w*f\w*[rR]", "recursive forced delete"),
    (r"\bdd\s+if=|\bmkfs|\bshred\b|\bwipefs\b", "disk or file destruction"),
    (r"\b(shutdown|reboot|halt|poweroff)\b", "power state change"),
    (r"\bcrontab\b|/etc/cron", "cron persistence"),
    (
        r"\bsystemctl\s+(--user\s+)?(enable|disable|start|stop|mask|restart|daemon-reload)",
        "service change",
    ),
    (
        r"\b(useradd|userdel|usermod|adduser|deluser|passwd|chpasswd|chsh|groupadd|visudo)\b",
        "account change",
    ),
    (r"/etc/(shadow|gshadow|sudoers)", "credential or sudo configuration access"),
    (
        r"\b(iptables|ip6tables|nft|ufw|setenforce|auditctl|aa-disable|apparmor_parser)\b",
        "security control change",
    ),
    (r"\b(insmod|modprobe|rmmod)\b", "kernel module change"),
    (
        r"history\s+-c|unset\s+HISTFILE|HISTFILE=|/var/log/\S*\s*$|>\s*/var/log",
        "log or history tampering",
    ),
    (r"ld\.so\.preload|LD_PRELOAD", "loader hijacking"),
    (r"authorized_keys|\.ssh/", "SSH key access"),
    (
        r"\.bashrc|\.bash_profile|\.zshrc|(^|\s)~?/?\.profile|/etc/profile|rc\.local",
        "shell startup persistence",
    ),
    (r"chmod\s+[ugoa]*\+s|chmod\s+[2467][0-7]{3}\b|\bsetcap\b", "setuid/capability change"),
    (
        r"\b(nc|ncat|netcat|socat|ssh|scp|sftp|ftp|tftp|telnet|nmap|masscan|hping3)\b",
        "network tool",
    ),
    (r"\b(curl|wget)\b", "network download/upload"),
    (r"/dev/tcp/|/dev/udp/", "raw socket shell redirection"),
    (r"http\.server|SimpleHTTPServer", "network listener"),
    (r"\b(kill|pkill|killall)\b", "process termination"),
    (
        r"(?i)\b(xmrig|mimipenguin|lazagne|linpeas|linenum|pspy|metasploit|msfvenom|sliver)\b",
        "offensive tooling",
    ),
    (r"\b(docker|podman|kubectl|ctr)\b", "container runtime access"),
    (r"\bchattr\b", "immutable attribute change"),
    (
        r"\b(cpan|pip3?|gem|npm|apt-get|apt|snap|dnf|yum)\b",
        "package manager (installs or fetches over network)",
    ),
    (r"/proc/\S*/mem|\bgdb\b|ptrace", "process memory access"),
    (r">\s*/dev/(sd|nvme|mmc)", "raw disk write"),
]

REVIEW_PATTERNS = [
    (r"(?<![0-9&<])>>?\s*(?!/dev/null\b|&)", "writes a file (shell redirection)"),
    (r"\btee\b", "writes a file (tee)"),
    (
        r"\b(cp|mv|mkdir|touch|ln|chmod|chown|mktemp|install|tar|zip|gzip|gunzip|unzip|split)\b",
        "creates or changes files",
    ),
    (r"/tmp\b|/var/tmp|/dev/shm", "uses a temporary location"),
    (
        r"/etc/(passwd|group|hosts|resolv\.conf|ssh)|\.bash_history|/root\b|/home/",
        "reads sensitive or personal paths",
    ),
    (r"(^|[;&|\s])(env|printenv)\b|\bset\s*$", "dumps environment variables (may expose secrets)"),
    (r"\bfind\s+[/.~$]|\blocate\b|\bls\s+-\w*R", "broad filesystem enumeration"),
    (r"https?://", "references a URL"),
    (r"\b(base64|xxd|openssl|gpg)\b", "encoding, obfuscation or crypto"),
    (
        r"\b(ping|dig|nslookup|host|arp|ss|netstat|ip\s+route|traceroute)\b",
        "network discovery traffic or state",
    ),
    (r"\b(gcc|cc|make|python3?|perl|ruby|php|node|java)\b", "runs a compiler or interpreter"),
    (r"\bsudo\b|\bsu\s", "requires elevated privileges"),
    (r"(?<![&>|])&(?![&>\d])", "starts a background process that can outlive the test"),
    (r"\bsystem\s*\(|\bexec\s+[\"']?/bin/", "spawns a shell from another program"),
    (r"\b(lsof|ps\s+-?\w*e|ps\s+aux)\b", "enumerates other users' processes or files"),
    (r"#\{[^}]*\}", "uses input arguments (review defaults)"),
]

SHELL_WORDS = {
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "for",
    "do",
    "done",
    "while",
    "until",
    "case",
    "esac",
    "[",
    "[[",
    "]",
    "]]",
    "!",
    "{",
    "}",
    "in",
    "export",
    "local",
    "true",
    "false",
    "test",
    "echo",
    "printf",
    "cd",
    "exit",
    "return",
    "unset",
    "eval",
    "exec",
    "read",
}


@dataclass
class AtomicTest:
    technique: str
    technique_name: str
    number: int
    name: str
    guid: str
    description: str
    platforms: list[str]
    executor: str
    elevation_required: bool
    command: str
    cleanup: str
    dependencies: list[dict[str, str]]
    input_arguments: dict[str, dict[str, object]]
    risk: str = "A"
    reasons: list[str] = field(default_factory=list)
    programs: list[str] = field(default_factory=list)
    observable: str = ""
    engine_rules: list[str] = field(default_factory=list)
    missing_tools: list[str] = field(default_factory=list)

    @property
    def suitable(self) -> str:
        """Suitability for this machine: risk class plus whether the tools exist here."""
        if self.risk == "C":
            return "no"
        if self.missing_tools:
            return "no: not installed here: " + ", ".join(self.missing_tools)
        return "yes, after reading details" if self.risk == "A" else "only after review"

    @property
    def rendered_command(self) -> str:
        return render(self.command, self.input_arguments)

    @property
    def rendered_cleanup(self) -> str:
        return render(self.cleanup, self.input_arguments)


def render(
    text: str,
    arguments: dict[str, dict[str, object]],
    overrides: dict[str, str] | None = None,
    atomics: Path | None = None,
) -> str:
    """Substitute #{arg} with the YAML default (or a reviewed override), as -ShowDetails does.

    With `atomics`, `PathToAtomicsFolder` is replaced like Invoke-AtomicTest does.
    """
    for name, spec in arguments.items():
        value = (overrides or {}).get(name, spec.get("default", ""))
        text = text.replace("#{" + name + "}", str(value))
    if atomics is not None:
        text = text.replace("PathToAtomicsFolder", str(atomics))
    return text


def programs(command: str) -> list[str]:
    """First word of each simple command; a rough guide to expected PROCESS_START events."""
    found: list[str] = []
    unquoted = re.sub(r"'[^']*'|\"[^\"]*\"", " ", command)
    for segment in re.split(r"[;\n|&()`]+|\$\(", unquoted):
        words = segment.strip().split()
        while words and words[0] in ("if", "then", "else", "elif", "do", "while", "until", "!"):
            words = words[1:]
        if not words or words[0] in ("for", "[", "[[", "test", "case", "unset", "export", "local"):
            continue
        while words and (words[0] in SHELL_WORDS or "=" in words[0] or words[0].startswith("-")):
            words = words[1:]
        if words:
            word = words[0] if words[0].startswith("/") else os.path.basename(words[0])
            if (
                re.fullmatch(r"/?[A-Za-z][A-Za-z0-9_.+/-]*", word)
                and word not in SHELL_WORDS
                and word not in found
            ):
                found.append(word)
    return found


def classify(test: AtomicTest) -> None:
    text = "\n".join(
        [test.rendered_command, test.rendered_cleanup]
        + [
            d.get("get_prereq_command", "") + "\n" + d.get("prereq_command", "")
            for d in test.dependencies
        ]
    )
    reasons: list[str] = []
    family = test.technique.split(".")[0]
    if family in UNSAFE_TECHNIQUES:
        reasons.append(f"technique family {family}: {UNSAFE_TECHNIQUES[family]}")
    for pattern, reason in UNSAFE_PATTERNS:
        if re.search(pattern, text, re.MULTILINE) and reason not in reasons:
            reasons.append(reason)
    if reasons:
        test.risk, test.reasons = "C", reasons
        return
    if test.elevation_required:
        reasons.append("elevation_required: true (must run as root)")
    if test.dependencies:
        reasons.append(
            f"{len(test.dependencies)} prerequisite(s); get_prereq may install or download"
        )
    if test.cleanup.strip():
        reasons.append("has cleanup command (changes state that must be reverted)")
    if test.executor not in ("sh", "bash"):
        reasons.append(f"executor '{test.executor}' (not a plain shell)")
    for pattern, reason in REVIEW_PATTERNS:
        if re.search(pattern, text, re.MULTILINE) and reason not in reasons:
            reasons.append(reason)
    test.risk, test.reasons = (
        ("B", reasons)
        if reasons
        else ("A", ["read-only commands, no writes, network, elevation or prerequisites found"])
    )


def engine_view(test: AtomicTest) -> None:
    """What the current engine could observe, from its actual collectors and rules."""
    command = test.rendered_command
    test.programs = programs(command)
    long_lived = re.search(r"\bsleep\s+([2-9]|\d{2,})", command) is not None or (
        re.search(r"\b(for|while)\b", command) is not None and "sleep" in command
    )
    notes = [
        "PROCESS_START via /proc polling"
        + (
            " (a process lives >= 2 s, so likely observed)"
            if long_lived
            else " (short-lived; may be missed between polls)"
        )
    ]
    if re.search(REVIEW_PATTERNS[0][0], command) or re.search(
        r"\b(cp|mv|touch|tee|mkdir)\b", command
    ):
        notes.append("file writes: not collected live")
    if re.search(r"https?://|\b(curl|wget|nc|ssh|ping)\b", command):
        notes.append("network: not collected live")
    if test.elevation_required or re.search(r"\bsudo\b|\bsu\s", command):
        notes.append("privilege change: not collected live")
    test.observable = "; ".join(notes)
    rules: list[str] = []
    if re.search(r"(/tmp|/var/tmp|/dev/shm)/\S+", command) and re.search(
        r"(^|[|;&\s])(/tmp|/var/tmp|/dev/shm)/\S+", command
    ):
        rules.append("RT002 (exec from temp path, live)")
    if re.search(r"\b(curl|wget)\b", command):
        rules.append("RT005 (transfer tool from shell, live)")
    if "/etc/shadow" in command or "/etc/gshadow" in command:
        rules.append("RT003 (needs FILE_ACCESS: replay only)")
    test.engine_rules = rules
    builtins = SHELL_WORDS | {"seq", "sleep", "cat", "grep", "ls", "id", "date", "whoami"}
    test.missing_tools = [
        p
        for p in test.programs
        if p not in builtins and not p.startswith("/") and shutil.which(p) is None
    ]


def load(atomics: Path) -> list[AtomicTest]:
    tests: list[AtomicTest] = []
    for path in sorted(atomics.glob("T*/T*.yaml")):
        tests += parse_file(path)
    return tests


TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


def find_test(atomics: Path, technique: str, number: int) -> AtomicTest | None:
    """One Linux test by technique and its 1-based position in the official YAML."""
    technique = technique.upper()
    if not TECHNIQUE_ID.match(technique):
        raise ValueError(f"not an ATT&CK technique ID: {technique!r}")
    path = atomics / technique / f"{technique}.yaml"
    if not path.is_file():
        return None
    return next((t for t in parse_file(path) if t.number == number), None)


def parse_file(path: Path) -> list[AtomicTest]:
    tests: list[AtomicTest] = []
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for number, raw in enumerate(data.get("atomic_tests", []), 1):
        if "linux" not in raw.get("supported_platforms", []):
            continue
        executor = raw.get("executor", {})
        test = AtomicTest(
            technique=data["attack_technique"],
            technique_name=data.get("display_name", ""),
            number=number,
            name=raw["name"],
            guid=raw["auto_generated_guid"],
            description=" ".join(str(raw.get("description", "")).split()),
            platforms=raw.get("supported_platforms", []),
            executor=executor.get("name", "?"),
            elevation_required=bool(executor.get("elevation_required", False)),
            command=str(executor.get("command") or executor.get("steps") or ""),
            cleanup=str(executor.get("cleanup_command") or ""),
            dependencies=[
                {k: str(v) for k, v in d.items()} for d in raw.get("dependencies", []) or []
            ],
            input_arguments=raw.get("input_arguments", {}) or {},
        )
        classify(test)
        engine_view(test)
        tests.append(test)
    return tests


def atomics_commit(atomics: Path) -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(atomics.parent), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def mitre_url(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"


def cell(text: object, limit: int = 0) -> str:
    value = " ".join(str(text).split()).replace("|", "\\|")
    return value if not limit or len(value) <= limit else value[: limit - 3] + "..."


def markdown(tests: list[AtomicTest], atomics: Path) -> str:
    counts = Counter(t.risk for t in tests)
    lines = (
        [
            "# Linux Atomic Red Team test catalog",
            "",
            "Generated by `scripts/catalog.py build` from the official",
            "[redcanaryco/atomic-red-team](https://github.com/redcanaryco/atomic-red-team) atomics",
            f"at commit `{atomics_commit(atomics)}`. Nothing was executed to build it.",
            "",
            f"Linux-capable tests: **{len(tests)}** in "
            f"**{len({t.technique for t in tests})}** techniques.",
            "",
            "| Risk class | Tests |",
            "|---|---:|",
        ]
        + [f"| {k} {RISK_LABELS[k]} | {counts.get(k, 0)} |" for k in "ABC"]
        + [
            "",
            "The classification is an automated, conservative triage of the actual attack,",
            "prerequisite and cleanup commands (see `scripts/catalog.py` for every pattern).",
            "Class A only means no risky pattern was found: read the full `-ShowDetails` output",
            "before running any test. Classes B and C are never run automatically by",
            "`run_atomic_test.ps1`; class C is refused outright.",
            "",
            "Engine observability uses the current collectors: only `PROCESS_START` is collected",
            "live, by `/proc` polling every 2 s. File, network and privilege events are not",
            "collected live, so rules RT003/RT004/RT006 can only fire on replayed telemetry.",
            "",
            "Columns: privileges (`user`/`root`), prerequisites (count), cleanup (yes/no),",
            "observable = expected engine telemetry, engine rules = rules that could match,",
            "suitable = suitable for this workstation without further review.",
            "",
            "| Risk | Technique | # | Test name | GUID | Exec | Priv | Prereq | Cleanup "
            "| Expected behaviour | Programs started | Observable by engine | Engine rules "
            "| Suitable | Triage reasons |",
            "|---|---|---:|---|---|---|---|---:|---|---|---|---|---|---|---|",
        ]
    )
    order = {"A": 0, "B": 1, "C": 2}
    for t in sorted(tests, key=lambda t: (order[t.risk], t.technique, t.number)):
        lines.append(
            "| "
            + " | ".join(
                [
                    t.risk,
                    f"[{t.technique}]({mitre_url(t.technique)})",
                    str(t.number),
                    cell(t.name, 70),
                    f"`{t.guid}`",
                    t.executor,
                    "root" if t.elevation_required else "user",
                    str(len(t.dependencies)),
                    "yes" if t.cleanup.strip() else "no",
                    cell(t.description, 110),
                    cell(", ".join(t.programs[:8]), 60),
                    cell(t.observable, 90),
                    cell(", ".join(t.engine_rules) or "-", 60),
                    cell(t.suitable, 60),
                    cell("; ".join(t.reasons), 160),
                ]
            )
            + " |"
        )
    return "\n".join(lines) + "\n"


def summary(test: AtomicTest) -> dict[str, object]:
    data = asdict(test)
    data.update(
        risk_label=RISK_LABELS[test.risk],
        rendered_command=test.rendered_command,
        rendered_cleanup=test.rendered_cleanup,
    )
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--atomics", type=Path, default=DEFAULT_ATOMICS)
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build")
    build.add_argument("--markdown", type=Path)
    build.add_argument("--json", type=Path)
    show = sub.add_parser("show")
    show.add_argument("--guid", required=True)
    show.add_argument("--json", action="store_true")
    listing = sub.add_parser("list")
    listing.add_argument("--risk", choices=list("ABC"))
    listing.add_argument("--technique")
    args = parser.parse_args(argv)
    if not args.atomics.is_dir():
        print(f"error: atomics folder not found: {args.atomics}", file=sys.stderr)
        return 1
    tests = load(args.atomics)
    if args.command == "build":
        if args.markdown:
            args.markdown.write_text(markdown(tests, args.atomics), encoding="utf-8")
        if args.json:
            args.json.write_text(
                json.dumps([summary(t) for t in tests], indent=2), encoding="utf-8"
            )
        counts = Counter(t.risk for t in tests)
        print(
            f"{len(tests)} Linux tests in {len({t.technique for t in tests})} techniques: "
            + ", ".join(f"{k} {RISK_LABELS[k]}={counts.get(k, 0)}" for k in "ABC")
        )
        return 0
    if args.command == "show":
        match = [t for t in tests if t.guid == args.guid.lower()]
        if not match:
            print(f"error: no Linux test with GUID {args.guid}", file=sys.stderr)
            return 3
        test = match[0]
        if args.json:
            print(json.dumps(summary(test), indent=2))
            return 0
        print(f"RISK CLASS     : {test.risk} - {RISK_LABELS[test.risk]}")
        for reason in test.reasons:
            print(f"  - {reason}")
        privileges = "root (elevation_required)" if test.elevation_required else "normal user"
        print(f"PRIVILEGES     : {privileges}")
        print(f"PREREQUISITES  : {len(test.dependencies)}")
        for dep in test.dependencies:
            print(f"  - {dep.get('description', '').strip()}")
            print(f"      check : {dep.get('prereq_command', '').strip()}")
            print(f"      get   : {dep.get('get_prereq_command', '').strip()}")
        print(f"SUITABLE HERE  : {test.suitable}")
        print(f"ENGINE VIEW    : {test.observable}")
        rules = ", ".join(test.engine_rules) or "none of the current rules is expected to match"
        print(f"ENGINE RULES   : {rules}")
        return 0
    for test in tests:
        if (args.risk and test.risk != args.risk) or (
            args.technique and test.technique != args.technique
        ):
            continue
        note = "" if test.suitable.startswith(("yes", "only")) else f"  [{test.suitable}]"
        print(f"{test.risk}  {test.technique:<10} #{test.number:<3} {test.guid}  {test.name}{note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
