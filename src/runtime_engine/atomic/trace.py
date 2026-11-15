"""Process-tree telemetry from strace, converted into the engine's replay events.

strace starts the Atomic runner as its own child, which a normal user may trace under
`kernel.yama.ptrace_scope` 0 or 1, and records system calls of every process and thread in
that tree while the test runs. These are events captured *during* execution, with exact
parent/child links from fork and clone return values.

What it does not see: processes outside the traced tree (a cron daemon or systemd running
installed persistence later), anything before strace attached, and the contents of data
written or sent (`write`, `send*` are not traced, so payloads are never recorded). Under
ptrace, set-user-ID and file-capability programs run WITHOUT their extra privileges, so
tests that rely on `sudo`, `crontab` or similar helpers behave differently when traced.
"""

import json
import os
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SYSCALLS = (
    "execve", "execveat", "fork", "vfork", "clone", "clone3", "open", "openat", "creat",
    "rename", "renameat", "renameat2", "unlink", "unlinkat", "chmod", "fchmod", "fchmodat",
    "chown", "fchown", "lchown", "fchownat", "mkdir", "mkdirat", "symlink", "symlinkat",
    "link", "linkat", "truncate", "connect", "setuid", "setreuid", "setresuid", "setgid",
    "setregid", "setresgid",
)  # fmt: skip
WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
NOISE_PREFIXES = ("/dev/null", "/dev/tty", "/dev/pts/", "/dev/urandom", "/dev/random", "/proc/",
                  "/sys/", "pipe:", "socket:", "anon_inode:")  # fmt: skip
SENSITIVE_READS = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/", "/root/")
SENSITIVE_PARTS = ("/.ssh/",)
MODIFYING = {
    "rename": "rename", "renameat": "rename", "renameat2": "rename", "unlink": "delete",
    "unlinkat": "delete", "chmod": "chmod", "fchmod": "chmod", "fchmodat": "chmod",
    "chown": "chown", "fchown": "chown", "lchown": "chown", "fchownat": "chown",
    "mkdir": "mkdir", "mkdirat": "mkdir", "symlink": "symlink", "symlinkat": "symlink",
    "link": "link", "linkat": "link", "truncate": "truncate", "creat": "create",
}  # fmt: skip
PRIVILEGE_CALLS = {"setuid", "setreuid", "setresuid", "setgid", "setregid", "setresgid"}

LINE = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(.*)$")
RESULT = re.compile(r"^(-?\d+|\?|0x[0-9a-fA-F]+)(<.*>)?(?:\s+(E[A-Z0-9]+)\s*\(.*\))?\s*$")
DIRFD = re.compile(r"^(AT_FDCWD|-?\d+)(?:<([^>]*)>)?")
INET = re.compile(
    r"sa_family=AF_INET,\s*sin_port=htons\((\d+)\),\s*sin_addr=inet_addr\(\"([^\"]+)\"\)"
)
INET6 = re.compile(
    r"sa_family=AF_INET6,\s*sin6_port=htons\((\d+)\).*?inet_pton\(AF_INET6,\s*\"([^\"]+)\""
)
OPEN_FLAGS = re.compile(r"(O_[A-Z_]+(?:\|(?:O_[A-Z_]+|0x[0-9a-fA-F]+))*)")
FD_KIND = re.compile(r"^\d+<(TCP|UDP|TCPv6|UDPv6|UNIX-STREAM|UNIX-DGRAM|NETLINK|RAW)\b")


def strace_argv(output: Path, command: list[str]) -> list[str]:
    """strace options: follow forks, epoch timestamps, fd paths; never environment blocks."""
    return [
        "strace", "-f", "-q", "-ttt", "-s", "256", "-yy",
        "-e", "trace=" + ",".join("?" + name for name in SYSCALLS),
        "-o", str(output), "--", *command,
    ]  # fmt: skip


@dataclass
class Call:
    pid: int
    time: float
    name: str
    args: str
    result: str
    annotation: str | None
    errno: str | None

    @property
    def ok(self) -> bool:
        return self.errno is None and self.result not in ("?",) and not self.result.startswith("-")


@dataclass
class Image:
    time: float
    path: str
    argv: list[str]
    truncated: bool

    @property
    def name(self) -> str:
        return os.path.basename(self.path)[:15]  # the kernel's comm for an execve


@dataclass
class Proc:
    pid: int
    parent: int | None
    first_seen: float
    images: list[Image] = field(default_factory=list)
    inherited: Image | None = None
    exit_status: str | None = None
    exit_time: float | None = None
    calls: list[Call] = field(default_factory=list)
    failed_execs: int = 0

    @property
    def token(self) -> str:
        return f"strace:{self.first_seen:.6f}"

    def image_at(self, when: float) -> Image | None:
        current = self.inherited
        for image in self.images:
            if image.time <= when:
                current = image
        return current


@dataclass
class Trace:
    processes: dict[int, Proc]
    lines: int
    unparsed: int
    first_pid: int | None


def unquote(text: str, start: int) -> tuple[str, int, bool]:
    """Decode the C string literal starting at text[start] == '"'; return (value, end, cut)."""
    out = bytearray()
    i = start + 1
    while i < len(text):
        char = text[i]
        if char == '"':
            cut = text.startswith("...", i + 1)
            return out.decode("utf-8", errors="replace"), i + 1 + (3 if cut else 0), cut
        if char == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            simple = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, '"': 34, "\\": 92}
            if nxt in simple:
                out.append(simple[nxt])
                i += 2
                continue
            if nxt == "x":
                out.append(int(text[i + 2 : i + 4], 16))
                i += 4
                continue
            digits = re.match(r"[0-7]{1,3}", text[i + 1 : i + 4])
            if digits:
                out.append(int(digits.group(), 8) & 0xFF)
                i += 1 + len(digits.group())
                continue
        out += char.encode("utf-8")
        i += 1
    return out.decode("utf-8", errors="replace"), len(text), True


def strings(args: str) -> list[str]:
    found, i = [], 0
    while (i := args.find('"', i)) != -1:
        value, i, _ = unquote(args, i)
        found.append(value)
    return found


def exec_args(args: str) -> tuple[str, list[str], bool] | None:
    """(filename, argv, truncated) from execve arguments."""
    first = args.find('"')
    if first == -1:
        return None
    filename, i, cut = unquote(args, first)
    bracket = args.find("[", i)
    argv: list[str] = []
    if bracket != -1:
        j = bracket + 1
        while j < len(args) and args[j] != "]":
            if args[j] == '"':
                value, j, part = unquote(args, j)
                argv.append(value)
                cut = cut or part
            elif args.startswith("...", j):
                cut = True
                j += 3
            else:
                j += 1
    return filename, argv, cut


def parse(lines: Iterable[str]) -> Trace:
    pending: dict[int, tuple[float, str]] = {}
    processes: dict[int, Proc] = {}
    tgid: dict[int, int] = {}
    count = unparsed = 0
    first_pid: int | None = None

    def proc(pid: int, when: float) -> Proc:
        owner = tgid.setdefault(pid, pid)
        if owner not in processes:
            processes[owner] = Proc(owner, None, when)
        return processes[owner]

    for raw in lines:
        count += 1
        match = LINE.match(raw.rstrip("\n"))
        if not match:
            unparsed += 1
            continue
        pid, when, body = int(match.group(1)), float(match.group(2)), match.group(3)
        if first_pid is None:
            first_pid = pid
        if body.startswith("+++"):
            owner = proc(pid, when)
            if tgid.get(pid, pid) == pid:  # a thread exiting is not the process exiting
                owner.exit_status = body.strip("+ ").replace("exited with ", "exit ")
                owner.exit_time = when
            continue
        if body.startswith("---"):
            continue
        if body.endswith("<unfinished ...>"):
            pending[pid] = (when, body[: -len("<unfinished ...>")].rstrip())
            continue
        resumed = re.match(r"^<\.\.\. (\w+) resumed>\s?(.*)$", body)
        if resumed:
            started, head = pending.pop(pid, (when, resumed.group(1) + "("))
            body, when = head + resumed.group(2), started
        call = split(pid, when, body)
        if call is None:
            unparsed += 1
            continue
        owner = proc(pid, when)
        if call.name in ("clone", "clone3", "fork", "vfork") and call.ok:
            child = int(call.result)
            if "CLONE_THREAD" in call.args:
                tgid[child] = owner.pid
                early = processes.pop(child, None)  # the thread printed before this return
                if early is not None and early.pid != owner.pid:
                    owner.calls += early.calls
                    owner.images += early.images
                continue
            tgid[child] = child
            if child in processes:  # the child reported a call before the parent's return
                processes[child].parent = owner.pid
                processes[child].first_seen = min(processes[child].first_seen, when)
            else:
                processes[child] = Proc(child, owner.pid, when)
            processes[child].inherited = owner.image_at(when)
            continue
        if call.name in ("execve", "execveat"):
            parsed = exec_args(call.args) if call.ok else None
            if parsed:
                owner.images.append(Image(when, parsed[0], parsed[1], parsed[2]))
            else:
                owner.failed_execs += 1  # e.g. PATH search misses before the real exec
            continue
        owner.calls.append(call)
    return Trace(processes, count, unparsed, first_pid)


def split(pid: int, when: float, body: str) -> Call | None:
    match = re.match(r"^(\w+)\((.*)$", body)
    if not match:
        return None
    name, rest = match.groups()
    cut = rest.rfind(") = ")
    if cut == -1:
        return None
    result = RESULT.match(rest[cut + 4 :])
    if not result:
        return None
    annotation = result.group(2)[1:-1] if result.group(2) else None
    return Call(pid, when, name, rest[:cut], result.group(1), annotation, result.group(3))


def subtree(trace: Trace, root: int) -> list[int]:
    children: dict[int, list[int]] = {}
    for proc in trace.processes.values():
        if proc.parent is not None:
            children.setdefault(proc.parent, []).append(proc.pid)
    ordered, stack = [], [root]
    while stack:
        pid = stack.pop()
        if pid in ordered or pid not in trace.processes:
            continue
        ordered.append(pid)
        stack.extend(sorted(children.get(pid, []), reverse=True))
    return sorted(ordered, key=lambda p: trace.processes[p].first_seen)


def path_args(call: Call) -> list[str]:
    """Absolute paths named by a file call, resolving dirfd-relative names via -yy."""
    values = strings(call.args)
    base = DIRFD.match(call.args)
    directory = base.group(2) if base and base.group(2) else None
    resolved = []
    for value in values[:2]:
        if not value.startswith("/") and directory:
            value = os.path.normpath(os.path.join(directory, value))
        resolved.append(value)
    if call.name in ("fchmod", "fchown"):
        fd = re.match(r"^\d+<([^>]*)>", call.args)
        resolved = [fd.group(1)] if fd else []
    if call.name in ("symlink", "symlinkat"):  # the first string is the link's target text
        resolved = resolved[1:2]
    return resolved


def noise(path: str) -> bool:
    return path.startswith(NOISE_PREFIXES) or not path


def sensitive(path: str) -> bool:
    return path.startswith(SENSITIVE_READS) or any(p in path for p in SENSITIVE_PARTS)


@dataclass
class Conversion:
    events: list[dict[str, Any]]
    stats: dict[str, Any]
    root: int | None
    runner: int | None


def to_events(
    trace: Trace,
    *,
    run_id: str,
    root: int | None,
    uid: int,
    source: str = "atomic-strace",
) -> Conversion:
    """Replay events for the executor's process tree (plus its parent as context)."""
    root = root if root in trace.processes else trace.first_pid
    host = f"atomic:{run_id}"
    stats: dict[str, Any] = dict(
        trace_lines=trace.lines, unparsed_lines=trace.unparsed, processes=0, execs=0,
        file_events=0, file_reads_ignored=0, network_events=0, privilege_events=0,
        privilege_attempts=0, exits=0, non_network_connects=0, failed_execs=0,
    )  # fmt: skip
    if root is None:
        return Conversion([], stats, None, None)
    pids = subtree(trace, root)
    runner = trace.processes[root].parent
    events: list[dict[str, Any]] = []
    seq = 0

    def base(proc: Proc, when: float, kind: str) -> dict[str, Any]:
        nonlocal seq
        seq += 1
        image = proc.image_at(when)
        parent = trace.processes.get(proc.parent) if proc.parent is not None else None
        event: dict[str, Any] = {
            "event_id": f"atomic:{run_id}:{seq:06d}",
            "timestamp": datetime.fromtimestamp(when, UTC).isoformat(),
            "event_type": kind,
            "pid": proc.pid,
            "process_name": image.name if image else None,
            "executable_path": image.path if image else None,
            "uid": uid,
            "process_start_time": proc.token,
            "host_id": host,
            "source": source,
            "metadata": {"collector": source, "run_id": run_id},
        }
        if parent is not None:
            event["ppid"] = parent.pid
            event["parent_start_time"] = parent.token
            parent_image = parent.image_at(when)
            if parent_image is not None:
                event["parent_process_name"] = parent_image.name
        return event

    if runner is not None and runner in trace.processes:
        context = trace.processes[runner]
        event = base(context, trace.processes[root].first_seen, "PROCESS_START")
        for key in ("ppid", "parent_start_time", "parent_process_name"):
            event.pop(key, None)
        event["metadata"]["role"] = "atomic-runner (context, not part of the test)"
        events.append(event)
    for pid in pids:
        proc = trace.processes[pid]
        stats["processes"] += 1
        stats["failed_execs"] += proc.failed_execs
        if not proc.images:
            event = base(proc, proc.first_seen, "PROCESS_START")
            event["metadata"]["note"] = "forked without exec (inherits the parent's image)"
            events.append(event)
        for image in proc.images:
            event = base(proc, image.time, "PROCESS_START")
            event["command_line"] = image.argv
            if image.truncated:
                event["metadata"]["command_line_truncated"] = True
            events.append(event)
            stats["execs"] += 1
        for call in proc.calls:
            converted = convert_call(call, proc, base, stats, uid)
            if converted is not None:
                events.append(converted)
        if proc.exit_status is not None and proc.exit_time is not None:
            event = base(proc, proc.exit_time, "PROCESS_EXIT")
            event["metadata"]["exit"] = proc.exit_status
            events.append(event)
            stats["exits"] += 1
    events.sort(key=lambda e: (e["timestamp"], e["event_id"]))
    return Conversion(events, stats, root, runner)


def convert_call(
    call: Call,
    proc: Proc,
    base: Callable[[Proc, float, str], dict[str, Any]],
    stats: dict[str, Any],
    uid: int,
) -> dict[str, Any] | None:
    result = "ok" if call.ok else (call.errno or call.result)
    if call.name == "connect":
        inet = INET.search(call.args) or INET6.search(call.args)
        if not inet:
            stats["non_network_connects"] += 1
            return None
        kind = FD_KIND.match(call.args)
        protocol = kind.group(1) if kind else "unknown"
        event = base(proc, call.time, "NETWORK_CONNECTION")
        event["network_destination"] = inet.group(2)
        event["metadata"].update(
            port=int(inet.group(1)),
            protocol=protocol,
            result=result,
            note="connect() attempt; EINPROGRESS means a non-blocking connect was started",
        )
        stats["network_events"] += 1
        return event
    if call.name in PRIVILEGE_CALLS:
        stats["privilege_attempts"] += 1
        values = [int(v) for v in re.findall(r"-?\d+", call.args)]
        target = next((v for v in values if v >= 0), None)
        if not call.ok or target is None or call.name.endswith("gid") or target == uid:
            return None  # only successful UID transitions are privilege changes
        event = base(proc, call.time, "PRIVILEGE_CHANGE")
        event["previous_uid"], event["uid"] = uid, target
        event["metadata"]["syscall"] = call.name
        stats["privilege_events"] += 1
        return event
    paths = path_args(call)
    if not paths or noise(paths[-1]):
        return None
    if call.name in ("open", "openat"):
        _, after, _ = unquote(call.args, call.args.find('"'))
        found = OPEN_FLAGS.search(call.args, after)
        flags = found.group(1) if found else ""
        writing = any(f in flags.split("|") for f in WRITE_FLAGS)
        path = call.annotation if call.ok and call.annotation else paths[-1]
        if not writing and not sensitive(path):
            stats["file_reads_ignored"] += 1
            return None
        access = "open-write" if writing else "open-read"
        event = base(proc, call.time, "FILE_ACCESS")
        event["file_path"] = path
        event["metadata"].update(operation=access, flags=flags, result=result)
        stats["file_events"] += 1
        return event
    operation = MODIFYING.get(call.name)
    if operation is None:
        return None
    event = base(proc, call.time, "FILE_ACCESS")
    event["file_path"] = paths[-1]
    event["metadata"].update(operation=operation, result=result)
    if operation == "rename" and len(paths) == 2:
        event["metadata"]["old_path"] = paths[0]
    if operation in ("chmod", "mkdir"):
        mode = re.search(r"\b0[0-7]{3,4}\b", call.args)
        if mode:
            event["metadata"]["mode"] = mode.group()
    stats["file_events"] += 1
    return event


def write_jsonl(events: list[dict[str, Any]], path: Path) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
