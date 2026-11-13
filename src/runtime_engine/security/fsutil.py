"""Read-only filesystem helpers shared by the security modules.

- Metadata uses lstat: symlinks are recorded as links, never followed.
- Hashing is incremental: a digest is reused while (device, inode, size, mtime, ctime)
  is unchanged, and files above a size limit are not read.
- Walks stay inside their root and never descend into symlinked directories.
- Permission errors are returned explicitly so callers can report coverage gaps.
"""

import errno
import fnmatch
import hashlib
import os
import stat
import struct
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

# Linux capability numbers (include/uapi/linux/capability.h).
CAPABILITIES = [
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_fsetid",
    "cap_kill", "cap_setgid", "cap_setuid", "cap_setpcap", "cap_linux_immutable",
    "cap_net_bind_service", "cap_net_broadcast", "cap_net_admin", "cap_net_raw",
    "cap_ipc_lock", "cap_ipc_owner", "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot",
    "cap_sys_ptrace", "cap_sys_pacct", "cap_sys_admin", "cap_sys_boot", "cap_sys_nice",
    "cap_sys_resource", "cap_sys_time", "cap_sys_tty_config", "cap_mknod", "cap_lease",
    "cap_audit_write", "cap_audit_control", "cap_setfcap", "cap_mac_override",
    "cap_mac_admin", "cap_syslog", "cap_wake_alarm", "cap_block_suspend", "cap_audit_read",
    "cap_perfmon", "cap_bpf", "cap_checkpoint_restore",
]  # fmt: skip
NOATIME = getattr(os, "O_NOATIME", 0)
DANGEROUS_CAPABILITIES = {
    "cap_sys_admin", "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_ptrace", "cap_sys_module", "cap_chown", "cap_fowner", "cap_setfcap",
    "cap_sys_rawio", "cap_bpf",
}  # fmt: skip


@dataclass(frozen=True)
class FileMeta:
    path: str
    kind: str  # file, dir, symlink, other, missing, denied
    mode: int | None = None
    uid: int | None = None
    gid: int | None = None
    size: int | None = None
    mtime_ns: int | None = None
    ctime_ns: int | None = None
    inode: int | None = None
    device: int | None = None
    link_target: str | None = None

    @property
    def permissions(self) -> str | None:
        return None if self.mode is None else stat.filemode(self.mode)

    @property
    def setuid(self) -> bool:
        return self.mode is not None and bool(self.mode & stat.S_ISUID)

    @property
    def setgid(self) -> bool:
        return self.mode is not None and bool(self.mode & stat.S_ISGID)

    @property
    def world_writable(self) -> bool:
        return self.mode is not None and bool(self.mode & stat.S_IWOTH)

    @property
    def group_writable(self) -> bool:
        return self.mode is not None and bool(self.mode & stat.S_IWGRP)

    @property
    def executable(self) -> bool:
        return self.kind == "file" and self.mode is not None and bool(self.mode & 0o111)

    def signature(self) -> tuple[Any, ...]:
        return (self.device, self.inode, self.size, self.mtime_ns, self.ctime_ns)

    def public(self) -> dict[str, Any]:
        """Evidence form: metadata only, never contents."""
        data = asdict(self)
        data["permissions"] = self.permissions
        for key in ("device", "inode", "ctime_ns"):
            data.pop(key)
        return data


def lstat(path: str | Path) -> FileMeta:
    text = str(path)
    try:
        st = os.lstat(text)
    except FileNotFoundError:
        return FileMeta(text, "missing")
    except PermissionError:
        return FileMeta(text, "denied")
    except OSError as exc:
        return FileMeta(text, "denied" if exc.errno == errno.EACCES else "missing")
    if stat.S_ISLNK(st.st_mode):
        kind = "symlink"
    elif stat.S_ISREG(st.st_mode):
        kind = "file"
    elif stat.S_ISDIR(st.st_mode):
        kind = "dir"
    else:
        kind = "other"
    target = None
    if kind == "symlink":
        try:
            target = os.readlink(text)
        except OSError:
            target = None
    return FileMeta(
        text,
        kind,
        st.st_mode,
        st.st_uid,
        st.st_gid,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
        st.st_ino,
        st.st_dev,
        target,
    )


class FileHasher:
    """SHA-256 with an LRU cache keyed by file signature; reads at most `max_bytes` files."""

    def __init__(self, max_bytes: int = 1_048_576, cache_size: int = 20_000) -> None:
        self.max_bytes = max_bytes
        self.cache_size = cache_size
        self.cache: OrderedDict[tuple[str, tuple[Any, ...]], str] = OrderedDict()
        self.reads = 0
        self.bytes_read = 0

    def digest(self, meta: FileMeta) -> tuple[str | None, str]:
        """Returns (hex digest or None, status: hashed|cached|too-large|denied|not-a-file)."""
        if meta.kind != "file":
            return None, "not-a-file"
        if meta.size is not None and meta.size > self.max_bytes:
            return None, "too-large"
        key = (meta.path, meta.signature())
        cached = self.cache.get(key)
        if cached is not None:
            self.cache.move_to_end(key)
            return cached, "cached"
        # O_NOFOLLOW: a file swapped for a symlink after lstat is not followed.
        # O_NOATIME is refused (EPERM) for files the caller does not own, so retry without.
        fd = -1
        for flags in (os.O_RDONLY | os.O_NOFOLLOW | NOATIME, os.O_RDONLY | os.O_NOFOLLOW):
            try:
                fd = os.open(meta.path, flags)
                break
            except PermissionError:
                continue
            except OSError:
                return None, "unreadable"
        if fd < 0:
            return None, "denied"
        digest = hashlib.sha256()
        with os.fdopen(fd, "rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
                self.bytes_read += len(chunk)
        self.reads += 1
        value = digest.hexdigest()
        self.cache[key] = value
        if len(self.cache) > self.cache_size:
            self.cache.popitem(last=False)
        return value, "hashed"


def excluded(path: str, patterns: list[str]) -> bool:
    name = os.path.basename(path)
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(name, p) for p in patterns)


def walk(
    root: str | Path,
    *,
    max_depth: int = 1,
    exclude: list[str] | None = None,
    errors: list[str] | None = None,
) -> Iterator[FileMeta]:
    """Entries under root (not root itself), depth-limited, never following symlinks."""
    base = os.path.realpath(root)
    patterns = exclude or []
    stack: list[tuple[str, int]] = [(str(root), 1)]
    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as entries:
                names = sorted(entry.path for entry in entries)
        except PermissionError:
            if errors is not None:
                errors.append(directory)
            continue
        except OSError:
            continue
        for path in names:
            if excluded(path, patterns):
                continue
            meta = lstat(path)
            yield meta
            if meta.kind == "dir" and depth < max_depth:
                real = os.path.realpath(path)
                if real == base or real.startswith(base.rstrip("/") + "/"):
                    stack.append((path, depth + 1))


def file_capabilities(path: str) -> str | None:
    """Decode the security.capability xattr (vfs_cap_data) without following symlinks."""
    try:
        raw = os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError:
        return None
    if len(raw) < 12:
        return "unparsed"
    magic = struct.unpack_from("<I", raw, 0)[0]
    effective = bool(magic & 0x1)
    permitted = struct.unpack_from("<I", raw, 4)[0]
    inheritable = struct.unpack_from("<I", raw, 8)[0]
    if len(raw) >= 20:  # revision 2/3: high 32 bits follow
        permitted |= struct.unpack_from("<I", raw, 12)[0] << 32
        inheritable |= struct.unpack_from("<I", raw, 16)[0] << 32
    names = [
        name for bit, name in enumerate(CAPABILITIES) if (permitted | inheritable) & (1 << bit)
    ]
    flags = ("e" if effective else "") + ("p" if permitted else "") + ("i" if inheritable else "")
    return ",".join(names) + (f"={flags}" if flags else "") if names else "none"


def dangerous(capabilities: str | None) -> list[str]:
    if not capabilities:
        return []
    names = capabilities.split("=")[0].split(",")
    return sorted(n for n in names if n in DANGEROUS_CAPABILITIES)


def expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))
