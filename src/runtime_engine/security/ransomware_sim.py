"""Safe ransomware-behaviour simulator for the early-warning demonstration.

It only ever touches files it creates itself, inside a dedicated lab directory:

* the lab directory must resolve to a path directly under the system temporary
  directory, its name must start with `rte-ransomware-lab`, and it must be new, empty or
  carry the simulator's marker file;
* every target path is checked to resolve inside the lab, files are opened with
  O_NOFOLLOW, created with O_EXCL, and symlinks in the lab abort the run;
* the "encryption" XORs the simulator's own dummy text with random bytes: high entropy,
  no real cryptography, no user data;
* the number of files is capped (`MAX_FILES`).

Run: python -m runtime_engine.security.ransomware_sim LAB_DIR [--files N] [--delay S]
"""

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

MARKER = ".rte-ransomware-lab"
PREFIX = "rte-ransomware-lab"
MAX_FILES = 200
NOTE = "README-LAB-NOTE.txt"


class UnsafeLabError(ValueError):
    pass


def validate_lab(path: str | Path) -> Path:
    """Refuse anything that is not a dedicated, simulator-owned lab directory."""
    lab = Path(os.path.realpath(path))
    temp_root = Path(os.path.realpath(tempfile.gettempdir()))
    if lab.parent != temp_root:
        raise UnsafeLabError(f"lab must be directly under {temp_root}, got {lab}")
    if not lab.name.startswith(PREFIX):
        raise UnsafeLabError(f"lab directory name must start with {PREFIX!r}")
    if Path(path).is_symlink():
        raise UnsafeLabError("lab path must not be a symlink")
    if lab.exists():
        if not lab.is_dir():
            raise UnsafeLabError("lab path exists and is not a directory")
        entries = os.listdir(lab)
        if entries and MARKER not in entries:
            raise UnsafeLabError("lab directory is not empty and has no simulator marker")
    return lab


def inside(lab: Path, name: str) -> Path:
    target = lab / name
    if os.path.realpath(target.parent) != str(lab) or "/" in name or name in ("", ".", ".."):
        raise UnsafeLabError(f"refusing path outside the lab: {name}")
    if target.is_symlink():
        raise UnsafeLabError(f"refusing symlink in the lab: {target}")
    return target


def create_lab(path: str | None = None) -> Path:
    lab = Path(tempfile.mkdtemp(prefix=PREFIX + "-")) if path is None else validate_lab(path)
    lab.mkdir(mode=0o700, exist_ok=True)
    (lab / MARKER).touch()
    return lab


def simulate(lab_path: str | Path, files: int = 20, delay: float = 0.02) -> dict[str, object]:
    lab = validate_lab(lab_path)
    if not (lab / MARKER).exists():
        raise UnsafeLabError("lab has no simulator marker; create it with create_lab()")
    if not 1 <= files <= MAX_FILES:
        raise UnsafeLabError(f"files must be between 1 and {MAX_FILES}")
    names = [f"lab-file-{i:03d}.txt" for i in range(files)]
    for name in names:  # phase 1: low-entropy dummy documents
        target = inside(lab, name)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(("Lab document for the ransomware early-warning demo. " * 80)[:4096])
    time.sleep(max(delay, 0.2))
    for name in names:  # phase 2: rewrite with random-looking bytes, then rename
        source = inside(lab, name)
        fd = os.open(source, os.O_RDWR | os.O_NOFOLLOW)
        with os.fdopen(fd, "r+b") as stream:
            content = stream.read()
            stream.seek(0)
            stream.write(
                bytes(a ^ b for a, b in zip(content, os.urandom(len(content)), strict=True))
            )
            stream.truncate()
        destination = inside(lab, name + ".locked")
        if destination.exists():
            raise UnsafeLabError(f"refusing to overwrite {destination}")
        os.rename(source, destination)
        time.sleep(delay)
    note = inside(lab, NOTE)
    fd = os.open(note, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write("Simulation only. No real files were encrypted.\n")
    return {"lab": str(lab), "files": files, "renamed": [n + ".locked" for n in names]}


def cleanup(lab_path: str | Path) -> int:
    """Remove only what the simulator created; returns the number of files removed."""
    lab = validate_lab(lab_path)
    removed = 0
    for entry in os.listdir(lab):
        if entry == MARKER or entry == NOTE or entry.startswith("lab-file-"):
            target = inside(lab, entry)
            if target.is_file():
                target.unlink()
                removed += 1
    if not os.listdir(lab):
        lab.rmdir()
    return removed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("lab")
    parser.add_argument("--files", type=int, default=20)
    parser.add_argument("--delay", type=float, default=0.02)
    args = parser.parse_args(argv)
    try:
        result = simulate(args.lab, args.files, args.delay)
    except UnsafeLabError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"simulated {result['files']} files in {result['lab']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
