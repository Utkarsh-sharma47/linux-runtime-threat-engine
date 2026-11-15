"""Safe cleanup for security-lab sessions — never touches paths outside the lab root."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from runtime_engine.lab.paths import (
    LAB_PREFIX,
    MARKER_NAME,
    RANSOMWARE_PREFIX,
    LabPathError,
    active_session_link,
    lab_root,
    resolve_active_session,
    temp_root,
    validate_under_lab_root,
)
from runtime_engine.security import ransomware_sim


def list_removable(session: Path) -> list[Path]:
    session = validate_under_lab_root(session)
    items: list[Path] = []
    for root, dirs, files in os.walk(session, topdown=False):
        for name in files:
            items.append(Path(root) / name)
        for name in dirs:
            items.append(Path(root) / name)
    items.append(session)
    return items


def ransomware_sibling(session: Path) -> Path | None:
    candidate = temp_root() / f"{RANSOMWARE_PREFIX}-{session.name}"
    if candidate.is_dir() and (candidate / ransomware_sim.MARKER).exists():
        return candidate
    return None


def cleanup_session(
    session: Path,
    *,
    preserve_reports: bool,
    yes: bool,
) -> int:
    session = validate_under_lab_root(session)
    if not (session / MARKER_NAME).exists():
        raise LabPathError(f"refusing cleanup: missing {MARKER_NAME} in {session}")
    print(f"Lab session: {session}")
    print(f"Lab root:    {lab_root()}")
    items = list_removable(session)
    if preserve_reports:
        keep = {p for p in items if "reports" in p.parts or "evidence" in p.parts}
        items = [p for p in items if p not in keep and p != session]
        print("Preserving reports/ and evidence/ (and the session directory itself).")
    print(f"Will remove {len(items)} path(s):")
    for path in items[:40]:
        print(f"  {path}")
    if len(items) > 40:
        print(f"  ... and {len(items) - 40} more")
    ransom = ransomware_sibling(session)
    if ransom is not None:
        print(f"Also ransomware lab sibling: {ransom}")
    if not yes:
        try:
            answer = input("Type DELETE to confirm removal: ").strip()
        except EOFError:
            print("refused: non-interactive cleanup needs --yes", file=sys.stderr)
            return 5
        if answer != "DELETE":
            print("aborted")
            return 1
    for path in items:
        if path.is_dir() and not path.is_symlink():
            try:
                path.rmdir()
            except OSError:
                shutil.rmtree(path)
        elif path.exists() or path.is_symlink():
            path.unlink()
    if not preserve_reports and session.exists():
        shutil.rmtree(session)
    if ransom is not None:
        removed = ransomware_sim.cleanup(ransom)
        print(f"Removed {removed} ransomware lab file(s)")
        if ransom.exists():
            shutil.rmtree(ransom)
    link = active_session_link()
    if link.is_symlink() and Path(os.path.realpath(link)) == Path(os.path.realpath(session)):
        link.unlink()
        print(f"Cleared active link {link}")
    print("Cleanup complete.")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safely remove a security-lab session tree")
    parser.add_argument(
        "--session",
        type=Path,
        help="Session directory (default: active lab session)",
    )
    parser.add_argument(
        "--preserve-reports",
        action="store_true",
        help="Keep evidence/ and reports/ under the session",
    )
    parser.add_argument("--yes", action="store_true", help="Confirm without interactive prompt")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    session = args.session
    if session is None:
        session = resolve_active_session()
        if session is None:
            print("error: no active lab session", file=sys.stderr)
            return 2
    try:
        # Extra guard: session name must live under rte-security-lab root.
        if lab_root().name != LAB_PREFIX:
            raise LabPathError("lab root misconfigured")
        return cleanup_session(session, preserve_reports=args.preserve_reports, yes=args.yes)
    except LabPathError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
