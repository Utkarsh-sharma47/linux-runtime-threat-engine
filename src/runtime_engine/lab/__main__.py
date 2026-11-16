"""python -m runtime_engine.lab {prepare|run|cleanup|list}"""

from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(
            "usage: python -m runtime_engine.lab {prepare|run|cleanup|list} [options]\n"
            "  prepare  create lab session + monitor.yaml\n"
            "  run      run scenarios (same as scripts/run-security-lab.sh)\n"
            "  cleanup  remove active lab session (confirmation required)\n"
            "  list     list scenarios"
        )
        return 0
    cmd, rest = args[0], args[1:]
    if cmd == "prepare":
        from runtime_engine.lab.session import env_exports, prepare_session

        session, config, ransom, status = prepare_session(repo_root=Path.cwd())
        exports = env_exports(session, config)
        rules = session / "lab-rules.yaml"
        print(f"session={session}")
        print(f"config={config}")
        print(f"rules={rules}")
        print(f"ransomware_lab={ransom}")
        print(f"database={status.database}")
        for key, value in exports.items():
            print(f"export {key}={value}")
        return 0
    if cmd == "run":
        from runtime_engine.lab.orchestrator import main as run_main

        return run_main(rest)
    if cmd == "cleanup":
        from runtime_engine.lab.cleanup import main as clean_main

        return clean_main(rest)
    if cmd == "list":
        from runtime_engine.lab.orchestrator import list_scenarios

        for name, desc in list_scenarios():
            print(f"{name:12}  {desc}")
        return 0
    print(f"unknown command {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
