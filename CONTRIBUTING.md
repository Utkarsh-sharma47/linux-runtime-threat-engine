# Contributing

Use Python 3.11+ and a local virtual environment. Install with
`python -m pip install -e '.[dev]'`, or `uv sync --extra dev --locked`.

Before proposing a change, run `ruff check .`, `ruff format --check .`, `mypy src`,
`pytest -q --cov=runtime_engine` and `python -m build`. Keep modules focused, type
public interfaces, use standard-library components where practical, and do not add
network communication, root requirements or remediation.

To add a rule, edit `rules/default_rules.yaml` and its packaged copy under
`src/runtime_engine/data/`, then test positive, negative, missing-evidence and disabled
cases. Use a unique rule ID and explain benign causes. MITRE mappings need a verified
source and evidence-level explanation, not a guessed association. For a new collector,
implement the finite `Collector` interface and expose rejected/error counters. Do not
execute telemetry strings or fabricate missing fields.

For pull requests: use a descriptive feature branch, include the provided template,
explain evidence and privacy effects, add tests and update docs. Do not commit live
monitoring data, secrets, generated databases or personal paths. CI must pass before
merging. Dependency changes must update both `pyproject.toml`/`requirements.txt` where
applicable and `uv.lock`. Keep packaged rules and root rules identical.
