`start-monitor.sh` / `python -m runtime_engine.lab prepare` write the live YAML into the
session directory and symlink it here as `active-monitor.yaml`.

Do not hand-edit system persistence paths into that file — the lab must stay under
`<tmp>/rte-security-lab/`.
