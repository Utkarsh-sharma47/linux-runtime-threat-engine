# Security policy

This is an experimental teaching prototype, not production security protection.
Read docs/LIMITATIONS.md before running it. The collector is read-only, detection
is heuristic and incomplete, and replay input is not authenticated. No live file,
network or privilege-change collection is implemented. There is no automatic
remediation, tamper resistance, database encryption or retention management.

Never test this project with real malware or destructive commands. Synthetic
scenarios are plain JSON strings and need no real sensitive-file access or connections.
Do not share raw live reports, command lines, credentials or sensitive file contents.

For a suspected vulnerability, use the repository's private GitHub vulnerability
reporting interface if it is enabled. Otherwise contact the repository owner through
a verified private channel and ask for a secure reporting route before sending
technical details. Do not post exploit details, secrets or live telemetry in a public
issue. No dedicated reporting mailbox, response SLA or supported-version policy is
promised yet. Include the version, a minimal harmless reproduction, impact and any
suggested fix once a private route is agreed.
