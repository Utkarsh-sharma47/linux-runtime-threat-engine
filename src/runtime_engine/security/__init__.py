"""Host security modules: scheduled, read-only scans that report evidence-backed findings.

Findings flow through the engine's existing bounded queue and pipeline thread, are stored
in the engine's SQLite database and, when the severity policy promotes them, join the
existing incident correlation. Modules never modify the host.
"""
