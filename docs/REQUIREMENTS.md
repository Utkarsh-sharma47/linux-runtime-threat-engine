Project: Linux Runtime Threat Detection Engine

Complete Repository Initialization and Prototype Implementation Instructions

You are a senior Linux systems engineer, cybersecurity engineer, Python architect, and open-source maintainer.

Your task is to design and implement a functional, beginner-friendly but technically sound prototype of a Linux Runtime Threat Detection Engine built from scratch.

Do not merely generate a project plan, architecture document, or boilerplate repository. Implement the actual working prototype, execute tests, fix errors, and prepare the repository for GitHub.

The project must demonstrate how Linux runtime activity can be collected, analyzed, correlated, and converted into evidence-backed security incidents.

---

1. Project Objective

Build a lightweight Linux Runtime Threat Detection Engine that observes system activities and identifies suspicious behavior through rule-based detection and event correlation.

The engine should follow this architecture:

Linux Event Sources
|
v
Event Collector
|
v
Event Normalizer
|
v
Detection Rule Engine
|
v
Process Ancestry Tracker
|
v
Alert Correlation Engine
|
v
Incident Report Generator
|
v
CLI / JSON Reports

The initial prototype is a detection and reporting system.

It must NOT kill processes, block network connections, modify firewall rules, or automatically remediate suspicious activity.

All monitoring should be read-only.

2. Technology Stack

Use the following stack:

- Language: Python 3.11+
- Platform: Linux
- CLI: argparse or Typer
- Data validation: Pydantic
- Testing: pytest
- Logging: Python logging
- Configuration: YAML
- Storage: SQLite
- Type checking: mypy or pyright where practical
- Formatting: Ruff
- CI/CD: GitHub Actions

Use standard Linux interfaces and avoid unnecessary external dependencies.

Do not use Falco, Wazuh, OSSEC, or another existing detection engine as the implementation. The detection and correlation logic must be our own.

Possible Linux telemetry sources:

- /proc filesystem for process metadata and process ancestry
- Linux audit subsystem where available
- eBPF as an optional future extension
- Controlled synthetic event generation for reproducible testing

For the first prototype, prioritize reliable functionality over sophisticated kernel instrumentation.

Do not claim that polling /proc captures every process event. Clearly document its limitations.

3. Repository Structure

Create a clean and maintainable structure similar to:

linux-runtime-threat-engine/
|
|-- src/
|   |-- runtime_engine/
|       |-- init.py
|       |-- main.py
|       |
|       |-- collector/
|       |   |-- init.py
|       |   |-- base.py
|       |   |-- proc_collector.py
|       |   |-- replay_collector.py
|       |
|       |-- events/
|       |   |-- init.py
|       |   |-- schema.py
|       |   |-- normalizer.py
|       |
|       |-- detection/
|       |   |-- init.py
|       |   |-- engine.py
|       |   |-- rules.py
|       |   |-- rule_loader.py
|       |
|       |-- process/
|       |   |-- init.py
|       |   |-- ancestry.py
|       |
|       |-- correlation/
|       |   |-- init.py
|       |   |-- engine.py
|       |
|       |-- incidents/
|       |   |-- init.py
|       |   |-- generator.py
|       |   |-- reporter.py
|       |
|       |-- storage/
|       |   |-- init.py
|       |   |-- database.py
|       |
|       |-- metrics/
|       |   |-- init.py
|       |   |-- collector.py
|       |
|       |-- config/
|           |-- settings.py
|
|-- rules/
|   |-- default_rules.yaml
|
|-- config/
|   |-- default.yaml
|
|-- datasets/
|   |-- sample_events.jsonl
|
|-- tests/
|   |-- unit/
|   |-- integration/
|   |-- replay/
|
|-- scripts/
|   |-- generate_scenario.py
|
|-- reports/
|   |-- .gitkeep
|
|-- docs/
|   |-- ARCHITECTURE.md
|   |-- DETECTION_RULES.md
|   |-- EVENT_SCHEMA.md
|   |-- TESTING.md
|   |-- LIMITATIONS.md
|
|-- .github/
|   |-- workflows/
|       |-- ci.yml
|   |-- ISSUE_TEMPLATE/
|   |-- pull_request_template.md
|
|-- .gitignore
|-- .pre-commit-config.yaml
|-- pyproject.toml
|-- requirements.txt
|-- README.md
|-- LICENSE
|-- CONTRIBUTING.md
|-- SECURITY.md

You may adjust the structure if there is a strong technical reason. Keep the implementation modular without introducing unnecessary abstraction.

4. Event Collection

Implement two collectors.

A. Linux Process Collector

Create a collector that reads Linux process metadata from /proc.

Collect, where available:

- PID
- PPID
- Process name
- Executable path
- Command-line arguments
- User ID
- Process start time
- Observation timestamp

Requirements:

- Handle processes disappearing during collection.
- Handle permission errors.
- Handle malformed or incomplete /proc entries.
- Avoid crashing the engine because one process cannot be inspected.
- Do not execute collected command-line arguments.
- Do not modify the monitored system.
- Handle PID reuse carefully by including process start-time information in process identity.

Implement a polling-based process observation mechanism.

Detect newly observed processes by comparing process snapshots.

Document that this collector provides process discovery through polling, not guaranteed kernel-level event capture.

B. Replay Collector

Create a collector that reads JSONL event datasets.

Each line represents one event.

Support:

- Reading events sequentially.
- Validating input.
- Handling malformed lines without crashing.
- Replaying events in timestamp order when configured.
- Reporting invalid records.

This collector will power deterministic testing and demonstrations.

5. Event Schema and Normalization

Create a standardized Pydantic event model.

Each event should support fields such as:

- event_id
- timestamp
- event_type
- pid
- ppid
- process_name
- executable_path
- command_line
- uid
- parent_process_name
- file_path
- network_destination
- source
- metadata

Not every field will be available for every event.

Use optional fields appropriately.

Support event types such as:

- PROCESS_START
- PROCESS_EXIT
- FILE_ACCESS
- PRIVILEGE_CHANGE
- NETWORK_CONNECTION

Validate event data and normalize timestamps into a consistent timezone-aware format.

Do not fabricate missing telemetry.

6. Detection Rule Engine

Implement a rule-based detection engine from scratch.

Rules must be configurable using YAML.

Each rule should contain:

- Rule ID
- Name
- Description
- Severity
- Event type
- Matching conditions
- Enabled/disabled status
- MITRE ATT&CK technique reference when applicable and verified

Implement at least these initial detection scenarios:

1. Suspicious shell execution:
   Detect a shell process launched from an unusual parent process.

2. Suspicious executable location:
   Detect execution from configured temporary or writable locations.

3. Sensitive file access:
   Detect configured sensitive-file access events.

4. Unusual privilege change:
   Detect suspicious privilege transitions when sufficient evidence is available.

5. Suspicious process chain:
   Detect a suspicious combination of parent-child process relationships.

Important:

- A rule match is a detection, not proof of malicious activity.
- Avoid rules that simply flag every shell or every command-line utility.
- Make rules configurable.
- Include the reason each rule matched.
- Support severity levels: LOW, MEDIUM, HIGH, CRITICAL.
- Do not use arbitrary machine-learning scores.
- Do not claim MITRE mappings without verifying that the behavior actually corresponds to the technique.

Create unit tests for every rule.

7. Process Ancestry Tracker

Implement a process ancestry component.

It should:

- Maintain process relationships.
- Associate child processes with parents.
- Reconstruct process trees.
- Track PID and process start-time identity.
- Handle missing parents.
- Handle process termination.
- Avoid creating infinite loops in malformed ancestry data.
- Provide a human-readable process tree.

Example:

suspicious_app (PID 2400)
|
+--- bash (PID 2410)
|
+--- curl (PID 2420)

The tracker should be reusable by the detection and correlation engines.

8. Alert Correlation Engine

This is one of the most important components.

Do not treat every rule match as a separate incident.

Implement an alert correlation engine that groups related alerts using:

- Process identity
- Parent-child ancestry
- Event timestamps
- Configurable time windows
- Related resources
- Detection rule identifiers

Example:

Event 1: Suspicious shell launched.
Event 2: Sensitive file accessed.
Event 3: Unusual network connection.

These events should be eligible to form one correlated incident when their process relationships and timestamps support that conclusion.

Requirements:

- Configurable correlation window.
- Deduplication of repeated detections.
- Preserve all original evidence.
- Store first-seen and last-seen timestamps.
- Maintain incident severity.
- Keep an event count.
- Avoid grouping unrelated events merely because they occurred close together.
- Document the correlation strategy and its limitations.

9. Incident Report Generator

Generate structured incident reports.

Each report should contain:

- Incident ID
- Title
- Severity
- Status
- First observed
- Last observed
- Related processes
- Process ancestry
- Detection rules triggered
- Evidence timeline
- Supporting events
- Explanation of why the incident was generated

Support:

1. Human-readable terminal output.
2. JSON report export.
3. SQLite persistence.

Example report:

INCIDENT: INC-0001
SEVERITY: HIGH

SUMMARY:
Suspicious process activity was detected.

TIMELINE:
10:02:01 - Initial process observed.
10:02:02 - Shell process created.
10:02:03 - Sensitive file access detected.
10:02:04 - Unusual network activity detected.

EVIDENCE:

- Process ID
- Parent process ID
- Executable path
- Matching detection rules
- Relevant timestamps

Do not fabricate evidence or claim successful data exfiltration unless the telemetry actually supports it.

10. SQLite Storage

Implement persistence for:

- Events
- Detection alerts
- Incidents
- Incident-event relationships

Requirements:

- Use parameterized queries.
- Create database tables automatically.
- Handle duplicate event IDs.
- Use transactions where appropriate.
- Support retrieving incidents.
- Support retrieving events associated with an incident.
- Avoid storing unnecessary sensitive information.
- Document retention and privacy considerations.

11. Metrics and Performance

Implement basic metrics collection.

Measure:

- Total events processed
- Total alerts generated
- Total incidents created
- Duplicate alerts suppressed
- Events rejected due to invalid input
- Average processing latency
- Maximum processing latency
- Event throughput
- Collector errors

Expose a CLI command to display metrics.

Do not report invented performance results.

Benchmark using actual replay datasets and record the test environment.

12. CLI Interface

Create a usable CLI.

Required commands:

python -m runtime_engine.main monitor

Starts read-only Linux process monitoring.

python -m runtime_engine.main replay --input datasets/sample_events.jsonl

Replays a dataset through the complete detection pipeline.

python -m runtime_engine.main incidents

Lists stored incidents.

python -m runtime_engine.main incident --id INC-0001

Displays one incident with its evidence.

python -m runtime_engine.main metrics

Displays engine metrics.

python -m runtime_engine.main rules

Lists enabled detection rules.

python -m runtime_engine.main export --id INC-0001 --format json

Exports an incident report.

Ensure the CLI has useful help messages and meaningful exit codes.

13. Demonstration Scenarios

Create reproducible synthetic scenarios.

At minimum:

A. Benign process activity.

B. Suspicious shell execution.

C. Suspicious process chain with multiple related events.

D. Sensitive file access.

E. Repeated events that should be deduplicated.

F. Unrelated events that should NOT be correlated.

The synthetic data must be clearly labelled as synthetic.

Provide a script that generates these datasets.

The prototype must work without requiring actual malicious activity.

Never use real malware or destructive commands in demonstrations.

14. Testing Requirements

Implement tests covering:

Unit tests:

- Event schema validation
- Event normalization
- Individual detection rules
- Process ancestry reconstruction
- Deduplication
- Correlation windows
- Incident generation
- Database operations

Integration tests:

- Replay collector to detection engine
- Detection engine to correlation engine
- Correlation engine to incident generator
- Full pipeline to SQLite storage

Reliability tests:

- Malformed JSONL records
- Missing process metadata
- Duplicate events
- Out-of-order timestamps
- Missing parent processes
- PID reuse
- Collector permission errors

Verify that benign scenarios do not produce unexpected high-severity incidents.

Run the complete test suite and fix failures before declaring the prototype complete.

15. GitHub Repository Setup

Prepare the repository as a professional open-source project.

README.md

Include:

- Project overview
- Problem statement
- Features
- Architecture diagram using Mermaid
- Technology stack
- Installation instructions
- Quick-start commands
- Example demonstration
- Sample incident report
- Testing instructions
- Limitations
- Roadmap
- Contribution instructions

Do not make unsupported claims about detection accuracy or production readiness.

GitHub Actions

Create ".github/workflows/ci.yml".

On pull requests and pushes to main, run:

1. Python environment setup.
2. Dependency installation.
3. Ruff linting.
4. Type checking where configured.
5. Pytest.
6. Basic package/import validation.

Use supported Ubuntu runners.

Pin or constrain dependencies responsibly.

.gitignore

Exclude:

- .venv/
- pycache/
- .pytest_cache/
- .ruff_cache/
- *.pyc
- .env
- *.db
- reports/generated/
- coverage artifacts

Do not commit credentials, personal machine paths, or generated sensitive data.

GitHub Issue Templates

Create issue templates for:

- Bug report
- Feature request
- Detection rule proposal

Pull Request Template

Include:

- Summary
- Changes
- Tests performed
- Security implications
- Performance implications
- Documentation updates

CONTRIBUTING.md

Explain:

- Development setup
- Coding conventions
- Running tests
- Adding detection rules
- Submitting pull requests

SECURITY.md

Explain responsible vulnerability reporting and explicitly state the current prototype's security limitations.

16. Engineering Standards

Follow these principles:

- Small, focused modules.
- Clear interfaces between components.
- Type hints throughout.
- Meaningful names.
- Docstrings for public interfaces.
- No unnecessary global state.
- No giant monolithic files.
- No hardcoded personal paths.
- No swallowed exceptions.
- Structured logging.
- No fake implementations.
- No placeholder methods that silently return success.
- No unnecessary dependencies.
- No hidden network communication.
- No automatic remediation.

Prefer straightforward, maintainable engineering over excessive abstraction.

17. Implementation Workflow

Work in the following order.

PHASE 1: Inspect the existing repository.

- Check current directory.
- Inspect existing files.
- Inspect Git status and branch.
- Never overwrite existing work without understanding it.
- Preserve useful existing files.

PHASE 2: Initialize the architecture.

- Create the required directory structure.
- Define event schemas.
- Define component interfaces.
- Write architecture documentation.

PHASE 3: Implement the core pipeline.

- Replay collector.
- Event normalization.
- Detection rules.
- Process ancestry.
- Alert correlation.
- Incident generation.

PHASE 4: Add storage and reporting.

- SQLite persistence.
- Terminal reporting.
- JSON export.
- Metrics.

PHASE 5: Add Linux monitoring.

- Implement the read-only /proc process collector.
- Integrate it into the existing pipeline.
- Document telemetry limitations.

PHASE 6: Add demonstration datasets.

- Generate benign and suspicious scenarios.
- Run complete replay demonstrations.
- Verify expected detections and correlations.

PHASE 7: Test and harden.

- Run Ruff.
- Run type checks.
- Run pytest.
- Fix all failures.
- Check reliability edge cases.

PHASE 8: Prepare GitHub.

- README.
- GitHub Actions.
- Issue templates.
- PR template.
- CONTRIBUTING.md.
- SECURITY.md.
- .gitignore.

18. Git and Commit Instructions

First inspect:

git status
git branch --show-current
git log -5 --oneline

Never delete existing branches, overwrite unrelated files, or force-push.

If the repository is empty and Git is not initialized, initialize it.

Use a descriptive branch:

feat/linux-runtime-threat-engine-prototype

Do not switch branches or discard user changes without checking.

Create logical commits only after the relevant tests pass.

Suggested commit sequence:

1. chore: initialize project structure and tooling
2. feat: implement Linux process and replay collectors
3. feat: add event normalization and detection rules
4. feat: implement process ancestry and alert correlation
5. feat: add incident reporting and SQLite persistence
6. test: add replay scenarios and integration coverage
7. docs: add architecture and GitHub project documentation
8. ci: configure GitHub Actions

Before committing, inspect the diff and ensure no credentials, generated databases, or sensitive data are included.

Do not push to GitHub unless the user explicitly authorizes the remote push.

If a GitHub remote already exists, inspect it and preserve its configuration.

19. Definition of Done

The prototype is complete only when:

- Linux process monitoring works on a supported Linux system.
- Synthetic JSONL event replay works.
- Events pass through the complete pipeline.
- Detection rules generate explainable alerts.
- Process ancestry is reconstructed.
- Related alerts are grouped into incidents.
- Duplicate alerts are handled correctly.
- Incidents are persisted in SQLite.
- JSON and terminal reports work.
- Metrics are available.
- All automated tests pass.
- GitHub Actions CI is configured.
- Documentation accurately describes the implementation and limitations.

20. Final Instructions to the Coding Agent

Do not stop after creating the architecture or directory structure.

Implement the working code.

Do not pretend a component works if it has not been tested.

Do not invent benchmark numbers, detection results, or test results.

If a feature cannot be implemented reliably in the current environment, explain the blocker and implement the best safe alternative.

After implementation, provide a final engineering report containing:

1. Implemented features.
2. Repository structure.
3. Important architectural decisions.
4. Commands to install and run.
5. Commands to demonstrate each scenario.
6. Test results and actual test counts.
7. Performance measurements, if measured.
8. Known limitations.
9. Git branch and commit information.
10. Remaining work required for a more advanced version.

The final result should be a small but genuinely functional Linux Runtime Threat Detection Engine prototype that can be demonstrated to a professor, reviewed by another engineer, and extended into a more advanced cybersecurity project.