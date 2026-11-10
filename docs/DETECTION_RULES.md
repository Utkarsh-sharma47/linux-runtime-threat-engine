# Detection rules

Use `--rules path.yaml` before the command to replace the bundled rule set. The root
copy in `rules/default_rules.yaml` matches the packaged copy; a test enforces parity.
A rule contains ID, name, description, severity, event type, enabled state, AND conditions
and an optional MITRE source URL. IDs must be unique. Disable a rule with `enabled: false`.

| ID | Indicator | Severity | Required evidence / likely benign causes |
|---|---|---|---|
| RT001 | Shell from configured office/web-server parent | HIGH | Shell name plus observed/bound unusual parent. Automation can match. |
| RT002 | Executable under /tmp, /var/tmp or /dev/shm | MEDIUM | Absolute executable path; installers and developer tools can match. |
| RT003 | /etc/shadow or /etc/gshadow access | HIGH | FILE_ACCESS record; authorized administration can match. |
| RT004 | Non-root to root UID change | HIGH | PRIVILEGE_CHANGE and both UIDs; legitimate sudo can match. |
| RT005 | Shell launches curl/wget | LOW | Explicit parent-child name evidence; many ordinary scripts match. |
| RT006 | Connection to configured watch destination | MEDIUM | NETWORK_CONNECTION destination equals the configured string. |

RT006 ships with a documentation-only demonstration destination, `203.0.113.10`.
It is not a threat-intelligence feed, a real malicious address assertion or a claim
that all external network activity is suspicious. Replace it with your authorized
watchlist. RT003, RT004 and RT006 are replay-only with the current collectors.

Conditions support `equals`, `in`, `not_in`, and `path_under`. List operators require
lists. `path_under` requires absolute roots and path fields, normalizes lexical `..`
and checks directory boundaries (`/tmpish` does not match `/tmp`). It does not resolve
filesystem symlinks in replay data or infer directory writability from mode bits.
Missing telemetry never matches a condition. Matching reasons name each condition
and its observed value. All four severity values are supported; none of these default
indicators alone merits CRITICAL.

## MITRE ATT&CK

RT001 references **T1059.004, Unix Shell** as a behavior-level association, verified
against MITRE's definition and detection strategy on November 9, 2026:
https://attack.mitre.org/techniques/T1059/004/

MITRE describes Unix shells used for execution and suspicious shell-parent contexts.
A shell observed under an unusual configured application is relevant to that behavior;
it does not prove adversarial use, a reverse shell, persistence or compromise.
The prototype does not claim complete T1059.004 detection coverage. The other rules
have no mapping: a temporary path, file access, UID transition or transfer utility alone
is insufficient to establish a more specific ATT&CK technique.

## Add a rule

Start from a default rule, use a new ID, document false positives and evidence
requirements, and add positive, negative, missing-evidence and disabled tests. Include
an independently checked source and explanation before adding a MITRE reference.
