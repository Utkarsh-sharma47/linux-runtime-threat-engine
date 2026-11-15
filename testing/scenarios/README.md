# Test scenarios

Scenario inputs for the engine, kept apart from the Atomic Red Team lab:

- `benign/`: activity that must not produce findings (false-positive checks)
- `suspicious/`: single indicators that should produce rule matches
- `attack_simulation/`: multi-step chains that should correlate into incidents

Replay files here must follow `docs/EVENT_SCHEMA.md`, mark themselves synthetic in
`metadata`, and never contain real host telemetry. Live behaviour is tested with the
Atomic lab in `../atomic-red-team/`; JSONL scenarios are the only way to exercise
file, network and privilege rules, because those event types are not collected live.
The bundled reference scenarios are in `datasets/`.
