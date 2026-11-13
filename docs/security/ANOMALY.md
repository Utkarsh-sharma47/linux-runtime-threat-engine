# Process anomaly detection (Isolation Forest)

Module `anomaly` (`src/runtime_engine/security/anomaly.py`). Unsupervised; it ranks
how unusual a process is relative to a reviewed baseline. **A score is a relative rarity
measure, never a malware probability**, and deterministic rules never depend on it.

## Features (only what the engine actually collects)

| Feature | Source | Notes |
|---|---|---|
| `cpu_percent` | `/proc/PID/stat` utime+stime ÷ lifetime | lifetime average, % of one core |
| `rss_mb` | `/proc/PID/status` VmRSS | |
| `lifetime_seconds` | `/proc/uptime` − start ticks ÷ CLK_TCK | |
| `child_count` | PPIDs in the same sample | live children only |
| `fd_count`, `net_connections` | the network module's descriptor scan (reused, no second `/proc/*/fd` walk) | missing for other users' processes or when the network module is off |
| `exe_category` | `/proc/PID/exe` | 0 system path, 1 opt/snap/local, 2 home, 3 temp or deleted; missing if unreadable |
| `launch_rate_per_min` | new identities with the same name in the last 10 min | only processes alive at a sample |

Not used, because the collectors cannot provide them reliably: per-interval CPU,
file I/O volume and syscall mix.

## Method

1. **Missing values** stay `None`, never 0. Features missing in more than
   `max_missing_fraction` (50%) of training rows are dropped and recorded. At scoring
   time a missing value is imputed with the training median (z = 0), so missing
   telemetry can never make a process look anomalous.
2. **Transform and normalize**: `log1p` for heavy-tailed counts and sizes, then robust
   scaling z = (x − median) / IQR from the training data (MAD × 1.4826 if the IQR is 0;
   1 for constant features).
3. **Model**: scikit-learn `IsolationForest(n_estimators=200, random_state=42)`; score =
   −`score_samples(x)` (higher = more isolated). Without scikit-learn (optional
   `pip install '.[ml]'`), a deterministic **fallback**: score = mean of the three largest
   |z|. `algorithm: auto` picks the forest when available.
4. **Threshold**: the `threshold_quantile` (0.99) of training scores, or
   `threshold_override`. By construction roughly 1% of baseline-like processes exceed
   it; tune it for your noise tolerance.
5. **Explanation**, separate from the score: every feature with |z| ≥ `deviation_z` (3)
   against the training distribution, with value, training median and direction. The
   forest can rank a combination as unusual even when no single feature crosses 3.

## Training rules

* `anomaly train` refuses host-collected rows unless `--i-reviewed-baseline` is passed:
  active processes are not automatically a clean baseline. The assertion is recorded in
  the model metadata.
* Rows labelled `anomaly`, and rows whose process identity has alerts or incidents in the
  engine database, are excluded and counted.
* Artifacts: `model_directory/metadata-<version>.json` (version, algorithm, parameters,
  dataset, row counts, features, threshold, scaler statistics, baseline assertion) and,
  for the forest, `model-<version>.joblib` with its SHA-256. joblib uses pickle, so a
  model whose hash does not match is refused. Files are mode 0600; `current.json`
  selects the active model; retraining writes a new version.

## Live monitoring

Every 30 s the module samples `/proc` (about 110 ms for ~520 processes on the test
host), scores every process and reports AN001 findings (LOW, stored and not promoted
by default) for scores above the threshold. Evidence: score, threshold, model version
and algorithm, raw features and deviations. Without a model the status is `no-model`
and nothing is scored; a corrupt model is reported as `error`.

## Commands

```bash
python -m runtime_engine.main anomaly demo [--output DIR] [--json]  # synthetic: train + rank
python -m runtime_engine.main anomaly train --dataset FILE [--algorithm auto|iforest|robust] \
    [--i-reviewed-baseline] [--model-dir DIR]
python -m runtime_engine.main anomaly status [--json]
python -m runtime_engine.main anomaly score --dataset FILE [--top N]
python -m runtime_engine.main anomaly inspect [--pid PID] [--top N]   # live processes now
python -m runtime_engine.main anomaly collect --duration 600 --interval 30 --output host.jsonl
```

Dataset format: JSONL with `{"features": {...}, "process": ..., "pid": ...,
"label": "normal"|"anomaly", "source": "synthetic"|"host-collected"}`.

## Synthetic demonstration (measured)

600 baseline rows (daemon, desktop and shell profiles) and 65 observed rows with 5
injected cases. Both algorithms flag exactly the four injected outliers (`fork-heavy`,
`tmp-dropper`, `respawner`, `miner-like`) with **no normal row flagged**. The fifth case,
a process with unreadable features, is correctly **not** flagged. Forest training takes
~1.4 s, the fallback ~5 ms.

Applying the synthetic model to this real host flags ordinary desktop applications.
That is expected: a model only describes the data it was trained on. For real use,
collect host data with `anomaly collect`, review it, and train with
`--i-reviewed-baseline`.

## Limitations

The baseline quality bounds everything: anything present while collecting becomes
"normal". Short-lived processes are missed between samples. Unreadable executables and
descriptors reduce the feature set. Scores from different model versions are not
comparable.
