"""Unsupervised process anomaly detection (Isolation Forest, deterministic fallback).

Pipeline: sample /proc -> feature vector (explicit missing values) -> log1p for heavy
tails -> robust scaling with the training median and IQR -> model score.

* Isolation Forest (scikit-learn, optional `ml` extra): anomaly score = -score_samples,
  higher is more unusual.
* Fallback without scikit-learn: mean of the three largest robust |z| values. Fully
  deterministic.

The alert threshold is a quantile of the training scores (or an explicit override).
Feature deviations (|z| against the training distribution) are computed separately from
the model score and explain what is unusual. An anomaly is a behavioural finding for
review: the score is not a malware probability, and deterministic rules never depend on
this model.
"""

import hashlib
import json
import math
import os
import statistics
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from runtime_engine.config.settings import AnomalySettings
from runtime_engine.events.schema import Severity
from runtime_engine.security.findings import (
    Coverage,
    Finding,
    ScanReport,
    SeverityPolicy,
    revision_of,
)

MODULE = "anomaly"
FEATURES = [
    "cpu_percent",  # lifetime average CPU, % of one core
    "rss_mb",  # resident memory
    "lifetime_seconds",
    "child_count",  # live children in the same snapshot
    "fd_count",  # from the network module's descriptor scan (readable processes only)
    "net_connections",  # sockets owned, from the same scan
    "exe_category",  # 0 system, 1 opt/snap/local, 2 home, 3 temp or deleted
    "launch_rate_per_min",  # new identities with the same name, last 10 minutes
]
LOG_FEATURES = {"cpu_percent", "rss_mb", "lifetime_seconds", "child_count", "fd_count",
                "net_connections", "launch_rate_per_min"}  # fmt: skip
EXE_LABELS = {0: "system path", 1: "opt/snap/local", 2: "home directory", 3: "temp or deleted"}


def sklearn_available() -> bool:
    try:
        import sklearn.ensemble  # noqa: F401
    except ImportError:
        return False
    return True


def exe_category(exe: str | None) -> float | None:
    if not exe:
        return None
    if exe.endswith(" (deleted)") or exe.startswith(("/memfd:", "/tmp/", "/var/tmp/", "/dev/shm/")):
        return 3.0
    if exe.startswith(("/home/", "/root/")):
        return 2.0
    if exe.startswith(("/opt/", "/snap/", "/usr/local/")):
        return 1.0
    return 0.0


# ----- process sampling -----


@dataclass(frozen=True)
class Sample:
    key: str
    pid: int
    name: str
    exe: str | None
    ppid: int
    start_ticks: int
    cpu_seconds: float
    rss_kb: int | None


class ProcessSampler:
    """One /proc pass per scan (stat, status, exe); descriptors come from the network scan."""

    def __init__(self, root: Path = Path("/proc")) -> None:
        self.root = root
        self.hertz = os.sysconf("SC_CLK_TCK")
        try:
            self.host = (root / "sys/kernel/random/boot_id").read_text().strip() or "local"
        except OSError:
            self.host = "local"
        self.launches: OrderedDict[str, deque[float]] = OrderedDict()
        self.seen: OrderedDict[str, None] = OrderedDict()

    def uptime(self) -> float:
        return float((self.root / "uptime").read_text().split()[0])

    def samples(self) -> tuple[list[Sample], Coverage]:
        coverage = Coverage()
        found: list[Sample] = []
        for entry in os.scandir(self.root):
            if not entry.name.isdigit():
                continue
            try:
                stat = Path(entry.path, "stat").read_text()
                right = stat.rindex(")")
                tail = stat[right + 2 :].split()
                start = int(tail[19])
                cpu = (int(tail[11]) + int(tail[12])) / self.hertz
                rss = None
                for line in Path(entry.path, "status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        rss = int(line.split()[1])
                        break
            except (OSError, ValueError, IndexError):
                continue  # exited during the scan
            try:
                exe: str | None = os.readlink(f"{entry.path}/exe")
            except PermissionError:
                exe = None
                coverage.deny(entry.path + "/exe")
            except OSError:
                exe = None  # kernel thread
            coverage.checked += 1
            pid = int(entry.name)
            key = json.dumps([self.host, pid, str(start)], separators=(",", ":"))
            found.append(
                Sample(
                    key, pid, stat[stat.index("(") + 1 : right], exe, int(tail[1]), start, cpu, rss
                )
            )
        return found, coverage

    def features(
        self, samples: list[Sample], resources: dict[str, dict[str, int]] | None
    ) -> dict[str, dict[str, float | None]]:
        now = time.time()
        uptime = self.uptime()
        children: dict[int, int] = {}
        for sample in samples:
            children[sample.ppid] = children.get(sample.ppid, 0) + 1
        for sample in samples:  # launch history: new identities per process name
            if sample.key not in self.seen:
                self.seen[sample.key] = None
                history = self.launches.setdefault(sample.name, deque(maxlen=200))
                history.append(now)
                self.launches.move_to_end(sample.name)
        while len(self.seen) > 50_000:
            self.seen.popitem(last=False)
        while len(self.launches) > 5_000:
            self.launches.popitem(last=False)
        result: dict[str, dict[str, float | None]] = {}
        for sample in samples:
            lifetime = max(0.001, uptime - sample.start_ticks / self.hertz)
            resource = (resources or {}).get(sample.key)
            launches = self.launches.get(sample.name, deque())
            result[sample.key] = {
                "cpu_percent": 100.0 * sample.cpu_seconds / lifetime,
                "rss_mb": None if sample.rss_kb is None else sample.rss_kb / 1024,
                "lifetime_seconds": lifetime,
                "child_count": float(children.get(sample.pid, 0)),
                "fd_count": float(resource["fds"]) if resource else None,
                "net_connections": float(resource["sockets"]) if resource else None,
                "exe_category": exe_category(sample.exe),
                "launch_rate_per_min": sum(1 for t in launches if now - t <= 600) / 10,
            }
        return result


# ----- scaling and models -----


def transform(name: str, value: float | None) -> float | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    return math.log1p(max(0.0, value)) if name in LOG_FEATURES else float(value)


def quantile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


@dataclass
class Scaler:
    features: list[str]
    median: dict[str, float]
    scale: dict[str, float]

    @classmethod
    def fit(cls, rows: list[dict[str, float | None]], features: list[str]) -> "Scaler":
        median: dict[str, float] = {}
        scale: dict[str, float] = {}
        for name in features:
            values = [v for row in rows if (v := transform(name, row.get(name))) is not None]
            mid = statistics.median(values)
            q1, q3 = quantile(values, 0.25), quantile(values, 0.75)
            spread = q3 - q1
            if spread <= 0:  # fall back to MAD, then to 1 (constant feature)
                spread = statistics.median(abs(v - mid) for v in values) * 1.4826 or 1.0
            median[name], scale[name] = mid, spread
        return cls(features, median, scale)

    def z(self, row: dict[str, float | None]) -> dict[str, float | None]:
        result: dict[str, float | None] = {}
        for name in self.features:
            value = transform(name, row.get(name))
            result[name] = None if value is None else (value - self.median[name]) / self.scale[name]
        return result

    def vector(self, row: dict[str, float | None]) -> list[float]:
        """Missing values are imputed with the training median (z = 0)."""
        return [0.0 if v is None else v for v in self.z(row).values()]


class RobustModel:
    """Deterministic fallback: mean of the three largest |z|."""

    algorithm = "robust-zscore"

    def score(self, vectors: list[list[float]]) -> list[float]:
        return [statistics.fmean(sorted((abs(x) for x in v), reverse=True)[:3]) for v in vectors]


class ForestModel:
    algorithm = "isolation-forest"

    def __init__(self, estimator: Any) -> None:
        self.estimator = estimator

    def score(self, vectors: list[list[float]]) -> list[float]:
        return [float(-s) for s in self.estimator.score_samples(vectors)]


@dataclass
class TrainedModel:
    metadata: dict[str, Any]
    scaler: Scaler
    model: RobustModel | ForestModel

    @property
    def threshold(self) -> float:
        return float(self.metadata["threshold"])

    def score_rows(self, rows: list[dict[str, float | None]]) -> list[float]:
        return self.model.score([self.scaler.vector(r) for r in rows]) if rows else []

    def deviations(self, row: dict[str, float | None], limit_z: float) -> list[dict[str, Any]]:
        """Per-feature robust z against training; independent of the model score."""
        result = []
        for name, z in self.scaler.z(row).items():
            if z is None:
                continue
            if abs(z) >= limit_z:
                result.append(
                    {
                        "feature": name,
                        "value": row.get(name),
                        "training_median": round(inverse(name, self.scaler.median[name]), 3),
                        "z": round(z, 2),
                        "direction": "higher" if z > 0 else "lower",
                    }
                )
        return sorted(result, key=lambda d: abs(d["z"]), reverse=True)


def inverse(name: str, value: float) -> float:
    return math.expm1(value) if name in LOG_FEATURES else value


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            item = json.loads(line)
            if not isinstance(item, dict) or not isinstance(item.get("features"), dict):
                raise ValueError("each dataset line needs a 'features' object")
            rows.append(item)
    return rows


def train(
    rows: list[dict[str, Any]],
    settings: AnomalySettings,
    *,
    dataset: str,
    excluded_keys: set[str] | None = None,
    algorithm: str | None = None,
    assertion: str,
) -> TrainedModel:
    """Fit on reviewed baseline rows. Rows labelled anomalous or tied to incidents are excluded."""
    excluded_keys = excluded_keys or set()
    usable = [
        r for r in rows
        if r.get("label", "normal") == "normal" and r.get("process_key") not in excluded_keys
    ]  # fmt: skip
    excluded = len(rows) - len(usable)
    if len(usable) < settings.min_training_rows:
        raise ValueError(
            f"{len(usable)} usable training rows; at least {settings.min_training_rows} needed"
        )
    features = [
        name for name in FEATURES
        if sum(1 for r in usable if r["features"].get(name) is None) / len(usable)
        <= settings.max_missing_fraction
    ]  # fmt: skip
    dropped = [f for f in FEATURES if f not in features]
    matrix = [r["features"] for r in usable]
    scaler = Scaler.fit(matrix, features)
    vectors = [scaler.vector(r) for r in matrix]
    chosen = algorithm or settings.algorithm
    if chosen == "auto":
        chosen = "iforest" if sklearn_available() else "robust"
    model: RobustModel | ForestModel
    if chosen == "iforest":
        from sklearn.ensemble import IsolationForest

        estimator = IsolationForest(
            n_estimators=settings.n_estimators, random_state=settings.random_state
        )
        estimator.fit(vectors)
        model = ForestModel(estimator)
    else:
        model = RobustModel()
    scores = model.score(vectors)
    threshold = (
        settings.threshold_override
        if settings.threshold_override is not None
        else quantile(scores, settings.threshold_quantile)
    )
    trained_at = datetime.now(UTC)
    digest = hashlib.sha256(json.dumps([dataset, len(usable), trained_at.isoformat()]).encode())
    metadata = {
        "version": f"{trained_at:%Y%m%dT%H%M%SZ}-{digest.hexdigest()[:8]}",
        "algorithm": model.algorithm,
        "trained_at": trained_at.isoformat(),
        "dataset": dataset,
        "training_rows": len(usable),
        "excluded_rows": excluded,
        "features": features,
        "dropped_features": dropped,
        "threshold": threshold,
        "threshold_rule": (
            "override"
            if settings.threshold_override is not None
            else f"quantile {settings.threshold_quantile} of training scores"
        ),  # fmt: skip
        "training_score_median": statistics.median(scores),
        "parameters": {
            "n_estimators": settings.n_estimators,
            "random_state": settings.random_state,
        }
        if chosen == "iforest"
        else {"top_k": 3},  # fmt: skip
        "baseline_assertion": assertion,
        "scaler": {"median": scaler.median, "scale": scaler.scale},
    }
    return TrainedModel(metadata, scaler, model)


# ----- persistence -----


def save_model(trained: TrainedModel, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    version = trained.metadata["version"]
    metadata = dict(trained.metadata)
    if isinstance(trained.model, ForestModel):
        import joblib

        artifact = directory / f"model-{version}.joblib"
        joblib.dump(trained.model.estimator, artifact)
        os.chmod(artifact, 0o600)
        metadata["artifact"] = artifact.name
        metadata["artifact_sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    path = directory / f"metadata-{version}.json"
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    os.chmod(path, 0o600)
    (directory / "current.json").write_text(json.dumps({"version": version}), encoding="utf-8")
    return path


def load_model(directory: Path) -> TrainedModel | None:
    pointer = directory / "current.json"
    if not pointer.is_file():
        return None
    version = json.loads(pointer.read_text())["version"]
    metadata = json.loads((directory / f"metadata-{version}.json").read_text())
    scaler = Scaler(metadata["features"], metadata["scaler"]["median"], metadata["scaler"]["scale"])
    if metadata["algorithm"] == "robust-zscore":
        return TrainedModel(metadata, scaler, RobustModel())
    if not sklearn_available():
        raise RuntimeError(
            "model needs scikit-learn (pip install '.[ml]') or retrain with --algorithm robust"
        )
    artifact = directory / metadata["artifact"]
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if digest != metadata["artifact_sha256"]:
        # joblib uses pickle: never load an artifact that does not match its metadata.
        raise RuntimeError(f"model artifact {artifact.name} does not match its recorded SHA-256")
    import joblib

    return TrainedModel(metadata, scaler, ForestModel(joblib.load(artifact)))


# ----- live module -----


def rank(
    trained: TrainedModel,
    rows: dict[str, dict[str, float | None]],
    names: dict[str, tuple[int, str]],
    limit_z: float,
) -> list[dict[str, Any]]:
    keys = list(rows)
    scores = trained.score_rows([rows[k] for k in keys])
    ranking = []
    for key, score in zip(keys, scores, strict=True):
        pid, name = names[key]
        ranking.append(
            {
                "process_key": key,
                "pid": pid,
                "process": name,
                "score": round(score, 4),
                "above_threshold": score >= trained.threshold,
                "features": rows[key],
                "deviations": trained.deviations(rows[key], limit_z),
            }
        )
    return sorted(ranking, key=lambda r: r["score"], reverse=True)


def anomaly_finding(item: dict[str, Any], trained: TrainedModel, detected: datetime) -> Finding:
    meta = trained.metadata
    finding = Finding.create(
        MODULE,
        "AN001",
        f"{item['process']} PID {item['pid']}",
        title="Unusual process behaviour (anomaly score above threshold)",
        severity=Severity.LOW,
        evidence={
            "summary": f"score {item['score']:.3f} >= threshold {trained.threshold:.3f}",
            "score": item["score"],
            "threshold": round(trained.threshold, 4),
            "model_version": meta["version"],
            "algorithm": meta["algorithm"],
            "features": item["features"],
            "deviations": item["deviations"],
        },
        explanation=(
            f"The {meta['algorithm']} model trained on {meta['training_rows']} reviewed baseline "
            "rows rates this process as unusual. The score is a relative rarity measure, not a "
            "probability of malware; the deviations list which measured features differ most "
            "from the training distribution. Review the process; deterministic rules are "
            "unaffected by this model."
        ),
        attribution="direct: the scored process itself",
        process_key=item["process_key"],
        pid=item["pid"],
        process_name=item["process"],
        detected_at=detected,
    )
    # Re-alert only when the picture changes, not on every rescore.
    finding.revision = revision_of(
        {
            "bucket": round(item["score"] / 0.05),
            "top": [d["feature"] for d in item["deviations"][:3]],
        }
    )
    return finding


class AnomalyDetector:
    name = MODULE

    def __init__(
        self,
        settings: AnomalySettings,
        policy: SeverityPolicy | None = None,
        resources: Callable[[], dict[str, dict[str, int]] | None] | None = None,
        sampler: ProcessSampler | None = None,
    ) -> None:
        self.settings = settings
        self.interval = settings.interval_seconds
        self.policy = policy or SeverityPolicy(
            overrides=settings.severity_overrides, allow=settings.allow
        )
        self.resources = resources or (lambda: None)
        self.sampler = sampler or ProcessSampler()
        self.trained: TrainedModel | None = None
        self.load_error: str | None = None
        self.reload()

    def reload(self) -> None:
        try:
            self.trained = load_model(Path(self.settings.model_directory))
            self.load_error = None
        except (OSError, ValueError, KeyError, RuntimeError) as exc:
            self.trained, self.load_error = None, f"{type(exc).__name__}: {exc}"

    def scan(self) -> ScanReport:
        started = datetime.now(UTC)
        clock = time.perf_counter()
        samples, coverage = self.sampler.samples()
        resources = self.resources()
        if resources is None:
            coverage.unavailable.append(
                "fd_count and net_connections unavailable (network module not running): "
                "treated as missing, imputed with the training median"
            )
        rows = self.sampler.features(samples, resources)
        names = {s.key: (s.pid, s.name) for s in samples}
        excluded = set(self.settings.exclude_names)
        rows = {k: v for k, v in rows.items() if names[k][1] not in excluded}
        summary: dict[str, Any] = {"processes_sampled": len(rows)}
        if self.trained is None:
            summary["model"] = None
            summary["model_error"] = self.load_error
            return ScanReport(
                MODULE,
                "error" if self.load_error else "no-model",
                started,
                time.perf_counter() - clock,
                coverage=coverage,
                summary=summary,
                error=self.load_error,
            )
        ranking = rank(self.trained, rows, names, self.settings.deviation_z)
        flagged = [
            anomaly_finding(item, self.trained, started)
            for item in ranking
            if item["above_threshold"]
        ]
        findings, suppressed = self.policy.apply(flagged)
        summary.update(
            model=public_metadata(self.trained.metadata),
            ranking=ranking[:50],
            above_threshold=len(flagged),
        )
        status = "degraded" if coverage.denied_count or coverage.unavailable else "ok"
        return ScanReport(
            MODULE,
            status,
            started,
            time.perf_counter() - clock,
            findings,
            coverage,
            summary,
            suppressed,
        )


def public_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in metadata.items() if k != "scaler"}


# ----- synthetic demonstration data -----


def synthetic_rows(seed: int = 11) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Synthetic baseline and observed sets; no real processes or malware are involved.

    The baseline mixes daemon-, desktop- and shell-like profiles. The observed set holds
    normal rows plus five injected outliers, each labelled with what makes it unusual.
    """
    import random

    rng = random.Random(seed)

    def normal(profile: str) -> dict[str, float | None]:
        if profile == "daemon":
            return {
                "cpu_percent": rng.uniform(0, 0.5),
                "rss_mb": rng.uniform(4, 60),
                "lifetime_seconds": rng.uniform(3600, 9e5),
                "child_count": rng.choice([0, 0, 1, 2]),
                "fd_count": rng.uniform(8, 60),
                "net_connections": rng.choice([0, 0, 1, 2]),
                "exe_category": 0.0,
                "launch_rate_per_min": rng.uniform(0, 0.1),
            }
        if profile == "desktop":
            return {
                "cpu_percent": rng.uniform(0.2, 6),
                "rss_mb": rng.uniform(80, 900),
                "lifetime_seconds": rng.uniform(600, 2e5),
                "child_count": rng.choice([0, 1, 3, 6]),
                "fd_count": rng.uniform(40, 300),
                "net_connections": rng.uniform(0, 25),
                "exe_category": rng.choice([0.0, 1.0]),
                "launch_rate_per_min": rng.uniform(0, 0.5),
            }
        return {
            "cpu_percent": rng.uniform(0, 2),
            "rss_mb": rng.uniform(2, 12),
            "lifetime_seconds": rng.uniform(1, 3600),
            "child_count": rng.choice([0, 1]),
            "fd_count": rng.uniform(3, 12),
            "net_connections": 0.0,
            "exe_category": 0.0,
            "launch_rate_per_min": rng.uniform(0, 1.5),
        }

    def row(
        profile: str, index: int, features: dict[str, float | None], label: str = "normal"
    ) -> dict[str, Any]:
        return {
            "process": f"{profile}-{index}",
            "pid": 1000 + index,
            "label": label,
            "source": "synthetic",
            "features": features,
        }

    profiles = ["daemon"] * 5 + ["desktop"] * 3 + ["shell"] * 2
    baseline = [
        row(p, i, normal(p)) for i, p in enumerate(rng.choice(profiles) for _ in range(600))
    ]
    observed = [
        row(p, 5000 + i, normal(p)) for i, p in enumerate(rng.choice(profiles) for _ in range(60))
    ]
    outliers = {
        "tmp-dropper": {
            "cpu_percent": 1.0,
            "rss_mb": 6.0,
            "lifetime_seconds": 40.0,
            "child_count": 0.0,
            "fd_count": 9.0,
            "net_connections": 14.0,
            "exe_category": 3.0,
            "launch_rate_per_min": 0.2,
        },
        "miner-like": {
            "cpu_percent": 380.0,
            "rss_mb": 2400.0,
            "lifetime_seconds": 7200.0,
            "child_count": 0.0,
            "fd_count": 30.0,
            "net_connections": 4.0,
            "exe_category": 2.0,
            "launch_rate_per_min": 0.1,
        },
        "respawner": {
            "cpu_percent": 0.5,
            "rss_mb": 3.0,
            "lifetime_seconds": 2.0,
            "child_count": 0.0,
            "fd_count": 5.0,
            "net_connections": 1.0,
            "exe_category": 0.0,
            "launch_rate_per_min": 45.0,
        },
        "fork-heavy": {
            "cpu_percent": 3.0,
            "rss_mb": 20.0,
            "lifetime_seconds": 300.0,
            "child_count": 120.0,
            "fd_count": 600.0,
            "net_connections": 0.0,
            "exe_category": 0.0,
            "launch_rate_per_min": 0.1,
        },
        "unreadable-exe": {
            "cpu_percent": 0.2,
            "rss_mb": 30.0,
            "lifetime_seconds": 5000.0,
            "child_count": 0.0,
            "fd_count": None,
            "net_connections": None,
            "exe_category": None,
            "launch_rate_per_min": 0.0,
        },
    }
    for index, (name, features) in enumerate(outliers.items()):
        observed.append(
            {
                "process": name,
                "pid": 9000 + index,
                "label": "anomaly" if name != "unreadable-exe" else "normal",
                "source": "synthetic",
                "features": features,
            }
        )
    return baseline, observed
