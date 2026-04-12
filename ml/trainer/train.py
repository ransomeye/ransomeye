from __future__ import annotations

import datetime as dt
import json
import os
import random
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.common.np_compat import np
from ml.dataset.loader import load_dataset, write_canonical_dataset
from ml.dataset.schema import DEFAULT_FEATURE_VERSION, canonical_dataset_hash
from ml.features.extractor import FeatureMatrix, VECTOR_LENGTH, extract_features
from ml.features.sequence import BURST_THRESHOLD_NS, MAX_TIME_DELTA_NS, SEQUENCE_WINDOW_SIZE
from ml.model.scorer import FUSION_VERSION, FUSION_WEIGHTS, SCORE_THRESHOLD, SINE_MIN_THRESHOLD


SEED = 42
DEFAULT_INPUT_PATH = ROOT / "ml" / "testdata" / "training_events.json"
DEFAULT_CANONICAL_DATASET_PATH = ROOT / "ml" / "dataset" / "canonical_dataset.json"
DEFAULT_MODEL_BIN_PATH = ROOT / "ml" / "model" / "model.bin"
DEFAULT_MODEL_META_PATH = ROOT / "ml" / "model" / "model.json"
DEFAULT_MODEL_SIG_PATH = ROOT / "ml" / "model" / "model.sig"
DEFAULT_REGISTRY_PATH = ROOT / "ml" / "registry" / "registry.json"
TRAINING_EPOCHS = 64
LEARNING_RATE = np.float64(0.5)


def main() -> int:
    _ensure_canonical_python()
    _ensure_deterministic_process()
    os.environ["PYTHONHASHSEED"] = "0"
    random.seed(SEED)
    np_random_seed(SEED)

    input_path = Path(os.getenv("RANSOMEYE_ML_INPUT_PATH", str(DEFAULT_INPUT_PATH)))
    canonical_dataset_path = Path(
        os.getenv("RANSOMEYE_ML_CANONICAL_DATASET_PATH", str(DEFAULT_CANONICAL_DATASET_PATH))
    )
    model_bin_path = Path(os.getenv("RANSOMEYE_ML_MODEL_BIN_PATH", str(DEFAULT_MODEL_BIN_PATH)))
    model_meta_path = Path(
        os.getenv("RANSOMEYE_ML_MODEL_METADATA_PATH", str(DEFAULT_MODEL_META_PATH))
    )
    model_sig_path = Path(
        os.getenv("RANSOMEYE_ML_MODEL_SIGNATURE_PATH", str(DEFAULT_MODEL_SIG_PATH))
    )
    registry_path = Path(os.getenv("RANSOMEYE_ML_REGISTRY_PATH", str(DEFAULT_REGISTRY_PATH)))
    feature_version = os.getenv("RANSOMEYE_FEATURE_VERSION", DEFAULT_FEATURE_VERSION).strip()

    dataset = load_dataset(input_path, feature_version=feature_version)
    dataset_hash = canonical_dataset_hash(dataset)
    write_canonical_dataset(dataset, canonical_dataset_path)
    feature_matrix = extract_features(dataset)
    if feature_matrix.dataset_hash != dataset_hash:
        raise ValueError("feature extractor dataset hash mismatch")
    if feature_matrix.feature_version != dataset.feature_version:
        raise ValueError("feature extractor feature version mismatch")
    model = train_model(feature_matrix)
    model_hash = write_model_artifacts(
        model=model,
        dataset_hash=dataset_hash,
        dataset_schema_version=dataset.schema_version,
        feature_version=feature_matrix.feature_version,
        feature_names=feature_matrix.feature_names,
        model_bin_path=model_bin_path,
        model_meta_path=model_meta_path,
        model_sig_path=model_sig_path,
        registry_path=registry_path,
    )
    print(model_hash)
    return 0


def train_model(matrix: FeatureMatrix) -> dict[str, Any]:
    if len(matrix.vectors) != len(matrix.labels):
        raise ValueError("feature vectors and labels must align")
    if not matrix.vectors:
        raise ValueError("feature matrix is empty")
    if len(matrix.vectors[0]) != VECTOR_LENGTH:
        raise ValueError(f"expected vector length {VECTOR_LENGTH}")

    weights = [np.float64(0.0) for _ in range(VECTOR_LENGTH)]
    bias = np.float64(0.0)
    sample_count = np.float64(len(matrix.vectors))

    for _ in range(TRAINING_EPOCHS):
        gradient_w = [np.float64(0.0) for _ in range(VECTOR_LENGTH)]
        gradient_b = np.float64(0.0)
        for vector, label in zip(matrix.vectors, matrix.labels):
            z_value = np.float64(bias + _dot(weights, vector))
            probability = _sigmoid(z_value)
            error = _round64(np.float64(probability) - np.float64(label))
            gradient_b = _round64(gradient_b + error)
            for idx, value in enumerate(vector):
                gradient_w[idx] = _round64(gradient_w[idx] + np.float64(error * np.float64(value)))

        for idx in range(VECTOR_LENGTH):
            step = _round64(np.float64(LEARNING_RATE * gradient_w[idx] / sample_count))
            weights[idx] = _round64(weights[idx] - step)
        bias = _round64(bias - _round64(np.float64(LEARNING_RATE * gradient_b / sample_count)))

    return {
        "algorithm": "deterministic_logistic_regression_v1",
        "bias": float(_round64(bias)),
        "vector_length": VECTOR_LENGTH,
        "weights": [float(_round64(weight)) for weight in weights],
    }


def write_model_artifacts(
    model: dict[str, Any],
    dataset_hash: str,
    dataset_schema_version: str,
    feature_version: str,
    feature_names: tuple[str, ...],
    model_bin_path: Path,
    model_meta_path: Path,
    model_sig_path: Path,
    registry_path: Path,
) -> str:
    model_bytes = _model_bin_bytes(model)
    model_bin_path.parent.mkdir(parents=True, exist_ok=True)
    model_bin_path.write_bytes(model_bytes)
    model_hash = sha256(model_bytes).hexdigest()

    metadata = {
        "algorithm": model["algorithm"],
        "created_at": _created_at(),
        "dataset_hash": dataset_hash,
        "dataset_schema_version": dataset_schema_version,
        "explainability": "loo-v1",
        "feature_version": feature_version,
        "feature_names": list(feature_names),
        "fusion_version": FUSION_VERSION,
        "fusion_weights": {key: float(value) for key, value in FUSION_WEIGHTS.items()},
        "max_time_delta_ns": MAX_TIME_DELTA_NS,
        "model_hash": model_hash,
        "model_id": f"model-{model_hash[:16]}",
        "score_threshold": float(SCORE_THRESHOLD),
        "sequence_window_size": SEQUENCE_WINDOW_SIZE,
        "sine_min_threshold": float(SINE_MIN_THRESHOLD),
        "temporal_burst_threshold_ns": BURST_THRESHOLD_NS,
        "vector_length": model["vector_length"],
    }
    _write_json(model_meta_path, metadata)

    model_sig_path.parent.mkdir(parents=True, exist_ok=True)
    model_sig_path.write_bytes(b"")

    placeholder_registry = {
        "created_at": metadata["created_at"],
        "dataset_hash": dataset_hash,
        "feature_version": feature_version,
        "hash": model_hash,
        "model_id": metadata["model_id"],
        "signature": "",
    }
    _write_json(registry_path, placeholder_registry)
    return model_hash


def _model_bin_bytes(model: dict[str, Any]) -> bytes:
    weights = ",".join(f"{float(value):.8f}" for value in model["weights"])
    content = "\n".join(
        [
            f"algorithm={model['algorithm']}",
            f"vector_length={model['vector_length']}",
            f"bias={float(model['bias']):.8f}",
            f"weights={weights}",
        ]
    )
    return (content + "\n").encode("utf-8")


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _sigmoid(value: float) -> float:
    if value >= 0:
        exponent = np.exp(-value)
        return np.float64(np.float64(1.0) / np.float64(1.0 + exponent))
    exponent = np.exp(value)
    return np.float64(exponent / np.float64(1.0 + exponent))


def _round64(value: float) -> float:
    return np.float64(np.round(np.float64(value), 8))


def _dot(weights: list[float], vector: tuple[float, ...]) -> float:
    total = np.float64(0.0)
    for weight, value in zip(weights, vector):
        total = _round64(total + np.float64(np.float64(weight) * np.float64(value)))
    return total


def _created_at() -> str:
    epoch = int(os.getenv("SOURCE_DATE_EPOCH", "1700000000"))
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_deterministic_process() -> None:
    wanted = {
        "PYTHONHASHSEED": "0",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
    }
    current = {key: os.environ.get(key) for key in wanted}
    if all(current[key] == value for key, value in wanted.items()):
        return

    env = os.environ.copy()
    env.update(wanted)
    os.environ.update(wanted)
    if _launched_as_script():
        os.execve(sys.executable, [sys.executable, *sys.argv], env)


def np_random_seed(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as real_numpy  # type: ignore

        real_numpy.random.seed(seed)
    except ModuleNotFoundError:
        return


def _ensure_canonical_python() -> None:
    if sys.executable not in ["/usr/bin/python3"]:
        raise RuntimeError("Non-canonical Python path")


def _launched_as_script() -> bool:
    argv0 = sys.argv[0].strip() if sys.argv else ""
    if not argv0:
        return False
    try:
        return Path(argv0).resolve() == Path(__file__).resolve()
    except OSError:
        return False


if __name__ == "__main__":
    raise SystemExit(main())
