from __future__ import annotations

import json
import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_MODEL_BIN_PATH = ROOT / "ml" / "model" / "model.bin"
DEFAULT_MODEL_SIG_PATH = ROOT / "ml" / "model" / "model.sig"
DEFAULT_REGISTRY_PATH = ROOT / "ml" / "registry" / "registry.json"


def main() -> int:
    _ensure_canonical_python()
    _ensure_deterministic_process()
    os.environ["PYTHONHASHSEED"] = "0"

    model_path = Path(os.getenv("RANSOMEYE_ML_MODEL_BIN_PATH", str(DEFAULT_MODEL_BIN_PATH)))
    signature_path = Path(os.getenv("RANSOMEYE_ML_MODEL_SIGNATURE_PATH", str(DEFAULT_MODEL_SIG_PATH)))
    registry_path = Path(os.getenv("RANSOMEYE_ML_REGISTRY_PATH", str(DEFAULT_REGISTRY_PATH)))

    model_hash = sha256(model_path.read_bytes()).hexdigest()
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        raise RuntimeError(f"invalid Ed25519 signature length: {len(signature)}")

    registry = _load_json(registry_path)
    expected_fields = {
        "created_at",
        "dataset_hash",
        "feature_version",
        "hash",
        "model_id",
        "signature",
    }
    if set(registry) != expected_fields:
        raise RuntimeError("registry.json must contain the strict placeholder schema")
    if registry["hash"] != model_hash:
        raise RuntimeError("registry hash mismatch")

    registry["signature"] = signature.hex()
    _write_json(registry_path, registry)
    return 0


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected object JSON: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


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
