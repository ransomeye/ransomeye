from __future__ import annotations

import os
import sys
from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_MODEL_BIN_PATH = ROOT / "ml" / "model" / "model.bin"
DEFAULT_MODEL_SIG_PATH = ROOT / "ml" / "model" / "model.sig"
KEY_PATH = Path("/etc/ransomeye/worm_signing.key")


def main() -> int:
    _ensure_canonical_python()
    _ensure_deterministic_process()
    os.environ["PYTHONHASHSEED"] = "0"

    model_path = Path(os.getenv("RANSOMEYE_ML_MODEL_BIN_PATH", str(DEFAULT_MODEL_BIN_PATH)))
    signature_path = Path(os.getenv("RANSOMEYE_ML_MODEL_SIGNATURE_PATH", str(DEFAULT_MODEL_SIG_PATH)))

    model_hash = sha256(model_path.read_bytes()).hexdigest()
    _require_signature_placeholder(signature_path)

    try:
        sign_model_hash(model_hash, signature_path)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


def sign_model_hash(
    model_hash: str,
    signature_path: Path,
) -> bytes:
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    seed = _load_signing_seed()
    signature = _sign_with_cryptography(model_hash, seed)
    if signature is None:
        raise RuntimeError("cryptography package is required for Ed25519 signing")
    signature_path.write_bytes(signature)
    if len(signature) != 64:
        raise RuntimeError(f"invalid Ed25519 signature length: {len(signature)}")
    return signature


def _require_signature_placeholder(path: Path) -> None:
    if not path.exists():
        raise RuntimeError(f"model signature placeholder missing: {path}")
    if not path.is_file():
        raise RuntimeError(f"model signature path is not a regular file: {path}")


def _load_signing_seed() -> bytes:
    if not KEY_PATH.is_file():
        raise RuntimeError(f"missing worm signing key: {KEY_PATH}")
    raw = KEY_PATH.read_bytes()
    if len(raw) == 32:
        return raw
    if len(raw) == 64:
        return raw[:32]
    raise RuntimeError(f"worm signing key invalid size: got {len(raw)} want 32 or 64")


def _sign_with_cryptography(model_hash: str, seed: bytes) -> bytes | None:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ModuleNotFoundError:
        return None

    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key.sign(model_hash.encode("ascii"))


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
