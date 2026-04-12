from __future__ import annotations

import json
import io
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.model import sign
from ml.model import update_registry
from ml.trainer import train


class ModelSignatureTest(unittest.TestCase):
    def test_registry_signature_matches_model_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ransomeye_sign.") as tempdir:
            root = Path(tempdir)
            self._run_training(root)
            key_path = root / "worm_signing.key"
            key_path.write_bytes(bytes(range(32)))

            env = os.environ.copy()
            env.update(
                {
                    "PYTHONHASHSEED": "0",
                    "RANSOMEYE_ML_MODEL_BIN_PATH": str(root / "model.bin"),
                    "RANSOMEYE_ML_MODEL_METADATA_PATH": str(root / "model.json"),
                    "RANSOMEYE_ML_MODEL_SIGNATURE_PATH": str(root / "model.sig"),
                    "RANSOMEYE_ML_REGISTRY_PATH": str(root / "registry.json"),
                }
            )
            with _temporary_environ(env):
                with mock.patch.object(sign, "KEY_PATH", key_path):
                    self.assertEqual(sign.main(), 0)
                self.assertEqual(update_registry.main(), 0)

            registry = json.loads((root / "registry.json").read_text(encoding="utf-8"))
            signature = (root / "model.sig").read_bytes().hex()
            self.assertEqual(signature, registry["signature"])
            self.assertEqual(registry["hash"], _sha256_hex(root / "model.bin"))

    def test_tampered_model_is_rejected_by_registry_finalizer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ransomeye_sign_tamper.") as tempdir:
            root = Path(tempdir)
            self._run_training(root)
            key_path = root / "worm_signing.key"
            key_path.write_bytes(bytes(range(32)))
            (root / "model.bin").write_bytes(b"tampered-model\n")

            env = os.environ.copy()
            env.update(
                {
                    "PYTHONHASHSEED": "0",
                    "RANSOMEYE_ML_MODEL_BIN_PATH": str(root / "model.bin"),
                    "RANSOMEYE_ML_MODEL_METADATA_PATH": str(root / "model.json"),
                    "RANSOMEYE_ML_MODEL_SIGNATURE_PATH": str(root / "model.sig"),
                    "RANSOMEYE_ML_REGISTRY_PATH": str(root / "registry.json"),
                }
            )
            with _temporary_environ(env):
                with mock.patch.object(sign, "KEY_PATH", key_path):
                    self.assertEqual(sign.main(), 0)
                with self.assertRaisesRegex(RuntimeError, "registry hash mismatch"):
                    update_registry.main()

    def test_invalid_key_path_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ransomeye_sign_missing_key.") as tempdir:
            root = Path(tempdir)
            self._run_training(root)
            missing_key_path = root / "missing-worm-signing.key"
            signature_path = root / "model.sig"
            registry_before = (root / "registry.json").read_text(encoding="utf-8")

            env = os.environ.copy()
            env.update(
                {
                    "PYTHONHASHSEED": "0",
                    "RANSOMEYE_ML_MODEL_BIN_PATH": str(root / "model.bin"),
                    "RANSOMEYE_ML_MODEL_METADATA_PATH": str(root / "model.json"),
                    "RANSOMEYE_ML_MODEL_SIGNATURE_PATH": str(root / "model.sig"),
                    "RANSOMEYE_ML_REGISTRY_PATH": str(root / "registry.json"),
                }
            )
            with _temporary_environ(env):
                with mock.patch.object(sign, "KEY_PATH", missing_key_path):
                    with redirect_stderr(io.StringIO()):
                        self.assertEqual(sign.main(), 1)
            self.assertTrue(signature_path.exists())
            self.assertEqual(signature_path.read_bytes(), b"")
            self.assertEqual((root / "registry.json").read_text(encoding="utf-8"), registry_before)

    def test_root_does_not_write_repo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ransomeye_sign_boundary.") as tempdir:
            root = Path(tempdir)
            self._run_training(root)
            key_path = root / "worm_signing.key"
            key_path.write_bytes(bytes(range(32)))

            model_path = root / "model.bin"
            metadata_path = root / "model.json"
            signature_path = root / "model.sig"
            registry_path = root / "registry.json"
            registry_before = registry_path.read_text(encoding="utf-8")
            tracked_stats_before = {
                path.name: path.stat()
                for path in (model_path, metadata_path, signature_path, registry_path)
            }

            env = os.environ.copy()
            env.update(
                {
                    "PYTHONHASHSEED": "0",
                    "RANSOMEYE_ML_MODEL_BIN_PATH": str(model_path),
                    "RANSOMEYE_ML_MODEL_METADATA_PATH": str(metadata_path),
                    "RANSOMEYE_ML_MODEL_SIGNATURE_PATH": str(signature_path),
                    "RANSOMEYE_ML_REGISTRY_PATH": str(registry_path),
                }
            )
            with _temporary_environ(env):
                with mock.patch.object(sign, "KEY_PATH", key_path):
                    self.assertEqual(sign.main(), 0)

            self.assertEqual(registry_path.read_text(encoding="utf-8"), registry_before)
            self.assertEqual(len(signature_path.read_bytes()), 64)
            for path in (model_path, metadata_path, signature_path, registry_path):
                before = tracked_stats_before[path.name]
                after = path.stat()
                self.assertEqual(after.st_uid, before.st_uid)
                self.assertEqual(after.st_gid, before.st_gid)

    def _run_training(self, root: Path) -> None:
        env = os.environ.copy()
        env.update(
            {
                "PYTHONHASHSEED": "0",
                "RANSOMEYE_ML_INPUT_PATH": str(ROOT / "ml" / "testdata" / "training_events.json"),
                "RANSOMEYE_ML_CANONICAL_DATASET_PATH": str(root / "canonical_dataset.json"),
                "RANSOMEYE_ML_MODEL_BIN_PATH": str(root / "model.bin"),
                "RANSOMEYE_ML_MODEL_METADATA_PATH": str(root / "model.json"),
                "RANSOMEYE_ML_MODEL_SIGNATURE_PATH": str(root / "model.sig"),
                "RANSOMEYE_ML_REGISTRY_PATH": str(root / "registry.json"),
                "SOURCE_DATE_EPOCH": "1700000000",
            }
        )
        with _temporary_environ(env):
            train.main()


@contextmanager
def _temporary_environ(new_env: dict[str, str]):
    old_env = os.environ.copy()
    os.environ.clear()
    os.environ.update(new_env)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old_env)


def _sha256_hex(path: Path) -> str:
    return __import__("hashlib").sha256(path.read_bytes()).hexdigest()


if __name__ == "__main__":
    unittest.main()
