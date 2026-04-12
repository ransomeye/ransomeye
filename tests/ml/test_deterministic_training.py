from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ml.trainer import train


class DeterministicTrainingTest(unittest.TestCase):
    def test_same_dataset_twice_yields_identical_model_hash(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ransomeye_train_a.") as left, tempfile.TemporaryDirectory(
            prefix="ransomeye_train_b."
        ) as right:
            left_hash = self._run_training(Path(left))
            right_hash = self._run_training(Path(right))
            self.assertEqual(left_hash, right_hash)

    def _run_training(self, root: Path) -> str:
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
        metadata = json.loads((root / "model.json").read_text(encoding="utf-8"))
        return str(metadata["model_hash"])


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


if __name__ == "__main__":
    unittest.main()
