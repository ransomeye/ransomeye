from __future__ import annotations

import math

try:  # pragma: no cover - exercised when numpy is available in target runtime.
    import numpy as np  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - local air-gapped fallback.
    class _NPCompat:
        float64 = float

        @staticmethod
        def round(value: float, decimals: int = 0) -> float:
            return float(round(float(value), decimals))

        @staticmethod
        def exp(value: float) -> float:
            return float(math.exp(float(value)))

    np = _NPCompat()
