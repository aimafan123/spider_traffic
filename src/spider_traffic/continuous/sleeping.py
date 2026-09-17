"""访问间隔采样与可中断等待。

默认分布为**截断指数分布**（``mean=20s``，``min=3s``，``max=90s``）：
采用 inverse-CDF 直接采样，没有拒绝循环，因此每次采样都是 O(1)。

注意：``mean`` 是「未截断」指数分布的均值参数；样本被限制在 ``[low, high]`` 内后，
实际均值会略小于 ``mean``（可由 :meth:`TruncatedExponential.theoretical_mean` 查看）。
"""

from __future__ import annotations

import math
import random
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


class TruncatedExponential:
    """截断指数分布采样器。"""

    def __init__(self, mean: float, low: float, high: float, rng: random.Random) -> None:
        if mean <= 0:
            raise ValueError("mean 必须 > 0")
        if low < 0:
            raise ValueError("min 不能为负")
        if high < low:
            raise ValueError("max 必须 >= min")
        self.mean = float(mean)
        self.low = float(low)
        self.high = float(high)
        self._rng = rng
        self._lambda = 1.0 / self.mean
        self._span = self.high - self.low
        self._denom = 1.0 - math.exp(-self._lambda * self._span)

    def sample(self) -> float:
        """返回 ``[low, high]`` 内的一个样本。"""
        if self._span <= 0 or self._denom <= 0:
            return self.low
        # u ∈ [0, 1)，钳制上界避免 log(0)
        u = min(max(self._rng.random(), 0.0), 1.0 - 1e-12)
        value = self.low - math.log(1.0 - u * self._denom) / self._lambda
        return min(max(value, self.low), self.high)

    def theoretical_mean(self) -> float:
        """截断后的理论均值，用于校验采样是否正确。"""
        if self._span <= 0 or self._denom <= 0:
            return self.low
        return (
            self.low
            + 1.0 / self._lambda
            - self._span * math.exp(-self._lambda * self._span) / self._denom
        )


@dataclass
class SleepStats:
    """已采样间隔的统计量。"""

    count: int = 0
    total_seconds: float = 0.0
    min_seconds: Optional[float] = None
    max_seconds: Optional[float] = None

    def add(self, seconds: float) -> None:
        self.count += 1
        self.total_seconds += seconds
        self.min_seconds = seconds if self.min_seconds is None else min(self.min_seconds, seconds)
        self.max_seconds = seconds if self.max_seconds is None else max(self.max_seconds, seconds)

    @property
    def mean_seconds(self) -> float:
        return self.total_seconds / self.count if self.count else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "total_seconds": round(self.total_seconds, 3),
            "mean_seconds": round(self.mean_seconds, 3),
            "min_seconds": round(self.min_seconds, 3) if self.min_seconds is not None else None,
            "max_seconds": round(self.max_seconds, 3) if self.max_seconds is not None else None,
        }


class SleepSampler:
    """按配置构造分布，并记录采样统计。"""

    def __init__(
        self,
        distribution: str,
        mean_seconds: float,
        min_seconds: float,
        max_seconds: float,
        rng: random.Random,
    ) -> None:
        if distribution != "truncated_exponential":
            raise ValueError(f"暂不支持的 sleep 分布: {distribution!r}")
        self.distribution = distribution
        self.mean_seconds = float(mean_seconds)
        self.min_seconds = float(min_seconds)
        self.max_seconds = float(max_seconds)
        self._distribution = TruncatedExponential(
            mean_seconds, min_seconds, max_seconds, rng
        )
        self.stats = SleepStats()

    def sample(self) -> float:
        seconds = self._distribution.sample()
        self.stats.add(seconds)
        return seconds

    def describe(self) -> str:
        return (
            f"{self.distribution}(mean={self.mean_seconds:g}s, "
            f"min={self.min_seconds:g}s, max={self.max_seconds:g}s)"
        )

    def theoretical_mean(self) -> float:
        return self._distribution.theoretical_mean()


def interruptible_sleep(seconds: float, stop_event: threading.Event,
                        tick_seconds: float = 0.2) -> bool:
    """等待 ``seconds`` 秒；若 ``stop_event`` 被置位则提前返回。

    Returns:
        bool: 完整睡满返回 True，被中断返回 False。
    """
    if seconds <= 0:
        return not stop_event.is_set()
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        if stop_event.wait(min(remaining, tick_seconds)):
            return False
