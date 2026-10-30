"""Per-provider send-rate control with adaptive back-off and warm-up caps."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from .providers import ProviderProfile


@dataclass
class _Bucket:
    rate_per_sec: float
    tokens: float
    updated: float
    backoff_until: float = 0.0
    penalty: float = 1.0  # multiplier on rate, shrinks on 421/4.7.x and recovers over time


class ProviderThrottle:
    """Token bucket per provider. `acquire` never sleeps; it tells the caller how long to wait."""

    RECOVERY_PER_MIN = 0.05  # penalty recovers +5 %/minute of clean sending
    MIN_PENALTY = 0.1

    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _bucket(self, p: ProviderProfile, now: float, ip: str | None) -> _Bucket:
        # 포털 속도 제한은 발송 IP 단위로 걸린다 → (IP, 포털) 별 버킷
        key = f"{ip}|{p.key}" if ip else p.key
        b = self._buckets.get(key)
        if b is None:
            b = self._buckets[key] = _Bucket(p.max_per_minute / 60.0, 1.0, now)
        return b

    def acquire(self, provider: ProviderProfile, ip: str | None = None) -> float:
        """Take one token. Returns 0 if allowed, otherwise seconds to wait before retrying."""
        with self._lock:
            now = self._clock()
            b = self._bucket(provider, now, ip)
            if now < b.backoff_until:
                return b.backoff_until - now
            elapsed = now - b.updated
            b.penalty = min(1.0, b.penalty + self.RECOVERY_PER_MIN * elapsed / 60.0)
            rate = b.rate_per_sec * b.penalty
            b.tokens = min(max(rate, 1.0), b.tokens + elapsed * rate)
            b.updated = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return 0.0
            return (1.0 - b.tokens) / rate

    def report_throttled(self, provider: ProviderProfile, pause_seconds: float = 60.0, ip: str | None = None) -> None:
        """Provider answered 421 / 4.7.x: halve the rate and pause that provider (for that IP)."""
        with self._lock:
            now = self._clock()
            b = self._bucket(provider, now, ip)
            b.penalty = max(self.MIN_PENALTY, b.penalty / 2)
            b.backoff_until = max(b.backoff_until, now + pause_seconds)
            b.tokens = 0.0
