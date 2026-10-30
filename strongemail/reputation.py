"""Reputation protection: bounce classification, suppression list, rate monitoring, IP warm-up.

Portals judge you mostly on three numbers per sending IP/domain:
  * hard-bounce rate  (sending to dead addresses = bought/old list)
  * spam complaint rate (Gmail: keep < 0.1 %, never reach 0.3 %)
  * volume consistency (sudden spikes from a cold IP look like a hijacked server)
This module tracks all three and tells the sender when to slow down or stop.
"""

from __future__ import annotations

import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum


class BounceKind(str, Enum):
    DELIVERED = "delivered"
    HARD = "hard"            # address does not exist -> suppress forever
    SOFT = "soft"            # temporary (mailbox full, greylisting) -> retry, suppress after repeats
    THROTTLED = "throttled"  # provider asks us to slow down -> back off the whole provider
    BLOCKED = "blocked"      # reputation / policy block -> stop and investigate, NOT the recipient's fault
    AUTH_FAILED = "auth"     # SPF/DKIM/DMARC failure -> fix DNS before sending more


_THROTTLE_HINTS = re.compile(r"rate|too many|throttl|try again later|deferred|limit|4\.7\.28|421 4\.7\.0", re.I)
_AUTH_HINTS = re.compile(r"5\.7\.2[3-7]|5\.7\.515|spf|dkim|dmarc|unauthenticated|not authenticated", re.I)
_BLOCK_HINTS = re.compile(r"spam|block|blacklist|reputation|policy|rbl|spamhaus|5\.7\.1\b|5\.7\.0\b", re.I)
_ENHANCED = re.compile(r"\b([245])\.(\d{1,3})\.(\d{1,3})\b")


def classify_smtp_response(code: int, text: str = "") -> BounceKind:
    """Classify an SMTP reply (sync or from a DSN) into an action category."""
    if 200 <= code < 300:
        return BounceKind.DELIVERED
    m = _ENHANCED.search(text)
    enhanced = m.group(0) if m else ""
    if _AUTH_HINTS.search(text):
        return BounceKind.AUTH_FAILED
    if code >= 500:
        if enhanced.startswith(("5.1.", "5.2.1")) or re.search(r"no such user|user unknown|does not exist|"
                                                              r"invalid recipient|존재하지|없는 (사용자|계정)", text, re.I):
            return BounceKind.HARD
        if enhanced.startswith("5.2.2"):  # mailbox full: treat as soft
            return BounceKind.SOFT
        if _BLOCK_HINTS.search(text) or enhanced.startswith("5.7."):
            return BounceKind.BLOCKED
        return BounceKind.HARD
    if _THROTTLE_HINTS.search(text) or code == 421:
        return BounceKind.THROTTLED
    return BounceKind.SOFT


class SuppressionScope(str, Enum):
    ALL = "all"              # never send anything (hard bounce, complaint)
    MARKETING = "marketing"  # unsubscribed: transactional mail still allowed


@dataclass(frozen=True)
class Thresholds:
    complaint_warn: float = 0.001   # 0.1 %
    complaint_pause: float = 0.003  # 0.3 % - Gmail/Yahoo enforcement line
    hard_bounce_warn: float = 0.02
    hard_bounce_pause: float = 0.05
    blocked_pause: float = 0.05     # share of attempts answered with policy blocks
    min_volume: int = 200           # don't judge rates on tiny samples
    window_seconds: int = 24 * 3600
    soft_bounce_suppress_after: int = 3


class Health(str, Enum):
    OK = "ok"
    WARN = "warn"
    PAUSED = "paused"


@dataclass(frozen=True)
class HealthReport:
    health: Health
    sent: int
    hard_bounce_rate: float
    complaint_rate: float
    blocked_rate: float
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class WarmupPlan:
    """Daily cap per provider for a new IP. Roughly doubles every day until max_daily."""
    start_daily: int = 50
    growth: float = 1.8
    max_daily: int = 500_000

    def cap(self, day_index: int) -> int:
        return min(self.max_daily, int(self.start_daily * (self.growth ** max(day_index, 0))))


class Store:
    """SQLite-backed suppression list and delivery event log."""

    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock, self._db:
            self._db.executescript("""
                CREATE TABLE IF NOT EXISTS suppressions (
                    address TEXT NOT NULL, scope TEXT NOT NULL, reason TEXT NOT NULL, created REAL NOT NULL,
                    PRIMARY KEY (address, scope));
                CREATE TABLE IF NOT EXISTS events (
                    ts REAL NOT NULL, kind TEXT NOT NULL, address TEXT NOT NULL,
                    provider TEXT NOT NULL, sending_domain TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_ts ON events (ts, sending_domain, provider);
                CREATE INDEX IF NOT EXISTS events_addr ON events (address, ts);
            """)

    def execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock, self._db:
            return self._db.execute(sql, params).fetchall()


class SuppressionList:
    def __init__(self, store: Store):
        self._s = store

    def add(self, address: str, scope: SuppressionScope, reason: str) -> None:
        self._s.execute("INSERT OR REPLACE INTO suppressions VALUES (?, ?, ?, ?)",
                        (address.lower(), scope.value, reason, time.time()))

    def remove(self, address: str, scope: SuppressionScope | None = None) -> None:
        if scope is None:
            self._s.execute("DELETE FROM suppressions WHERE address = ?", (address.lower(),))
        else:
            self._s.execute("DELETE FROM suppressions WHERE address = ? AND scope = ?", (address.lower(), scope.value))

    def blocked_reason(self, address: str, marketing: bool) -> str | None:
        scopes = ("all", "marketing") if marketing else ("all",)
        rows = self._s.execute(
            f"SELECT reason FROM suppressions WHERE address = ? AND scope IN ({','.join('?' * len(scopes))})",
            (address.lower(), *scopes))
        return rows[0][0] if rows else None


class ReputationMonitor:
    """Records delivery outcomes and decides whether a domain/provider pair may keep sending."""

    def __init__(self, store: Store, thresholds: Thresholds = Thresholds(), clock=time.time):
        self._s = store
        self.thresholds = thresholds
        self._clock = clock
        self.suppressions = SuppressionList(store)

    def record(self, kind: BounceKind | str, address: str, provider: str, sending_domain: str) -> None:
        kind = kind.value if isinstance(kind, BounceKind) else kind
        address = address.lower()
        self._s.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?)",
                        (self._clock(), kind, address, provider, sending_domain))
        if kind == BounceKind.HARD.value:
            self.suppressions.add(address, SuppressionScope.ALL, "hard_bounce")
        elif kind == "complaint":
            self.suppressions.add(address, SuppressionScope.ALL, "complaint")
        elif kind == "unsubscribe":
            self.suppressions.add(address, SuppressionScope.MARKETING, "unsubscribe")
        elif kind == BounceKind.SOFT.value:
            self._maybe_suppress_soft(address)

    def _maybe_suppress_soft(self, address: str) -> None:
        recent = self._s.execute(
            "SELECT kind FROM events WHERE address = ? AND kind IN ('soft', 'delivered') ORDER BY ts DESC LIMIT ?",
            (address, self.thresholds.soft_bounce_suppress_after))
        if len(recent) == self.thresholds.soft_bounce_suppress_after and all(k == "soft" for (k,) in recent):
            self.suppressions.add(address, SuppressionScope.ALL, "repeated_soft_bounce")

    def sent_since(self, since: float, provider: str, sending_domain: str) -> int:
        return self._s.execute(
            "SELECT COUNT(*) FROM events WHERE ts >= ? AND provider = ? AND sending_domain = ? AND kind != 'complaint' "
            "AND kind != 'unsubscribe'", (since, provider, sending_domain))[0][0]

    def health(self, sending_domain: str, provider: str | None = None) -> HealthReport:
        t = self.thresholds
        since = self._clock() - t.window_seconds
        sql = "SELECT kind, COUNT(*) FROM events WHERE ts >= ? AND sending_domain = ?"
        params: tuple = (since, sending_domain)
        if provider:
            sql += " AND provider = ?"
            params += (provider,)
        counts = dict(self._s.execute(sql + " GROUP BY kind", params))
        attempts = sum(v for k, v in counts.items() if k not in ("complaint", "unsubscribe"))
        delivered = counts.get("delivered", 0)
        hard = counts.get("hard", 0) / attempts if attempts else 0.0
        blocked = (counts.get("blocked", 0) + counts.get("auth", 0)) / attempts if attempts else 0.0
        complaints = counts.get("complaint", 0) / delivered if delivered else 0.0

        reasons, health = [], Health.OK
        if counts.get("auth", 0):
            health = Health.PAUSED
            reasons.append(f"인증(SPF/DKIM/DMARC) 실패 응답 {counts['auth']}건 — DNS 를 먼저 고치세요")
        if attempts >= t.min_volume:
            for rate, warn, pause, label in (
                (complaints, t.complaint_warn, t.complaint_pause, "스팸 신고율"),
                (hard, t.hard_bounce_warn, t.hard_bounce_pause, "하드바운스율"),
                (blocked, t.blocked_pause / 2, t.blocked_pause, "정책 차단율"),
            ):
                if rate >= pause:
                    health = Health.PAUSED
                    reasons.append(f"{label} {rate:.2%} ≥ 중단 기준 {pause:.2%}")
                elif rate >= warn:
                    health = health if health is Health.PAUSED else Health.WARN
                    reasons.append(f"{label} {rate:.2%} ≥ 경고 기준 {warn:.2%}")
        return HealthReport(health, attempts, hard, complaints, blocked, tuple(reasons))
