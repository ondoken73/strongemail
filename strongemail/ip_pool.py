"""멀티 IP: IP 풀, IP 별 웜업, 차단 시 페일오버와 '돌려막기' 방지.

원칙
  * 메일 종류(거래성/광고)와 고객 규모별로 풀을 나눈다. 광고 IP가 막혀도 인증번호 메일은 나가야 한다.
  * 한 IP가 특정 포털에서 막히면 같은 풀의 다른 IP로 넘기되, 넘어간 IP의 웜업/일일 한도를 넘지 않는다.
  * 같은 풀에서 여러 IP가 같은 포털에 동시에 막히면 IP가 아니라 목록·콘텐츠 문제다.
    이때 IP를 계속 바꿔 보내면(snowshoeing) 포털이 IP 대역 전체를 차단하므로 풀 전체를 그 포털에 대해 멈춘다.
  * 예비 IP는 평소에도 소량을 보내 '따뜻하게' 유지해야 페일오버 때 쓸 수 있다 (차가운 IP로 갑자기 넘기면 바로 막힌다).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from .blocklist import IncidentLog
from .providers import ProviderProfile
from .reputation import ReputationMonitor, WarmupPlan

KST = timezone(timedelta(hours=9))


@dataclass(frozen=True)
class SendingIP:
    address: str
    helo: str                          # PTR 과 같은 이름 (mail1.service.com)
    warmup_started: date | None = None  # None = 이미 웜업 완료
    weight: int = 1                     # 같은 조건이면 가중치 높은 IP를 더 많이 사용


@dataclass
class IPPool:
    name: str
    ips: list[SendingIP]
    # 이 비율 이상의 IP가 같은 포털에서 막히면 풀 전체를 그 포털에 대해 중지 (최소 2개)
    max_blocked_share: float = 0.5
    _rr: int = field(default=0, repr=False)


@dataclass(frozen=True)
class IPChoice:
    ip: SendingIP | None
    reason: str = ""
    retry_after: float = 0.0


class IPSelector:
    def __init__(self, pools: list[IPPool], monitor: ReputationMonitor, incidents: IncidentLog,
                 warmup: WarmupPlan = WarmupPlan(), clock=None):
        self.pools = {p.name: p for p in pools}
        self.monitor = monitor
        self.incidents = incidents
        self.warmup = warmup
        self._clock = clock or monitor._clock

    def all_ips(self) -> list[SendingIP]:
        seen: dict[str, SendingIP] = {}
        for p in self.pools.values():
            for ip in p.ips:
                seen.setdefault(ip.address, ip)
        return list(seen.values())

    def _today(self) -> tuple[date, float]:
        now = datetime.fromtimestamp(self._clock(), KST)
        midnight = datetime.combine(now.date(), datetime.min.time(), KST)
        return now.date(), midnight.timestamp()

    def _until_midnight(self) -> float:
        today, midnight = self._today()
        return midnight + 86400 - self._clock()

    def daily_cap(self, ip: SendingIP, provider: ProviderProfile) -> int | None:
        """IP·포털별 오늘 한도. 새 IP이거나 차단 해제 직후면 웜업 한도, 아니면 None(제한 없음)."""
        start = ip.warmup_started
        resolved = self.incidents.last_resolved(ip.address, provider.key)
        if resolved is not None:
            rewarm = datetime.fromtimestamp(resolved, KST).date()
            start = rewarm if start is None else max(start, rewarm)
        if start is None:
            return None
        today, _ = self._today()
        cap = self.warmup.cap(today.toordinal() - start.toordinal())
        return None if cap >= self.warmup.max_daily else cap

    def remaining(self, ip: SendingIP, provider: ProviderProfile) -> float:
        cap = self.daily_cap(ip, provider)
        if cap is None:
            return math.inf
        _, midnight = self._today()
        return cap - self.monitor.sent_since(midnight, provider=provider.key, ip=ip.address)

    def blocked_ips(self, pool: IPPool, provider: ProviderProfile) -> list[str]:
        return [ip.address for ip in pool.ips if self.incidents.blocking(ip.address, provider.key)]

    def choose(self, pool_name: str, provider: ProviderProfile) -> IPChoice:
        pool = self.pools.get(pool_name)
        if pool is None or not pool.ips:
            return IPChoice(None, f"IP 풀 '{pool_name}' 이 없습니다")
        blocked = self.blocked_ips(pool, provider)
        if len(blocked) >= max(2, math.ceil(len(pool.ips) * pool.max_blocked_share)):
            return IPChoice(None, f"풀 '{pool.name}' 의 IP {len(blocked)}/{len(pool.ips)}개가 {provider.name} 에서 차단 — "
                                  f"IP 문제가 아니라 목록/콘텐츠 문제입니다. 돌려막기 방지를 위해 이 포털 발송 중지",
                            retry_after=3600)
        candidates = []
        for ip in pool.ips:
            if ip.address in blocked:
                continue
            if self.monitor.health(provider=provider.key, ip=ip.address).health.value == "paused":
                continue
            left = self.remaining(ip, provider)
            if left > 0:
                candidates.append((ip, left))
        if not candidates:
            if blocked and len(blocked) == len(pool.ips):
                return IPChoice(None, f"풀 '{pool.name}' 의 모든 IP가 {provider.name} 에서 차단됨", retry_after=3600)
            return IPChoice(None, f"풀 '{pool.name}' 의 {provider.name} 오늘 발송 한도(웜업) 소진",
                            retry_after=self._until_midnight())
        # 가중 라운드로빈: 웜업 중인 IP는 남은 한도 안에서만, 같은 조건이면 weight 순
        pool._rr += 1
        expanded = [ip for ip, _ in candidates for _ in range(ip.weight)]
        return IPChoice(expanded[pool._rr % len(expanded)])
