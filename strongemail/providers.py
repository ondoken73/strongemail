"""Mailbox provider (portal) profiles.

Rate numbers are deliberately conservative *starting points* for a fresh IP /
domain. Providers do not publish exact limits; tune them from the 4xx deferral
rates you observe (see reputation.BounceKind.THROTTLED).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .domains import domain_of


@dataclass(frozen=True)
class ProviderProfile:
    key: str
    name: str
    domains: frozenset[str]
    # Per sending IP. Throttle backs off further when the provider defers us.
    max_per_minute: int
    max_connections: int
    # Requirements the provider enforces (or strongly signals) for bulk senders.
    requires_dmarc: bool = True
    requires_one_click_unsubscribe: bool = True
    requires_fcrdns: bool = True
    # User-reported spam rate the provider tolerates before penalising.
    spam_rate_ceiling: float = 0.003
    notes: tuple[str, ...] = field(default_factory=tuple)


PROVIDERS: dict[str, ProviderProfile] = {
    p.key: p
    for p in [
        ProviderProfile(
            key="gmail", name="Gmail",
            domains=frozenset({"gmail.com", "googlemail.com"}),
            max_per_minute=600, max_connections=5,
            notes=(
                "하루 5,000통 이상 대량 발송자: SPF+DKIM+DMARC(p=none 이상), From 정렬 필수",
                "RFC 8058 원클릭 수신거부(List-Unsubscribe-Post), 요청 2일 내 처리",
                "Postmaster Tools 스팸 신고율 0.1% 미만 유지, 0.3% 이상이면 차단 대상",
                "발송 IP의 PTR(역방향 DNS)과 정방향 DNS 일치, TLS 연결",
            ),
        ),
        ProviderProfile(
            key="yahoo", name="Yahoo/AOL",
            domains=frozenset({"yahoo.com", "ymail.com", "rocketmail.com", "aol.com", "yahoo.co.kr"}),
            max_per_minute=300, max_connections=3,
            notes=("Gmail과 동일한 대량 발송자 기준 (SPF/DKIM/DMARC, 원클릭 수신거부, 0.3%)",),
        ),
        ProviderProfile(
            key="microsoft", name="Outlook/Hotmail",
            domains=frozenset({"outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.kr"}),
            max_per_minute=300, max_connections=3,
            notes=(
                "하루 5,000통 이상 발송 시 SPF/DKIM/DMARC 미충족 메일 거부 (550 5.7.515)",
                "SNDS / JMRP(피드백 루프) 등록 권장",
            ),
        ),
        ProviderProfile(
            key="naver", name="네이버 메일",
            domains=frozenset({"naver.com"}),
            max_per_minute=300, max_connections=3,
            notes=(
                "SPF 미설정·불일치 메일은 스팸/거부 처리 비율이 매우 높음 — SPF 필수, DKIM/DMARC 권장",
                "광고 메일은 제목 '(광고)' 표기, 수신거부 안내 등 정보통신망법 준수 여부를 강하게 봄",
                "동일 IP의 급격한 발송량 증가에 민감 — 웜업 필수",
            ),
        ),
        ProviderProfile(
            key="kakao", name="다음/카카오 메일",
            domains=frozenset({"daum.net", "hanmail.net", "kakao.com"}),
            max_per_minute=200, max_connections=2,
            notes=(
                "SPF/DKIM 인증 및 PTR 일치 확인, 미인증 대량메일은 스팸함 또는 거부",
                "수신자 스팸 신고가 누적되면 IP 단위로 일시 차단 (421 응답)",
            ),
        ),
        ProviderProfile(
            key="nate", name="네이트 메일",
            domains=frozenset({"nate.com"}),
            max_per_minute=100, max_connections=2,
            notes=("발송량이 적은 포털 — 낮은 속도로 시작",),
        ),
    ]
}

DEFAULT_PROVIDER = ProviderProfile(
    key="other", name="기타", domains=frozenset(),
    max_per_minute=120, max_connections=2,
    requires_dmarc=False, requires_one_click_unsubscribe=False, requires_fcrdns=True,
)

_DOMAIN_INDEX = {d: p for p in PROVIDERS.values() for d in p.domains}


def provider_for(address: str) -> ProviderProfile:
    """Map a recipient address to its mailbox provider profile."""
    return _DOMAIN_INDEX.get(domain_of(address), DEFAULT_PROVIDER)
