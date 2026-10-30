"""발송 IP 차단 대응: 탐지 → 해당 포털 발송 중지 → 원인 조치 → 소명(해제 요청) → 해제 확인 → 재웜업.

소명은 원인을 고치지 않은 상태로 내면 거절되고, 반복되면 해제가 더 어려워진다.
그래서 `build_appeal` 은 준비 상태(DNS 인증, 현재 평판, 조치 내역)를 먼저 검사한다.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum

from .dns_audit import DnsLookupError, Resolver
from .findings import Finding, Severity, has_errors
from .reputation import Health, HealthReport, Store

KST = timezone(timedelta(hours=9))


# ------------------------------------------------------------- 소명 채널

@dataclass(frozen=True)
class AppealChannel:
    key: str
    name: str
    how: str            # 어디서 어떻게 요청하는지
    url: str
    language: str       # 소명서 작성 언어
    typical_wait: str
    affects_all: bool = False  # 공용 차단목록(DNSBL)이면 모든 포털 발송에 영향


# URL/메뉴 경로는 각 사가 수시로 바꾼다. 소명 전에 반드시 최신 경로를 확인할 것.
APPEAL_CHANNELS: dict[str, AppealChannel] = {c.key: c for c in [
    AppealChannel("naver", "네이버 메일", "네이버 고객센터 > 메일 > 대량메일/수신차단 해제 문의(1:1 문의)",
                  "https://help.naver.com", "ko", "영업일 기준 수일"),
    AppealChannel("kakao", "다음/카카오 메일", "카카오 고객센터 > 다음 메일 > 스팸/수신 차단 해제 문의",
                  "https://cs.kakao.com", "ko", "영업일 기준 수일"),
    AppealChannel("nate", "네이트 메일", "네이트 고객센터 > 메일 > 1:1 문의", "https://helpdesk.nate.com", "ko", "수일"),
    AppealChannel("gmail", "Gmail", "Postmaster Tools 로 평판 확인 후 Gmail 대량 발송자 문의 양식(Sender contact form) 제출. "
                  "IP/도메인 평판은 자동 회복이 원칙이라 원인 제거 후 발송량을 낮춰 기다리는 것이 우선",
                  "https://postmaster.google.com", "en", "수일~수주 (자동 회복)"),
    AppealChannel("microsoft", "Outlook/Hotmail", "Outlook.com 발신자 지원(Sender Support) 양식. "
                  "응답에 S3150/S3140 코드가 있으면 함께 기재. Office 365 수신 차단은 sender.office.com 에서 해제",
                  "https://olcsupport.office.com", "en", "1~3 영업일"),
    AppealChannel("yahoo", "Yahoo/AOL", "Yahoo Sender Hub 에서 발송자 지원 요청", "https://senders.yahooinc.com", "en", "수일"),
    AppealChannel("spamhaus", "Spamhaus (공용 차단목록)", "IP 조회 후 리스트 종류(SBL/XBL/CSS/PBL)별 안내에 따라 해제 요청. "
                  "XBL/CSS 는 감염·오설정 해결이 먼저", "https://check.spamhaus.org", "en", "수시간~수일", True),
    AppealChannel("barracuda", "Barracuda (공용 차단목록)", "Removal Request 양식 제출",
                  "https://www.barracudacentral.org/rbl/removal-request", "en", "약 12~24시간", True),
    AppealChannel("spamcop", "SpamCop (공용 차단목록)", "별도 요청 없이 신고가 멈추면 24시간 후 자동 해제",
                  "https://www.spamcop.net/bl.shtml", "en", "24시간 (자동)", True),
]}


# ----------------------------------------------------------- DNSBL 조회

@dataclass(frozen=True)
class Dnsbl:
    key: str
    zone: str
    # 조회 거부/오류를 뜻하는 응답 (등재가 아님). Spamhaus 는 공용 DNS(8.8.8.8 등) 조회를 거부한다.
    error_codes: frozenset[str] = frozenset()


DNSBLS = (
    Dnsbl("spamhaus", "zen.spamhaus.org", frozenset({"127.255.255.252", "127.255.255.254", "127.255.255.255"})),
    Dnsbl("barracuda", "b.barracudacentral.org"),
    Dnsbl("spamcop", "bl.spamcop.net"),
)


@dataclass(frozen=True)
class DnsblResult:
    list_key: str
    listed: bool | None  # None = 판단 불가 (조회 거부/실패)
    codes: tuple[str, ...] = ()
    note: str = ""


def _reverse(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split(".")))
    return ".".join(reversed(addr.exploded.replace(":", "")))


def check_dnsbls(ip: str, resolver: Resolver, lists: tuple[Dnsbl, ...] = DNSBLS) -> list[DnsblResult]:
    results = []
    for bl in lists:
        try:
            answers = [a for a in resolver.addresses(f"{_reverse(ip)}.{bl.zone}") if a.startswith("127.")]
        except DnsLookupError as e:
            results.append(DnsblResult(bl.key, None, note=f"조회 실패: {e}"))
            continue
        if answers and all(a in bl.error_codes for a in answers):
            results.append(DnsblResult(bl.key, None, tuple(answers),
                                       "조회 거부 — 공용 DNS 가 아닌 자체 리졸버로 조회하세요"))
        else:
            results.append(DnsblResult(bl.key, bool(answers), tuple(answers)))
    return results


# ---------------------------------------------------------- 차단 원인 탐지

_SOURCE_PATTERNS = (
    ("spamhaus", re.compile(r"spamhaus", re.I)),
    ("barracuda", re.compile(r"barracuda", re.I)),
    ("spamcop", re.compile(r"spamcop", re.I)),
    ("microsoft", re.compile(r"\bS3(1[0-9]{2})\b|banned sending ip|outlook\.com|hotmail", re.I)),
)


def detect_block_source(smtp_text: str, provider_key: str) -> str:
    """차단 응답이 공용 차단목록 때문인지, 포털 자체 차단인지 구분."""
    for key, pattern in _SOURCE_PATTERNS:
        if pattern.search(smtp_text):
            return key
    return provider_key


# --------------------------------------------------------------- 사고 기록

class IncidentState(str, Enum):
    OPEN = "open"            # 차단 확인, 해당 대상 발송 중지
    APPEALED = "appealed"    # 소명 제출, 회신 대기 (발송 계속 중지)
    RESOLVED = "resolved"    # 해제 확인 → 재웜업


@dataclass
class Incident:
    id: int
    ip: str
    target: str
    state: IncidentState
    opened_at: float
    evidence: str
    appealed_at: float | None = None
    resolved_at: float | None = None
    actions: list[str] = field(default_factory=list)
    appeal_count: int = 0

    @property
    def channel(self) -> AppealChannel | None:
        return APPEAL_CHANNELS.get(self.target)


class IncidentLog:
    def __init__(self, store: Store, clock=time.time):
        self._s = store
        self._clock = clock
        store.execute("""CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, target TEXT NOT NULL, state TEXT NOT NULL,
            opened_at REAL NOT NULL, evidence TEXT NOT NULL, appealed_at REAL, resolved_at REAL,
            actions TEXT NOT NULL DEFAULT '', appeal_count INTEGER NOT NULL DEFAULT 0)""")

    _COLS = "id, ip, target, state, opened_at, evidence, appealed_at, resolved_at, actions, appeal_count"

    def _row(self, r) -> Incident:
        return Incident(r[0], r[1], r[2], IncidentState(r[3]), r[4], r[5], r[6], r[7],
                        [a for a in r[8].split("\n") if a], r[9])

    def get(self, incident_id: int) -> Incident:
        rows = self._s.execute(f"SELECT {self._COLS} FROM incidents WHERE id = ?", (incident_id,))
        if not rows:
            raise KeyError(incident_id)
        return self._row(rows[0])

    def active(self, ip: str | None = None) -> list[Incident]:
        sql = f"SELECT {self._COLS} FROM incidents WHERE state != 'resolved'"
        params: tuple = ()
        if ip:
            sql += " AND ip = ?"
            params = (ip,)
        return [self._row(r) for r in self._s.execute(sql + " ORDER BY opened_at", params)]

    def open(self, ip: str, target: str, evidence: str) -> Incident:
        """같은 IP·대상의 진행 중 사고가 있으면 그것을 돌려준다 (중복 생성 안 함)."""
        for inc in self.active(ip):
            if inc.target == target:
                return inc
        # 같은 대상에 대한 과거 소명 횟수를 이어받는다 — 반복 차단이면 소명서에 재발 방지책이 더 중요
        prior = self._s.execute("SELECT COALESCE(MAX(appeal_count), 0) FROM incidents WHERE ip = ? AND target = ?",
                                (ip, target))[0][0]
        self._s.execute("INSERT INTO incidents (ip, target, state, opened_at, evidence, appeal_count) "
                        "VALUES (?, ?, 'open', ?, ?, ?)", (ip, target, self._clock(), evidence[:1000], prior))
        return self.active(ip)[-1]

    def add_action(self, incident_id: int, action: str) -> None:
        inc = self.get(incident_id)
        self._s.execute("UPDATE incidents SET actions = ? WHERE id = ?", ("\n".join([*inc.actions, action]), incident_id))

    def mark_appealed(self, incident_id: int) -> None:
        self._s.execute("UPDATE incidents SET state = 'appealed', appealed_at = ?, appeal_count = appeal_count + 1 "
                        "WHERE id = ?", (self._clock(), incident_id))

    def resolve(self, incident_id: int) -> None:
        self._s.execute("UPDATE incidents SET state = 'resolved', resolved_at = ? WHERE id = ?",
                        (self._clock(), incident_id))

    def blocking(self, ip: str, provider_key: str) -> Incident | None:
        """이 IP 로 이 포털에 보내면 안 되는 진행 중 사고."""
        for inc in self.active(ip):
            ch = inc.channel
            if inc.target == provider_key or (ch is not None and ch.affects_all):
                return inc
        return None

    def last_resolved(self, ip: str, provider_key: str) -> float | None:
        rows = self._s.execute(
            "SELECT MAX(resolved_at) FROM incidents WHERE ip = ? AND state = 'resolved' AND target IN (?, ?, ?, ?)",
            (ip, provider_key, *[c.key for c in APPEAL_CHANNELS.values() if c.affects_all]))
        return rows[0][0]


# ----------------------------------------------------------------- 소명서

@dataclass
class AppealContext:
    company: str
    contact_name: str
    contact_email: str
    contact_phone: str
    sending_domain: str
    mail_type: str                      # 예: "회원 대상 주문/배송 알림 및 수신동의 회원 대상 뉴스레터"
    consent_method: str                 # 예: "회원가입 시 별도 체크박스(기본 해제)로 광고 수신동의, 2년마다 재확인"
    daily_volume: int
    dns_findings: list[Finding]         # dns_audit.audit_domain 결과
    health: HealthReport                # ReputationMonitor.health(domain, provider)
    dnsbl_results: list[DnsblResult] = field(default_factory=list)


@dataclass
class AppealPacket:
    ready: bool
    blockers: list[str]
    channel: AppealChannel | None
    letter: str


def _fmt(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, KST).strftime("%Y-%m-%d %H:%M KST") if ts else "-"


def build_appeal(inc: Incident, ctx: AppealContext, *, now: float | None = None) -> AppealPacket:
    now = now or time.time()
    blockers: list[str] = []
    if has_errors(ctx.dns_findings):
        bad = ", ".join(f.code for f in ctx.dns_findings if f.severity is Severity.ERROR)
        blockers.append(f"DNS 인증 오류가 남아 있습니다 ({bad}). 고치기 전 소명은 거절됩니다.")
    if ctx.health.health is Health.PAUSED:
        blockers.append("현재 평판 지표가 중지 기준을 넘습니다: " + "; ".join(ctx.health.reasons))
    if not inc.actions:
        blockers.append("원인 조치 내역이 없습니다. 무엇을 고쳤는지(목록 정리, 발송량 축소, 계정 탈취 차단 등) 기록하세요.")
    if now - inc.opened_at < 12 * 3600 and inc.target in ("gmail", "microsoft", "yahoo"):
        blockers.append("차단 후 12시간이 지나지 않았습니다. 조치 효과가 지표에 반영된 뒤 제출하세요.")
    still_listed = [r.list_key for r in ctx.dnsbl_results if r.listed and r.list_key != inc.target]
    if still_listed:
        blockers.append(f"다른 공용 차단목록에도 등재되어 있습니다: {', '.join(still_listed)} — 함께 처리하세요.")

    ch = inc.channel
    auth = "SPF, DKIM(2048bit), DMARC 모두 통과" if not has_errors(ctx.dns_findings) else "점검 중"
    h = ctx.health
    actions = "\n".join(f"  {i}. {a}" for i, a in enumerate(inc.actions, 1)) or "  (작성 필요)"
    repeat = inc.appeal_count > 0

    if ch is None or ch.language == "ko":
        letter = f"""제목: [차단 해제 요청] 발송 IP {inc.ip} ({ctx.sending_domain}) 수신 차단 해제 요청드립니다

안녕하세요. {ctx.company}의 메일 발송 담당자 {ctx.contact_name}입니다.
{_fmt(inc.opened_at)}부터 아래 IP에서 귀사로 보내는 메일이 차단되어 해제를 요청드립니다.

1. 발송 정보
  - 발송 IP: {inc.ip}
  - 발신 도메인: {ctx.sending_domain}
  - 메일 종류: {ctx.mail_type}
  - 일 평균 발송량: {ctx.daily_volume:,}통
  - 발신 인증: {auth}
  - 수신 서버 응답: {inc.evidence}

2. 수신 동의 및 수신거부
  - 수신 동의: {ctx.consent_method}
  - 광고 메일은 제목에 (광고)를 표기하고, 본문 하단 및 List-Unsubscribe 헤더로 원클릭 수신거부를 제공합니다.
  - 반송·스팸 신고·수신거부 주소는 즉시 발송 대상에서 제외됩니다.

3. 원인 및 조치 내역
{actions}

4. 현재 지표 (최근 24시간, {h.sent:,}통 기준)
  - 하드바운스율 {h.hard_bounce_rate:.2%} / 스팸 신고율 {h.complaint_rate:.2%}
  - 차단 이후 귀사로의 발송은 중지한 상태이며, 해제 후에는 소량부터 단계적으로 늘리겠습니다.
{"  - 이전에도 차단 해제를 요청드린 이력이 있어, 재발 방지를 위해 위 조치를 상시 적용했습니다." + chr(10) if repeat else ""}
확인 후 차단 해제를 부탁드립니다. 추가 자료가 필요하시면 아래로 연락 주십시오.

{ctx.company} {ctx.contact_name}
{ctx.contact_email} / {ctx.contact_phone}
"""
    else:
        letter = f"""Subject: Delisting request for {inc.ip} ({ctx.sending_domain})

Hello,

I am {ctx.contact_name}, responsible for email delivery at {ctx.company}.
Mail from {inc.ip} has been rejected since {_fmt(inc.opened_at)}. We have investigated and fixed the cause,
and respectfully request a review.

Sending details
  - IP: {inc.ip}
  - Sending domain: {ctx.sending_domain}
  - Mail type: {ctx.mail_type}
  - Average daily volume: {ctx.daily_volume:,}
  - Authentication: {"SPF, DKIM (2048-bit) and DMARC all pass and align" if not has_errors(ctx.dns_findings) else "being fixed"}
  - Rejection received: {inc.evidence}

Consent and unsubscribe
  - Consent: {ctx.consent_method}
  - RFC 8058 one-click unsubscribe on every bulk message; bounces, complaints and unsubscribes are suppressed immediately.

Root cause and remediation
{actions}

Current metrics (last 24h, {h.sent:,} messages)
  - Hard bounce rate {h.hard_bounce_rate:.2%}, complaint rate {h.complaint_rate:.2%}
  - Sending to your service is paused; after delisting we will ramp volume up gradually.
{"  - This is a repeat incident; the measures above are now permanently enforced." + chr(10) if repeat else ""}
Thank you for your review.

{ctx.contact_name}, {ctx.company}
{ctx.contact_email} / {ctx.contact_phone}
"""
    return AppealPacket(not blockers, blockers, ch, letter)
