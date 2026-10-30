"""Sending pipeline: every message passes the reputation gates before it touches SMTP.

    고객사·발신주소 확인 -> 발신 도메인 검증 -> 수신제외 -> 수신동의(정보통신망법)
    -> 평판(고객사·도메인·포털) -> IP 선택(풀·차단·웜업·돌려막기 방지) -> (IP,포털) 속도 제한
    -> 메시지 생성 + 고객 도메인으로 DKIM 서명 -> 규정 검사 -> SMTP(선택된 IP) -> 결과 기록
"""

from __future__ import annotations

import smtplib
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, make_msgid
from enum import Enum
from html import escape
from typing import Protocol

from .blocklist import IncidentLog, detect_block_source
from .compliance import lint_message
from .domain_setup import SenderDomainRegistry, VerificationResult, dkim_txt_from_private_key
from .domains import domain_of
from .findings import Finding, Severity, has_errors
from .ip_pool import IPPool, IPSelector, SendingIP
from .providers import provider_for
from .reputation import BounceKind, Health, ReputationMonitor, WarmupPlan, classify_smtp_response
from .tenants import SenderDomain, Tenant, TenantRegistry
from .throttle import ProviderThrottle
from .unsubscribe import UnsubscribeTokens

KST = timezone(timedelta(hours=9))
CONSENT_RECONFIRM = timedelta(days=730)  # 정보통신망법 시행령 제62조의3: 2년마다 수신동의 여부 확인


class Category(str, Enum):
    TRANSACTIONAL = "transactional"  # 가입 인증, 영수증, 비밀번호 재설정 ...
    MARKETING = "marketing"          # 광고성 정보 (뉴스레터, 프로모션)


@dataclass
class Consent:
    """Recipient's opt-in record for marketing mail."""
    marketing_opt_in_at: datetime | None = None
    last_confirmed_at: datetime | None = None   # 2년 주기 재확인 통지 시점
    night_opt_in: bool = False                   # 21:00~08:00 발송 별도 동의 (enforce_night_consent 시 사용)


@dataclass
class OutgoingEmail:
    tenant_id: str
    from_address: str                 # 고객의 발신 주소 (news@shop.co.kr)
    to: str
    subject: str
    text: str
    html: str | None = None
    from_name: str = ""
    category: Category = Category.TRANSACTIONAL
    consent: Consent | None = None
    list_id: str = "default"
    reply_to: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


class Status(str, Enum):
    SENT = "sent"
    DEFERRED = "deferred"   # try again later (retry_after seconds)
    REJECTED = "rejected"   # not sent, must not retry as-is


@dataclass
class SendResult:
    status: Status
    reason: str = ""
    retry_after: float = 0.0
    smtp_code: int | None = None
    bounce: BounceKind | None = None
    ip: str | None = None
    findings: list[Finding] = field(default_factory=list)


class Transport(Protocol):
    def send(self, mail_from: str, rcpt: str, data: bytes, ip: SendingIP) -> tuple[int, str]: ...


def _smtp_error(e: Exception) -> tuple[int, str]:
    if isinstance(e, smtplib.SMTPRecipientsRefused):
        code, msg = next(iter(e.recipients.values()))
        return code, msg.decode(errors="replace")
    if isinstance(e, smtplib.SMTPResponseException):
        err = e.smtp_error
        return e.smtp_code, err.decode(errors="replace") if isinstance(err, bytes) else str(err)
    return 451, f"4.4.1 connection problem: {e}"


class RelayTransport:
    """앞단 MTA(KumoMTA, PowerMTA, Postfix 등)로 넘기고, 사용할 발송 IP는 헤더로 지정.

    MTA 는 이 헤더를 보고 egress source/virtual MTA 를 고른 뒤 헤더를 제거해야 한다.
    헤더는 DKIM 서명 이후에 붙이므로 서명 대상(h=)이 아니다.
    """

    def __init__(self, host: str, port: int = 587, username: str | None = None, password: str | None = None,
                 egress_header: str = "X-Egress-IP", timeout: float = 30.0):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.egress_header, self.timeout = egress_header, timeout

    def send(self, mail_from: str, rcpt: str, data: bytes, ip: SendingIP) -> tuple[int, str]:
        data = f"{self.egress_header}: {ip.address}\r\n".encode() + data
        try:
            with smtplib.SMTP(self.host, self.port, local_hostname=ip.helo, timeout=self.timeout) as s:
                s.starttls(context=ssl.create_default_context())
                if self.username:
                    s.login(self.username, self.password or "")
                s.sendmail(mail_from, [rcpt], data)
            return 250, "OK"
        except (OSError, smtplib.SMTPException) as e:
            return _smtp_error(e)


class DirectMXTransport:
    """수신 도메인 MX 로 직접 연결. 선택된 IP 를 소스 주소로 바인딩하고 HELO 를 PTR 이름으로 보낸다."""

    def __init__(self, resolver=None, timeout: float = 30.0):
        self._resolver = resolver
        self.timeout = timeout

    def _mx_hosts(self, domain: str) -> list[str]:
        if self._resolver:
            return self._resolver.mx(domain) or [domain]
        import dns.resolver

        try:
            answers = sorted(dns.resolver.resolve(domain, "MX"), key=lambda r: r.preference)
            return [str(r.exchange).rstrip(".") for r in answers] or [domain]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return [domain]

    def send(self, mail_from: str, rcpt: str, data: bytes, ip: SendingIP) -> tuple[int, str]:
        last: tuple[int, str] = (451, "4.4.4 no MX reachable")
        for host in self._mx_hosts(domain_of(rcpt)):
            try:
                with smtplib.SMTP(host, 25, local_hostname=ip.helo, timeout=self.timeout,
                                  source_address=(ip.address, 0)) as s:
                    s.ehlo()
                    if s.has_extn("starttls"):
                        s.starttls(context=ssl.create_default_context())
                        s.ehlo()
                    s.sendmail(mail_from, [rcpt], data)
                return 250, "OK"
            except (OSError, smtplib.SMTPException) as e:
                last = _smtp_error(e)
                if 500 <= last[0] < 600:  # 영구 오류는 다음 MX 에 물어도 같다
                    return last
        return last


@dataclass
class MailerConfig:
    unsubscribe_base_url: str           # https://mail.<서비스도메인>
    unsubscribe_secret: bytes
    warmup: WarmupPlan = WarmupPlan()
    # 야간(21~08시) 광고 별도 동의는 법 제50조③ 단서·시행령 제61조로 전자우편은 제외된다.
    # SMS/푸시와 같은 정책을 자율적으로 적용하려면 True.
    enforce_night_consent: bool = False
    require_verified_domain: bool = True


class Mailer:
    def __init__(self, config: MailerConfig, tenants: TenantRegistry, pools: list[IPPool],
                 monitor: ReputationMonitor, transport: Transport, throttle: ProviderThrottle | None = None,
                 clock=time.time):
        self.cfg = config
        self.tenants = tenants
        self.monitor = monitor
        self.transport = transport
        self.throttle = throttle or ProviderThrottle()
        self.tokens = UnsubscribeTokens(config.unsubscribe_secret)
        self._clock = clock
        self.incidents = IncidentLog(monitor.store, clock=clock)
        self.domains = SenderDomainRegistry(monitor.store, clock=clock)
        self.ips = IPSelector(pools, monitor, self.incidents, config.warmup, clock=clock)

    # ------------------------------------------------------------ onboarding

    def tenant_ips(self, tenant: Tenant) -> list[str]:
        return sorted({ip.address for name in set(tenant.pools.values())
                       for ip in (self.ips.pools[name].ips if name in self.ips.pools else [])})

    def verify_tenant_domain(self, tenant_id: str, domain: str) -> VerificationResult:
        """고객 도메인이 우리 IP 전부를 SPF 로 허용하고, 고객 DKIM 키가 게시되었는지 검증."""
        tenant = self.tenants.get(tenant_id)
        sd = tenant.domains[domain.lower()]
        return self.domains.verify(domain, sending_ips=self.tenant_ips(tenant), selector=sd.dkim_selector,
                                   dkim_txt=dkim_txt_from_private_key(sd.dkim_private_key))

    # ------------------------------------------------------------------ gates

    def _now(self) -> datetime:
        return datetime.fromtimestamp(self._clock(), KST)

    def _consent_problem(self, email: OutgoingEmail) -> str | None:
        c = email.consent
        if c is None or c.marketing_opt_in_at is None:
            return "광고 수신동의 기록이 없습니다 (정보통신망법 제50조: 사전 동의 필요)"
        now = self._now()
        last = max(filter(None, (c.marketing_opt_in_at, c.last_confirmed_at)))
        if last.tzinfo is None:
            last = last.replace(tzinfo=KST)
        if now - last > CONSENT_RECONFIRM:
            return "수신동의 후 2년이 지났지만 재확인 통지 기록이 없습니다"
        if self.cfg.enforce_night_consent and (now.hour >= 21 or now.hour < 8) and not c.night_opt_in:
            return "야간(21:00~08:00) 광고 발송에는 별도 동의가 필요합니다"
        return None

    def _next_kst_hour(self, hour: int) -> float:
        now = self._now()
        target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return (target - now).total_seconds()

    # ------------------------------------------------------------------ build

    def build(self, email: OutgoingEmail, tenant: Tenant) -> EmailMessage:
        from_domain = domain_of(email.from_address)
        msg = EmailMessage()
        msg["From"] = formataddr((email.from_name, email.from_address)) if email.from_name else email.from_address
        msg["To"] = email.to
        msg["Subject"] = email.subject
        msg["Date"] = format_datetime(self._now())
        msg["Message-ID"] = make_msgid(domain=from_domain)
        if email.reply_to:
            msg["Reply-To"] = email.reply_to
        url = None
        if email.category is Category.MARKETING:
            url = self.tokens.url(self.cfg.unsubscribe_base_url, email.to, f"{tenant.id}/{email.list_id}")
            msg["List-Unsubscribe"] = f"<{url}>"
            msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
            msg["List-Id"] = f"<{email.list_id}.{from_domain}>"
            # Feedback-ID: Gmail Postmaster Tools 가 고객사·캠페인별로 신고율을 나눠 보여준다.
            msg["Feedback-ID"] = f"{email.list_id}:{tenant.id}:{email.category.value}:strongemail"
        for k, v in email.headers.items():
            msg[k] = v
        text, html = email.text, email.html
        if url:
            # 정보통신망법: 전송자(고객사) 명칭·연락처와 무료 수신거부 방법을 본문에 명시
            ident = tenant.sender_identity
            text += (f"\n\n---\n발신: {ident.name} / 연락처: {ident.contact}\n"
                     f"본 메일은 광고 수신에 동의하신 분께 발송되었습니다. 수신거부: {url}\n")
            if html:
                footer = (f'<hr><p style="font-size:12px;color:#666">발신: {escape(ident.name)} / '
                          f'연락처: {escape(ident.contact)}<br>본 메일은 광고 수신에 동의하신 분께 발송되었습니다. '
                          f'<a href="{escape(url, quote=True)}">수신거부</a></p>')
                html = html.replace("</body>", footer + "</body>") if "</body>" in html else html + footer
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        return msg

    @staticmethod
    def sign(msg: EmailMessage, sd: SenderDomain) -> bytes:
        import dkim

        # max_line_length=998 (RFC 5322 hard limit) keeps long List-Unsubscribe URLs from being
        # RFC 2047-encoded, which would break one-click unsubscribe at Gmail/Yahoo.
        raw = msg.as_bytes(policy=msg.policy.clone(linesep="\r\n", max_line_length=998))
        include = [b"from", b"to", b"subject", b"date", b"message-id", b"reply-to", b"mime-version",
                   b"content-type", b"list-unsubscribe", b"list-unsubscribe-post", b"list-id", b"feedback-id"]
        sig = dkim.sign(raw, sd.dkim_selector.encode(), sd.domain.encode(), sd.dkim_private_key,
                        include_headers=[h for h in include if msg.get(h.decode())])
        return sig + raw

    # ------------------------------------------------------------------- send

    def send(self, email: OutgoingEmail) -> SendResult:
        marketing = email.category is Category.MARKETING
        provider = provider_for(email.to)

        tenant = self.tenants.get(email.tenant_id)
        if tenant is None:
            return SendResult(Status.REJECTED, f"등록되지 않은 고객사: {email.tenant_id}")
        if tenant.suspended:
            return SendResult(Status.REJECTED, f"고객사 발송 정지: {tenant.suspended}")
        sd = tenant.sender_domain_for(email.from_address)
        if sd is None:
            return SendResult(Status.REJECTED, f"{email.from_address} 은 이 고객사가 등록한 발신 주소/도메인이 아닙니다")
        if self.cfg.require_verified_domain:
            ok, why = self.domains.status(sd.domain)
            if not ok:
                return SendResult(Status.REJECTED, why)

        if reason := self.monitor.suppressions.blocked_reason(email.to, marketing, tenant.id):
            return SendResult(Status.REJECTED, f"수신 제외 목록: {reason}")
        if marketing and (problem := self._consent_problem(email)):
            if "야간" in problem:
                return SendResult(Status.DEFERRED, problem, retry_after=self._next_kst_hour(8))
            return SendResult(Status.REJECTED, problem)

        # 고객사 단위 평판: 한 고객의 나쁜 목록이 공유 IP 전체를 망치지 않도록 그 고객만 멈춘다
        for label, report in (("고객사", self.monitor.health(tenant=tenant.id)),
                              ("발신 도메인", self.monitor.health(sd.domain)),
                              (provider.name, self.monitor.health(sd.domain, provider.key))):
            if report.health is Health.PAUSED:
                return SendResult(Status.DEFERRED, f"평판 보호를 위해 발송 중지({label}): " + "; ".join(report.reasons),
                                  retry_after=3600)

        pool_name = tenant.pool_for(email.category.value)
        pool = self.ips.pools.get(pool_name)
        ip, wait, why = None, float("inf"), ""
        for _ in range(len(pool.ips) if pool else 1):
            choice = self.ips.choose(pool_name, provider)
            if choice.ip is None:
                return SendResult(Status.DEFERRED, choice.reason, retry_after=choice.retry_after)
            w = self.throttle.acquire(provider, choice.ip.address)
            if w == 0:
                ip = choice.ip
                break
            wait, why = min(wait, w), f"{provider.name} 발송 속도 제한 (풀 '{pool_name}' 전체)"
        if ip is None:
            return SendResult(Status.DEFERRED, why, retry_after=wait)

        msg = self.build(email, tenant)
        findings = lint_message(msg, marketing=marketing, dkim_domain=sd.domain, return_path=sd.return_path,
                                sender=tenant.sender_identity)
        if has_errors(findings):
            errors = [f for f in findings if f.severity is Severity.ERROR]
            return SendResult(Status.REJECTED, "규정 위반: " + ", ".join(f.code for f in errors), findings=findings)

        code, text = self.transport.send(sd.return_path, email.to, self.sign(msg, sd), ip)
        kind = classify_smtp_response(code, text)
        self.monitor.record(kind, email.to, provider.key, sd.domain, tenant.id, ip.address)
        result = dict(smtp_code=code, bounce=kind, ip=ip.address, findings=findings)
        if kind is BounceKind.DELIVERED:
            return SendResult(Status.SENT, **result)
        if kind is BounceKind.BLOCKED:
            # 이 IP 는 이 포털(공용 차단목록이면 전체)에서 빠지고, 재시도 때 같은 풀의 다른 IP 사용
            inc = self.incidents.open(ip.address, detect_block_source(text, provider.key),
                                      f"{code} {text} (고객사 {tenant.id})")
            return SendResult(Status.DEFERRED, f"IP {ip.address} 차단 (사고 #{inc.id}) — 다른 IP로 재시도",
                              retry_after=60, **result)
        if kind is BounceKind.THROTTLED:
            self.throttle.report_throttled(provider, ip=ip.address)
            return SendResult(Status.DEFERRED, text, retry_after=60, **result)
        if kind is BounceKind.SOFT:
            return SendResult(Status.DEFERRED, text, retry_after=900, **result)
        return SendResult(Status.REJECTED, text, **result)

    # -------------------------------------------------- asynchronous feedback

    def handle_dsn(self, address: str, code: int, text: str, *, tenant_id: str = "", sending_domain: str = "",
                   ip: str = "") -> BounceKind:
        """나중에 반송 메일(DSN)로 들어온 결과. VERP/Return-Path 로 고객사·IP 를 찾아 넘긴다."""
        kind = classify_smtp_response(code, text)
        provider = provider_for(address).key
        self.monitor.record(kind, address, provider, sending_domain, tenant_id, ip)
        if kind is BounceKind.BLOCKED and ip:
            self.incidents.open(ip, detect_block_source(text, provider), f"{code} {text} (DSN, 고객사 {tenant_id})")
        return kind

    def handle_complaint(self, address: str, *, tenant_id: str, sending_domain: str = "", ip: str = "") -> None:
        """Feedback-loop (ARF) report: recipient pressed 'spam'."""
        self.monitor.record("complaint", address, provider_for(address).key, sending_domain, tenant_id, ip)

    def handle_unsubscribe(self, address: str, list_id: str = "default") -> None:
        """원클릭 수신거부 엔드포인트 콜백. list_id 는 '<tenant>/<list>' 형식."""
        tenant_id, _, _ = list_id.partition("/")
        self.monitor.record("unsubscribe", address, provider_for(address).key, "", tenant_id)
