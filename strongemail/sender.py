"""Sending pipeline: every message passes the reputation gates before it touches SMTP.

    suppression -> consent (정보통신망법) -> reputation health -> warm-up cap
    -> provider throttle -> build + DKIM sign -> compliance lint -> SMTP -> record outcome
"""

from __future__ import annotations

import smtplib
import ssl
import time
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime, formataddr, make_msgid
from enum import Enum
from html import escape
from typing import Protocol

from .blocklist import IncidentLog, detect_block_source
from .compliance import SenderIdentity, lint_message
from .domain_setup import SenderDomainRegistry
from .domains import domain_of
from .findings import Finding, Severity, has_errors
from .providers import ProviderProfile, provider_for
from .reputation import BounceKind, Health, ReputationMonitor, WarmupPlan, classify_smtp_response
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
    to: str
    subject: str
    text: str
    html: str | None = None
    category: Category = Category.TRANSACTIONAL
    consent: Consent | None = None
    list_id: str = "default"
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
    findings: list[Finding] = field(default_factory=list)


class Transport(Protocol):
    def send(self, mail_from: str, rcpt: str, data: bytes) -> tuple[int, str]: ...


class SMTPTransport:
    """Direct SMTP to a relay/MTA (Postfix, KumoMTA, ...) with mandatory STARTTLS."""

    def __init__(self, host: str, port: int = 587, username: str | None = None, password: str | None = None,
                 helo: str | None = None, timeout: float = 30.0):
        self.host, self.port, self.username, self.password = host, port, username, password
        self.helo, self.timeout = helo, timeout

    def send(self, mail_from: str, rcpt: str, data: bytes) -> tuple[int, str]:
        try:
            with smtplib.SMTP(self.host, self.port, local_hostname=self.helo, timeout=self.timeout) as s:
                s.starttls(context=ssl.create_default_context())
                if self.username:
                    s.login(self.username, self.password or "")
                s.sendmail(mail_from, [rcpt], data)
            return 250, "OK"
        except smtplib.SMTPRecipientsRefused as e:
            code, msg = next(iter(e.recipients.values()))
            return code, msg.decode(errors="replace")
        except smtplib.SMTPResponseException as e:
            return e.smtp_code, e.smtp_error.decode(errors="replace") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        except (OSError, smtplib.SMTPException) as e:
            return 451, f"4.4.1 connection problem: {e}"


@dataclass
class MailerConfig:
    from_address: str                   # news@example.co.kr
    from_name: str
    return_path: str                    # bounces@bounce.example.co.kr  (SPF-aligned subdomain)
    dkim_selector: str
    dkim_private_key: bytes             # PEM
    sender_identity: SenderIdentity     # 광고 본문 표기용 상호/연락처
    unsubscribe_base_url: str           # https://mail.example.co.kr
    unsubscribe_secret: bytes
    warmup_started: date | None = None  # None = IP already warm
    warmup: WarmupPlan = WarmupPlan()
    dkim_domain: str | None = None      # defaults to From domain
    # 야간(21~08시) 광고 별도 동의는 법 제50조③ 단서·시행령 제61조로 전자우편은 제외된다.
    # SMS/푸시와 같은 정책을 자율적으로 적용하려면 True.
    enforce_night_consent: bool = False
    sending_ip: str | None = None       # 이 Mailer 가 쓰는 발송 IP (차단 사고 추적 단위)
    require_verified_domain: bool = True

    @property
    def sending_domain(self) -> str:
        return domain_of(self.from_address)


class Mailer:
    def __init__(self, config: MailerConfig, monitor: ReputationMonitor, transport: Transport,
                 throttle: ProviderThrottle | None = None, clock=time.time):
        self.cfg = config
        self.monitor = monitor
        self.transport = transport
        self.throttle = throttle or ProviderThrottle()
        self.tokens = UnsubscribeTokens(config.unsubscribe_secret)
        self._clock = clock
        self.incidents = IncidentLog(monitor.store, clock=clock)
        self.domains = SenderDomainRegistry(monitor.store, clock=clock)

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

    def _warmup_start(self, provider: ProviderProfile) -> date | None:
        """웜업 시작일. 차단이 해제된 포털은 해제일부터 다시 웜업한다."""
        start = self.cfg.warmup_started
        if self.cfg.sending_ip:
            resolved = self.incidents.last_resolved(self.cfg.sending_ip, provider.key)
            if resolved is not None:
                rewarm = datetime.fromtimestamp(resolved, KST).date()
                start = rewarm if start is None else max(start, rewarm)
        return start

    def _warmup_cap(self, provider: ProviderProfile) -> int | None:
        start = self._warmup_start(provider)
        if start is None:
            return None
        today = self._now().date()
        cap = self.cfg.warmup.cap(today.toordinal() - start.toordinal())
        if cap >= self.cfg.warmup.max_daily:
            return None
        midnight = datetime.combine(today, datetime.min.time(), KST).timestamp()
        sent = self.monitor.sent_since(midnight, provider.key, self.cfg.sending_domain)
        return cap - sent

    def _next_kst_hour(self, hour: int) -> float:
        now = self._now()
        target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
        if target <= now:
            target += timedelta(days=1)
        return (target - now).total_seconds()

    # ------------------------------------------------------------------ build

    def build(self, email: OutgoingEmail) -> EmailMessage:
        cfg = self.cfg
        msg = EmailMessage()
        msg["From"] = formataddr((cfg.from_name, cfg.from_address))
        msg["To"] = email.to
        msg["Subject"] = email.subject
        msg["Date"] = format_datetime(self._now())
        msg["Message-ID"] = make_msgid(domain=cfg.sending_domain)
        if email.category is Category.MARKETING:
            url = self.tokens.url(cfg.unsubscribe_base_url, email.to, email.list_id)
            msg["List-Unsubscribe"] = f"<{url}>"
            msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
            msg["List-Id"] = f"<{email.list_id}.{cfg.sending_domain}>"
            # Feedback-ID lets Gmail Postmaster Tools break complaint rates down per campaign.
            msg["Feedback-ID"] = f"{email.list_id}:{email.category.value}:{cfg.sending_domain}"
        for k, v in email.headers.items():
            msg[k] = v
        text, html = email.text, email.html
        if email.category is Category.MARKETING:
            # 정보통신망법: 전송자 명칭·연락처와 무료 수신거부 방법을 본문에 명시
            ident = cfg.sender_identity
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

    def sign(self, msg: EmailMessage) -> bytes:
        import dkim

        # max_line_length=998 (RFC 5322 hard limit) keeps long List-Unsubscribe URLs from being
        # RFC 2047-encoded, which would break one-click unsubscribe at Gmail/Yahoo.
        raw = msg.as_bytes(policy=msg.policy.clone(linesep="\r\n", max_line_length=998))
        domain = (self.cfg.dkim_domain or self.cfg.sending_domain).encode()
        include = [b"from", b"to", b"subject", b"date", b"message-id", b"mime-version", b"content-type",
                   b"list-unsubscribe", b"list-unsubscribe-post", b"list-id", b"feedback-id"]
        sig = dkim.sign(raw, self.cfg.dkim_selector.encode(), domain, self.cfg.dkim_private_key,
                        include_headers=[h for h in include if msg.get(h.decode())])
        return sig + raw

    # ------------------------------------------------------------------- send

    def send(self, email: OutgoingEmail) -> SendResult:
        marketing = email.category is Category.MARKETING
        provider = provider_for(email.to)
        domain = self.cfg.sending_domain

        if self.cfg.require_verified_domain:
            ok, why = self.domains.status(domain)
            if not ok:
                return SendResult(Status.REJECTED, why)
        if self.cfg.sending_ip and (inc := self.incidents.blocking(self.cfg.sending_ip, provider.key)):
            return SendResult(Status.DEFERRED, f"발송 IP {inc.ip} 가 {inc.target} 에서 차단됨 (사고 #{inc.id}, "
                                               f"{inc.state.value}) — 해제 전까지 발송 중지", retry_after=3600)
        if reason := self.monitor.suppressions.blocked_reason(email.to, marketing):
            return SendResult(Status.REJECTED, f"수신 제외 목록: {reason}")
        if marketing and (problem := self._consent_problem(email)):
            if "야간" in problem:
                return SendResult(Status.DEFERRED, problem, retry_after=self._next_kst_hour(8))
            return SendResult(Status.REJECTED, problem)

        for report in (self.monitor.health(domain), self.monitor.health(domain, provider.key)):
            if report.health is Health.PAUSED:
                return SendResult(Status.DEFERRED, "평판 보호를 위해 발송 중지: " + "; ".join(report.reasons),
                                  retry_after=3600)

        remaining = self._warmup_cap(provider)
        if remaining is not None and remaining <= 0:
            return SendResult(Status.DEFERRED, f"{provider.name} 웜업 일일 한도 도달", retry_after=self._next_kst_hour(0))
        if wait := self.throttle.acquire(provider):
            return SendResult(Status.DEFERRED, f"{provider.name} 발송 속도 제한", retry_after=wait)

        msg = self.build(email)
        findings = lint_message(msg, marketing=marketing, dkim_domain=self.cfg.dkim_domain or domain,
                                return_path=self.cfg.return_path, sender=self.cfg.sender_identity)
        if has_errors(findings):
            errors = [f for f in findings if f.severity is Severity.ERROR]
            return SendResult(Status.REJECTED, "규정 위반: " + ", ".join(f.code for f in errors), findings=findings)

        code, text = self.transport.send(self.cfg.return_path, email.to, self.sign(msg))
        kind = classify_smtp_response(code, text)
        self.monitor.record(kind, email.to, provider.key, domain)
        if kind is BounceKind.DELIVERED:
            return SendResult(Status.SENT, smtp_code=code, bounce=kind, findings=findings)
        if kind is BounceKind.BLOCKED and self.cfg.sending_ip:
            self.incidents.open(self.cfg.sending_ip, detect_block_source(text, provider.key), f"{code} {text}")
        if kind is BounceKind.THROTTLED:
            self.throttle.report_throttled(provider)
            return SendResult(Status.DEFERRED, text, retry_after=60, smtp_code=code, bounce=kind, findings=findings)
        if kind is BounceKind.SOFT:
            return SendResult(Status.DEFERRED, text, retry_after=900, smtp_code=code, bounce=kind, findings=findings)
        return SendResult(Status.REJECTED, text, smtp_code=code, bounce=kind, findings=findings)

    # -------------------------------------------------- asynchronous feedback

    def handle_dsn(self, address: str, code: int, text: str) -> BounceKind:
        """Bounce that arrived later as a DSN to the Return-Path mailbox."""
        kind = classify_smtp_response(code, text)
        self.monitor.record(kind, address, provider_for(address).key, self.cfg.sending_domain)
        return kind

    def handle_complaint(self, address: str) -> None:
        """Feedback-loop (ARF) report: recipient pressed 'spam'."""
        self.monitor.record("complaint", address, provider_for(address).key, self.cfg.sending_domain)

    def handle_unsubscribe(self, address: str, list_id: str = "default") -> None:
        self.monitor.record("unsubscribe", address, provider_for(address).key, self.cfg.sending_domain)
