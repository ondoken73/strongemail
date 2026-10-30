from datetime import date, datetime, timedelta

import dkim
import pytest

from strongemail.compliance import SenderIdentity, lint_message
from strongemail.reputation import BounceKind, ReputationMonitor, Store
from strongemail.sender import KST, Category, Consent, Mailer, MailerConfig, OutgoingEmail, Status


class FakeTransport:
    def __init__(self, reply=(250, "OK")):
        self.reply, self.sent = reply, []

    def send(self, mail_from, rcpt, data):
        self.sent.append((mail_from, rcpt, data))
        return self.reply


NOON = datetime(2026, 10, 30, 12, 0, tzinfo=KST).timestamp()
NIGHT = datetime(2026, 10, 30, 22, 0, tzinfo=KST).timestamp()


@pytest.fixture
def setup(dkim_key):
    pem, pub = dkim_key

    def make(reply=(250, "OK"), at=NOON, warmup_started=None, night_rule=False):
        cfg = MailerConfig(
            from_address="news@example.co.kr", from_name="예시상점", return_path="b@bounce.example.co.kr",
            dkim_selector="s1", dkim_private_key=pem,
            sender_identity=SenderIdentity("(주)예시상점", "02-123-4567"),
            unsubscribe_base_url="https://mail.example.co.kr", unsubscribe_secret=b"s" * 32,
            warmup_started=warmup_started, enforce_night_consent=night_rule,
        )
        transport = FakeTransport(reply)
        monitor = ReputationMonitor(Store(), clock=lambda: at)
        return Mailer(cfg, monitor, transport, clock=lambda: at), transport, pub
    return make


def consent(days_ago=10, night=False):
    return Consent(marketing_opt_in_at=datetime.fromtimestamp(NOON, KST) - timedelta(days=days_ago), night_opt_in=night)


def ad(**kw):
    base = dict(to="user@naver.com", subject="(광고) 가을 세일", text="가을 세일을 시작합니다.",
                html="<html><body><p>가을 세일을 시작합니다.</p></body></html>",
                category=Category.MARKETING, consent=consent())
    base.update(kw)
    return OutgoingEmail(**base)


def test_transactional_is_signed_and_sent(setup):
    mailer, transport, pub = setup()
    r = mailer.send(OutgoingEmail(to="user@gmail.com", subject="인증번호 안내", text="인증번호: 123456"))
    assert r.status is Status.SENT, r
    mail_from, rcpt, data = transport.sent[0]
    assert mail_from == "b@bounce.example.co.kr"
    assert b"List-Unsubscribe" not in data
    dns_txt = b"v=DKIM1; k=rsa; p=" + __import__("base64").b64encode(pub)
    assert dkim.verify(data, dnsfunc=lambda name, timeout=5: dns_txt)


def test_marketing_gets_compliant_headers_and_footer(setup):
    mailer, transport, _ = setup()
    r = mailer.send(ad())
    assert r.status is Status.SENT, r
    data = transport.sent[0][2].decode()
    assert "List-Unsubscribe-Post: List-Unsubscribe=One-Click" in data
    assert "List-Unsubscribe: <https://mail.example.co.kr/unsubscribe?t=" in data


def test_marketing_requires_ad_prefix(setup):
    mailer, transport, _ = setup()
    r = mailer.send(ad(subject="가을 세일"))
    assert r.status is Status.REJECTED and "KR_AD_PREFIX" in r.reason
    assert transport.sent == []


def test_marketing_requires_consent(setup):
    mailer, _, _ = setup()
    assert mailer.send(ad(consent=None)).status is Status.REJECTED
    assert "2년" in mailer.send(ad(consent=consent(days_ago=800))).reason


def test_night_marketing_allowed_for_email_by_default(setup):
    mailer, _, _ = setup(at=NIGHT)
    assert mailer.send(ad()).status is Status.SENT


def test_night_marketing_deferred_when_policy_enabled(setup):
    mailer, _, _ = setup(at=NIGHT, night_rule=True)
    r = mailer.send(ad())
    assert r.status is Status.DEFERRED and r.retry_after == 10 * 3600
    assert mailer.send(ad(consent=consent(night=True))).status is Status.SENT


def test_hard_bounce_then_suppressed(setup):
    mailer, transport, _ = setup(reply=(550, "5.1.1 user unknown"))
    r = mailer.send(OutgoingEmail(to="gone@daum.net", subject="안내", text="안내"))
    assert r.status is Status.REJECTED and r.bounce is BounceKind.HARD
    r = mailer.send(OutgoingEmail(to="gone@daum.net", subject="안내", text="안내"))
    assert r.status is Status.REJECTED and "hard_bounce" in r.reason
    assert len(transport.sent) == 1


def test_unsubscribe_blocks_marketing_only(setup):
    mailer, _, _ = setup()
    mailer.handle_unsubscribe("user@naver.com")
    assert mailer.send(ad()).status is Status.REJECTED
    assert mailer.send(OutgoingEmail(to="user@naver.com", subject="영수증", text="결제 완료")).status is Status.SENT


def test_warmup_cap(setup):
    mailer, _, _ = setup(warmup_started=date(2026, 10, 30))  # day 0 -> 50/day
    mailer.throttle.acquire = lambda p: 0.0
    results = [mailer.send(OutgoingEmail(to=f"u{i}@naver.com", subject="안내", text="안내")) for i in range(51)]
    assert all(r.status is Status.SENT for r in results[:50])
    assert results[50].status is Status.DEFERRED and "웜업" in results[50].reason


def test_lint_flags_freemail_from_and_misalignment():
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = "me@naver.com"
    msg["To"] = "a@b.com"
    msg["Subject"] = "hi"
    msg.set_content("x")
    codes = {f.code for f in lint_message(msg, marketing=False, dkim_domain="esp.com")}
    assert {"FROM_FREEMAIL", "DKIM_NOT_ALIGNED", "HEADER_MISSING"} <= codes
