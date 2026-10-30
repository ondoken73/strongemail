import base64
from datetime import date, datetime, timedelta

import dkim
import pytest

from strongemail.compliance import SenderIdentity, lint_message
from strongemail.ip_pool import IPPool, SendingIP
from strongemail.reputation import BounceKind, ReputationMonitor, Store
from strongemail.sender import KST, Category, Consent, Mailer, MailerConfig, OutgoingEmail, Status
from strongemail.tenants import SenderDomain, Tenant, TenantRegistry


class FakeTransport:
    """수신 포털·IP 별로 응답을 바꿀 수 있는 가짜 SMTP."""

    def __init__(self, reply=(250, "OK")):
        self.reply, self.sent, self.rules = reply, [], {}

    def send(self, mail_from, rcpt, data, ip):
        self.sent.append((mail_from, rcpt, data, ip.address))
        return self.rules.get((ip.address, rcpt.split("@")[1]), self.reply)


NOON = datetime(2026, 10, 30, 12, 0, tzinfo=KST).timestamp()
NIGHT = datetime(2026, 10, 30, 22, 0, tzinfo=KST).timestamp()
TX_IP = "203.0.113.1"
MK_IPS = ["203.0.113.11", "203.0.113.12", "203.0.113.13"]


@pytest.fixture
def setup(dkim_key):
    pem, pub = dkim_key

    def make(reply=(250, "OK"), at=NOON, warmup_started=None, night_rule=False, marketing_ips=MK_IPS):
        tenants = TenantRegistry()
        for tid, dom, name in (("shop", "example.co.kr", "(주)예시상점"), ("cafe", "cafe.kr", "예시카페")):
            t = Tenant(tid, name, SenderIdentity(name, "02-123-4567"))
            t.add_domain(SenderDomain(dom, "s1", pem))
            tenants.add(t)
        pools = [
            IPPool("shared-transactional", [SendingIP(TX_IP, "mail1.svc.kr")]),
            IPPool("shared-marketing", [SendingIP(a, f"mk{i}.svc.kr", warmup_started) for i, a in enumerate(marketing_ips)]),
        ]
        transport = FakeTransport(reply)
        monitor = ReputationMonitor(Store(), clock=lambda: at)
        cfg = MailerConfig("https://mail.svc.kr", b"s" * 32, enforce_night_consent=night_rule)
        mailer = Mailer(cfg, tenants, pools, monitor, transport, clock=lambda: at)
        mailer.domains.mark_verified("example.co.kr")
        mailer.domains.mark_verified("cafe.kr")
        mailer.throttle.acquire = lambda p, ip=None: 0.0
        return mailer, transport, pub
    return make


def consent(days_ago=10, night=False):
    return Consent(marketing_opt_in_at=datetime.fromtimestamp(NOON, KST) - timedelta(days=days_ago), night_opt_in=night)


def tx(to="user@gmail.com", tenant="shop", frm="noreply@example.co.kr", **kw):
    return OutgoingEmail(tenant, frm, to, kw.pop("subject", "인증번호 안내"), kw.pop("text", "인증번호: 123456"), **kw)


def ad(to="user@naver.com", tenant="shop", frm="news@example.co.kr", **kw):
    base = dict(subject="(광고) 가을 세일", text="가을 세일을 시작합니다.",
                html="<html><body><p>가을 세일을 시작합니다.</p></body></html>",
                category=Category.MARKETING, consent=consent())
    base.update(kw)
    subject, text = base.pop("subject"), base.pop("text")
    return OutgoingEmail(tenant, frm, to, subject, text, **base)


# --------------------------------------------------------------- 기본 발송

def test_transactional_signed_with_customer_domain(setup):
    mailer, transport, pub = setup()
    r = mailer.send(tx(from_name="예시상점"))
    assert r.status is Status.SENT and r.ip == TX_IP, r
    mail_from, _, data, _ = transport.sent[0]
    assert mail_from == "bounces@bounce.example.co.kr"
    assert b"d=example.co.kr" in data and b"List-Unsubscribe" not in data
    dns_txt = b"v=DKIM1; k=rsa; p=" + base64.b64encode(pub)
    assert dkim.verify(data, dnsfunc=lambda name, timeout=5: dns_txt)


def test_subdomain_from_uses_parent_key(setup):
    mailer, transport, _ = setup()
    assert mailer.send(tx(frm="alert@news.example.co.kr")).status is Status.SENT


def test_marketing_headers_footer_and_pool(setup):
    mailer, transport, _ = setup()
    r = mailer.send(ad())
    assert r.status is Status.SENT and r.ip in MK_IPS, r
    data = transport.sent[0][2].decode()
    assert "List-Unsubscribe-Post: List-Unsubscribe=One-Click" in data
    assert "List-Unsubscribe: <https://mail.svc.kr/unsubscribe?t=" in data


def test_marketing_requires_ad_prefix(setup):
    mailer, transport, _ = setup()
    r = mailer.send(ad(subject="가을 세일"))
    assert r.status is Status.REJECTED and "KR_AD_PREFIX" in r.reason and transport.sent == []


def test_marketing_requires_consent(setup):
    mailer, _, _ = setup()
    assert mailer.send(ad(consent=None)).status is Status.REJECTED
    assert "2년" in mailer.send(ad(consent=consent(days_ago=800))).reason


def test_night_marketing(setup):
    mailer, _, _ = setup(at=NIGHT)
    assert mailer.send(ad()).status is Status.SENT  # 전자우편은 야간 동의 예외
    mailer, _, _ = setup(at=NIGHT, night_rule=True)
    r = mailer.send(ad())
    assert r.status is Status.DEFERRED and r.retry_after == 10 * 3600
    assert mailer.send(ad(consent=consent(night=True))).status is Status.SENT


# ---------------------------------------------------- 고객사 발신 주소

def test_customer_cannot_send_from_other_domains(setup):
    mailer, transport, _ = setup()
    assert "등록한 발신" in mailer.send(tx(frm="noreply@cafe.kr")).reason       # 다른 고객 도메인
    assert "등록한 발신" in mailer.send(tx(frm="ceo@bank.com")).reason          # 남의 도메인
    assert mailer.send(tx(tenant="cafe", frm="hello@cafe.kr")).status is Status.SENT
    assert "등록되지 않은" in mailer.send(tx(tenant="nobody")).reason


def test_domain_cannot_be_claimed_twice(setup, dkim_key):
    mailer, _, _ = setup()
    with pytest.raises(ValueError):
        mailer.tenants.add_domain("cafe", SenderDomain("example.co.kr", "s1", dkim_key[0]))


def test_unverified_domain_cannot_send(setup):
    mailer, transport, _ = setup()
    mailer.monitor.store.execute("DELETE FROM sender_domains WHERE domain = 'cafe.kr'")
    r = mailer.send(tx(tenant="cafe", frm="hello@cafe.kr"))
    assert r.status is Status.REJECTED and "검증" in r.reason and transport.sent == []
    assert mailer.send(tx()).status is Status.SENT


def test_suspended_tenant(setup):
    mailer, _, _ = setup()
    mailer.tenants.get("shop").suspended = "약관 위반(구매 DB 발송)"
    assert "정지" in mailer.send(tx()).reason


# ------------------------------------------------- 수신 제외 / 고객 평판

def test_hard_bounce_is_global(setup):
    mailer, transport, _ = setup(reply=(550, "5.1.1 user unknown"))
    r = mailer.send(tx(to="gone@daum.net"))
    assert r.status is Status.REJECTED and r.bounce is BounceKind.HARD
    r = mailer.send(tx(to="gone@daum.net", tenant="cafe", frm="hello@cafe.kr"))
    assert "hard_bounce" in r.reason and len(transport.sent) == 1


def test_unsubscribe_is_per_tenant_and_marketing_only(setup):
    mailer, _, _ = setup()
    mailer.handle_unsubscribe("user@naver.com", "shop/default")
    assert mailer.send(ad()).status is Status.REJECTED
    assert mailer.send(tx(to="user@naver.com")).status is Status.SENT
    assert mailer.send(ad(tenant="cafe", frm="news@cafe.kr")).status is Status.SENT


def test_bad_tenant_paused_without_hurting_others(setup):
    mailer, _, _ = setup()
    for i in range(300):
        mailer.monitor.record(BounceKind.DELIVERED, f"u{i}@gmail.com", "gmail", "example.co.kr", "shop", MK_IPS[0])
    for i in range(3):
        mailer.handle_complaint(f"u{i}@gmail.com", tenant_id="shop", sending_domain="example.co.kr")
    r = mailer.send(ad(to="x@gmail.com"))
    assert r.status is Status.DEFERRED and "고객사" in r.reason
    assert mailer.send(ad(to="x@gmail.com", tenant="cafe", frm="news@cafe.kr")).status is Status.SENT


# --------------------------------------------------------- 멀티 IP

def test_round_robin_across_pool(setup):
    mailer, _, _ = setup()
    used = {mailer.send(ad(to=f"u{i}@naver.com")).ip for i in range(6)}
    assert used == set(MK_IPS)


def test_blocked_ip_fails_over_to_other_ips_for_that_portal_only(setup):
    mailer, transport, _ = setup()
    bad = MK_IPS[0]
    transport.rules[(bad, "naver.com")] = (554, "5.7.1 blocked due to poor reputation")
    results = [mailer.send(ad(to=f"u{i}@naver.com")) for i in range(6)]
    blocked = [r for r in results if r.bounce is BounceKind.BLOCKED]
    assert len(blocked) == 1 and blocked[0].ip == bad and blocked[0].status is Status.DEFERRED
    [inc] = mailer.incidents.active()
    assert (inc.ip, inc.target) == (bad, "naver") and "shop" in inc.evidence
    later = [mailer.send(ad(to=f"v{i}@naver.com")) for i in range(6)]
    assert all(r.status is Status.SENT and r.ip != bad for r in later)
    # 같은 IP 라도 다른 포털로는 계속 사용
    assert bad in {mailer.send(ad(to=f"w{i}@gmail.com")).ip for i in range(6)}


def test_snowshoe_guard_pauses_pool_when_many_ips_blocked(setup):
    mailer, _, _ = setup()
    for ip in MK_IPS[:2]:
        mailer.incidents.open(ip, "kakao", "554 5.7.1 spam")
    r = mailer.send(ad(to="a@daum.net"))
    assert r.status is Status.DEFERRED and "돌려막기" in r.reason
    assert mailer.send(ad(to="a@naver.com")).status is Status.SENT
    assert mailer.send(tx(to="a@daum.net")).status is Status.SENT  # 거래성 풀은 영향 없음


def test_public_blocklist_removes_ip_for_all_portals(setup):
    mailer, transport, _ = setup()
    transport.rules[(MK_IPS[1], "naver.com")] = (554, "5.7.1 client host blocked using zen.spamhaus.org")
    for i in range(3):
        mailer.send(ad(to=f"u{i}@naver.com"))
    assert mailer.incidents.active()[0].target == "spamhaus"
    used = {mailer.send(ad(to=f"g{i}@gmail.com")).ip for i in range(6)}
    assert MK_IPS[1] not in used and used


def test_marketing_block_does_not_touch_transactional(setup):
    mailer, _, _ = setup(marketing_ips=MK_IPS[:1])
    mailer.incidents.open(MK_IPS[0], "naver", "554 blocked")
    r = mailer.send(ad())
    assert r.status is Status.DEFERRED and "차단" in r.reason
    assert mailer.send(tx(to="user@naver.com")).status is Status.SENT


def test_per_ip_warmup_cap(setup):
    mailer, _, _ = setup(warmup_started=date(2026, 10, 30), marketing_ips=MK_IPS[:2])  # IP당 50통/일
    results = [mailer.send(ad(to=f"u{i}@naver.com")) for i in range(101)]
    assert all(r.status is Status.SENT for r in results[:100])
    assert results[100].status is Status.DEFERRED and "한도" in results[100].reason
    assert mailer.send(ad(to="x@gmail.com")).status is Status.SENT  # 포털별 한도


def test_resolved_incident_rewarms_only_that_ip_and_portal(setup):
    mailer, _, _ = setup(marketing_ips=MK_IPS[:1])
    inc = mailer.incidents.open(MK_IPS[0], "naver", "554 blocked")
    mailer.incidents.resolve(inc.id)
    results = [mailer.send(ad(to=f"u{i}@naver.com")) for i in range(51)]
    assert results[49].status is Status.SENT and "한도" in results[50].reason
    assert mailer.send(ad(to="x@gmail.com")).status is Status.SENT


def test_lint_flags_freemail_from_and_misalignment():
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["From"] = "me@naver.com"
    msg["To"] = "a@b.com"
    msg["Subject"] = "hi"
    msg.set_content("x")
    codes = {f.code for f in lint_message(msg, marketing=False, dkim_domain="esp.com")}
    assert {"FROM_FREEMAIL", "DKIM_NOT_ALIGNED", "HEADER_MISSING"} <= codes


def test_customer_domain_verified_via_service_spf_include(setup):
    from strongemail.domain_setup import dkim_txt_from_private_key
    from test_dns_audit import FakeResolver

    mailer, _, _ = setup()
    sd = mailer.tenants.get("cafe").domains["cafe.kr"]
    good = FakeResolver(txt={
        "cafe.kr": ["v=spf1 include:_spf.svc.kr ~all"],              # 고객은 include 한 줄만 추가
        "_spf.svc.kr": ["v=spf1 ip4:203.0.113.0/24 -all"],            # 서비스가 모든 발송 IP 관리
        "s1._domainkey.cafe.kr": [dkim_txt_from_private_key(sd.dkim_private_key)],
        "_dmarc.cafe.kr": ["v=DMARC1; p=none; rua=mailto:d@cafe.kr"],
    })
    mailer.domains._resolver = good
    assert mailer.verify_tenant_domain("cafe", "cafe.kr").verified

    partial = FakeResolver(txt={**good._txt, "_spf.svc.kr": ["v=spf1 ip4:203.0.113.11 -all"]})
    mailer.domains._resolver = partial
    res = mailer.verify_tenant_domain("cafe", "cafe.kr")
    assert not res.verified
    assert sum(f.code == "SPF_NOT_AUTHORIZED" for f in res.findings) == 3  # 나머지 IP 3개 누락
    assert "검증 실패" in mailer.send(tx(tenant="cafe", frm="hello@cafe.kr")).reason
