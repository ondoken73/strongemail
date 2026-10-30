from strongemail.blocklist import (AppealContext, IncidentLog, IncidentState, build_appeal, check_dnsbls,
                                   detect_block_source)
from strongemail.findings import Finding, Severity
from strongemail.reputation import Health, HealthReport, Store
from test_dns_audit import FakeResolver

OK_HEALTH = HealthReport(Health.OK, 5000, 0.004, 0.0004, 0.0, ())


def ctx(**kw):
    base = dict(company="(주)예시상점", contact_name="홍길동", contact_email="postmaster@shop.co.kr",
                contact_phone="02-123-4567", sending_domain="shop.co.kr", mail_type="주문 알림 및 뉴스레터",
                consent_method="가입 시 별도 체크박스로 광고 수신동의", daily_volume=20000,
                dns_findings=[], health=OK_HEALTH)
    base.update(kw)
    return AppealContext(**base)


def test_dnsbl_check():
    r = FakeResolver(addresses={"10.113.0.203.zen.spamhaus.org": ["127.0.0.2"],
                                "10.113.0.203.bl.spamcop.net": []})
    res = {x.list_key: x.listed for x in check_dnsbls("203.0.113.10", r)}
    assert res == {"spamhaus": True, "barracuda": False, "spamcop": False}
    refused = FakeResolver(addresses={"10.113.0.203.zen.spamhaus.org": ["127.255.255.254"]})
    assert check_dnsbls("203.0.113.10", refused)[0].listed is None


def test_detect_source():
    assert detect_block_source("554 5.7.1 blocked using zen.spamhaus.org", "naver") == "spamhaus"
    assert detect_block_source("550 5.7.1 S3150 banned sending IP", "other") == "microsoft"
    assert detect_block_source("554 5.7.1 rejected", "kakao") == "kakao"


def test_incident_lifecycle():
    now = [1_000_000.0]
    log = IncidentLog(Store(), clock=lambda: now[0])
    inc = log.open("203.0.113.10", "naver", "554 blocked")
    assert log.open("203.0.113.10", "naver", "again").id == inc.id  # 중복 생성 안 함
    assert log.blocking("203.0.113.10", "naver") and not log.blocking("203.0.113.10", "gmail")
    log.add_action(inc.id, "6개월 무반응 수신자 12,000명 제외")
    log.mark_appealed(inc.id)
    assert log.get(inc.id).state is IncidentState.APPEALED and log.blocking("203.0.113.10", "naver")
    now[0] += 3600
    log.resolve(inc.id)
    assert log.blocking("203.0.113.10", "naver") is None
    assert log.last_resolved("203.0.113.10", "naver") == now[0]
    again = log.open("203.0.113.10", "naver", "554 blocked again")
    assert again.id != inc.id and again.appeal_count == 1


def test_appeal_blocked_until_ready():
    log = IncidentLog(Store(), clock=lambda: 0.0)
    inc = log.open("203.0.113.10", "naver", "554 5.7.1 blocked")
    bad_dns = [Finding("SPF_MISSING", Severity.ERROR, "x")]
    paused = HealthReport(Health.PAUSED, 1000, 0.08, 0.0, 0.0, ("하드바운스율 8.00%",))
    packet = build_appeal(inc, ctx(dns_findings=bad_dns, health=paused), now=100)
    assert not packet.ready and len(packet.blockers) == 3

    log.add_action(inc.id, "구매 DB 발송 중단 및 6개월 무반응 수신자 제외")
    packet = build_appeal(log.get(inc.id), ctx(), now=100)
    assert packet.ready, packet.blockers
    assert "203.0.113.10" in packet.letter and "구매 DB" in packet.letter and "차단 해제" in packet.letter
    assert packet.channel.key == "naver"


def test_appeal_english_for_gmail_and_waits():
    log = IncidentLog(Store(), clock=lambda: 0.0)
    inc = log.open("203.0.113.10", "gmail", "550 5.7.1 unsolicited mail")
    log.add_action(inc.id, "Removed purchased list")
    early = build_appeal(log.get(inc.id), ctx(), now=3600)
    assert not early.ready and "12시간" in early.blockers[0]
    later = build_appeal(log.get(inc.id), ctx(), now=13 * 3600)
    assert later.ready and later.letter.startswith("Subject: Delisting request")
