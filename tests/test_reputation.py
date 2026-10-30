from strongemail.reputation import (BounceKind, Health, ReputationMonitor, Store, SuppressionScope, Thresholds,
                                    WarmupPlan, classify_smtp_response)


def test_classify():
    assert classify_smtp_response(250) is BounceKind.DELIVERED
    assert classify_smtp_response(550, "5.1.1 The email account that you tried to reach does not exist") is BounceKind.HARD
    assert classify_smtp_response(552, "5.2.2 mailbox full") is BounceKind.SOFT
    assert classify_smtp_response(550, "5.7.1 Message rejected as spam") is BounceKind.BLOCKED
    assert classify_smtp_response(550, "5.7.26 Unauthenticated email from a.com is not accepted") is BounceKind.AUTH_FAILED
    assert classify_smtp_response(421, "4.7.28 rate limited") is BounceKind.THROTTLED
    assert classify_smtp_response(450, "4.2.0 mailbox busy") is BounceKind.SOFT


def make_monitor(**kw):
    clock = [1_000_000.0]
    m = ReputationMonitor(Store(), Thresholds(min_volume=100, **kw), clock=lambda: clock[0])
    return m, clock


def test_hard_bounce_and_complaint_suppress():
    m, _ = make_monitor()
    m.record(BounceKind.HARD, "Dead@naver.com", "naver", "a.com")
    assert m.suppressions.blocked_reason("dead@naver.com", marketing=False) == "hard_bounce"
    m.record("unsubscribe", "u@naver.com", "naver", "a.com")
    assert m.suppressions.blocked_reason("u@naver.com", marketing=False) is None
    assert m.suppressions.blocked_reason("u@naver.com", marketing=True) == "unsubscribe"
    m.suppressions.remove("u@naver.com", SuppressionScope.MARKETING)
    assert m.suppressions.blocked_reason("u@naver.com", marketing=True) is None


def test_repeated_soft_bounces_suppress():
    m, clock = make_monitor()
    for _ in range(3):
        clock[0] += 1
        m.record(BounceKind.SOFT, "full@daum.net", "kakao", "a.com")
    assert m.suppressions.blocked_reason("full@daum.net", marketing=False) == "repeated_soft_bounce"


def test_complaint_rate_pauses():
    m, clock = make_monitor()
    for i in range(1000):
        m.record(BounceKind.DELIVERED, f"u{i}@gmail.com", "gmail", "a.com")
    assert m.health("a.com").health is Health.OK
    for i in range(2):
        m.record("complaint", f"u{i}@gmail.com", "gmail", "a.com")
    assert m.health("a.com").health is Health.WARN
    for i in range(2, 4):
        m.record("complaint", f"u{i}@gmail.com", "gmail", "a.com")
    report = m.health("a.com", "gmail")
    assert report.health is Health.PAUSED and "스팸 신고율" in report.reasons[0]
    assert m.health("a.com", "naver").health is Health.OK
    clock[0] += 2 * 24 * 3600  # window passes
    assert m.health("a.com").health is Health.OK


def test_auth_failure_pauses_immediately():
    m, _ = make_monitor()
    m.record(BounceKind.AUTH_FAILED, "x@gmail.com", "gmail", "a.com")
    assert m.health("a.com").health is Health.PAUSED


def test_warmup_plan():
    w = WarmupPlan(start_daily=50, growth=2, max_daily=1000)
    assert [w.cap(d) for d in range(6)] == [50, 100, 200, 400, 800, 1000]
