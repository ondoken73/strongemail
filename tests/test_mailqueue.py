from datetime import date

import pytest

from strongemail.mailqueue import JobStatus, MailQueue, RetryPolicy, Worker, _decode, _encode
from strongemail.sender import Category, Status
from test_sender import MK_IPS, NOON, ad, setup, tx  # noqa: F401  (fixture 재사용)


@pytest.fixture
def env(setup):
    def make(**kw):
        mailer, transport, _ = setup(**kw)
        now = [NOON]
        mailer._clock = mailer.ips._clock = lambda: now[0]
        mailer.monitor._clock = mailer.incidents._clock = mailer.domains._clock = lambda: now[0]
        q = MailQueue(mailer.monitor.store, clock=lambda: now[0])
        w = Worker(q, mailer, RetryPolicy(base=60, max_attempts=3), clock=lambda: now[0])
        return q, w, mailer, transport, now
    return make


def test_payload_roundtrip():
    e = ad()
    assert _decode(_encode(e)) == e


def test_transactional_first_and_sent(env):
    q, w, _, transport, _ = env()
    a = q.enqueue(ad(to="a@naver.com"))
    t = q.enqueue(tx(to="t@naver.com"))
    assert w.run_once() == {"sent": 2, "deferred": 0, "failed": 0, "expired": 0}
    assert [s[1] for s in transport.sent] == ["t@naver.com", "a@naver.com"]
    assert q.get(a).status is JobStatus.SENT and q.get(t).last_ip


def test_rejected_is_final(env):
    q, w, *_ = env()
    j = q.enqueue(ad(consent=None))
    w.run_once()
    assert q.get(j).status is JobStatus.FAILED and "수신동의" in q.get(j).last_reason


def test_soft_bounce_retries_with_backoff_then_fails(env):
    q, w, _, transport, now = env(reply=(451, "4.3.0 temporary failure"))
    j = q.enqueue(tx(to="a@corp.co.kr"))
    w.run_once()
    job = q.get(j)
    assert job.status is JobStatus.QUEUED and job.attempts == 1 and job.next_attempt_at == now[0] + 900
    assert w.run_once()["sent"] == 0 and len(transport.sent) == 1  # 아직 시간이 안 됨
    for _ in range(2):
        now[0] = q.get(j).next_attempt_at
        w.run_once()
    assert q.get(j).status is JobStatus.FAILED and q.get(j).attempts == 3


def test_blocked_ip_retry_goes_out_on_another_ip(env):
    q, w, _, transport, now = env(marketing_ips=MK_IPS[:2])
    transport.rules[(MK_IPS[0], "naver.com")] = (554, "5.7.1 blocked due to poor reputation")
    ids = [q.enqueue(ad(to=f"u{i}@naver.com")) for i in range(2)]
    w.run_once()
    now[0] += 120
    w.run_once()
    jobs = [q.get(i) for i in ids]
    assert all(j.status is JobStatus.SENT for j in jobs)
    assert {j.last_ip for j in jobs} == {MK_IPS[1]}


def test_warmup_cap_defers_group_without_burning_attempts(env):
    q, w, mailer, transport, now = env(warmup_started=date(2026, 10, 30), marketing_ips=MK_IPS[:1])
    ids = [q.enqueue(ad(to=f"u{i}@naver.com")) for i in range(60)]
    calls = []
    real = mailer.send
    mailer.send = lambda e: calls.append(e) or real(e)
    done = w.run_once()
    assert done["sent"] == 50 and done["deferred"] == 10
    assert len(calls) == 51  # 한도 도달 확인 후 같은 그룹은 send 생략
    waiting = q.get(ids[-1])
    assert waiting.attempts == 0 and "한도" in waiting.last_reason
    now[0] = waiting.next_attempt_at
    assert w.run_once()["sent"] == 10  # 다음 날 한도(90)로 발송


def test_transactional_expires(env):
    q, w, _, _, now = env(reply=(451, "4.3.0 try later"))
    j = q.enqueue(tx(to="otp@corp.co.kr"), ttl=600)  # 인증번호 10분
    w.run_once()
    assert q.get(j).status is JobStatus.EXPIRED


def test_scheduled_cancel_and_idempotency(env):
    q, w, _, transport, now = env()
    j = q.enqueue(ad(), send_at=NOON + 3600, idempotency_key="campaign-1:user@naver.com")
    assert q.enqueue(ad(), idempotency_key="campaign-1:user@naver.com") == j
    assert w.run_once()["sent"] == 0
    now[0] += 3600
    assert w.run_once()["sent"] == 1
    k = q.enqueue(ad(to="b@naver.com"))
    assert not q.cancel(k, tenant_id="cafe")  # 다른 고객사는 취소 불가
    assert q.cancel(k, tenant_id="shop")
    w.run_once()
    assert q.get(k).status is JobStatus.CANCELED and len(transport.sent) == 1


def test_crashed_worker_lease_is_reclaimed(env):
    q, w, _, _, now = env()
    j = q.enqueue(tx())
    assert len(q.claim()) == 1  # 워커가 가져간 뒤 죽음
    assert w.run_once()["sent"] == 0
    now[0] += q.lease_seconds + 1
    assert w.run_once()["sent"] == 1 and q.get(j).status is JobStatus.SENT


def test_exception_does_not_stop_batch(env):
    q, w, mailer, _, _ = env()
    bad = q.enqueue(tx(to="a@naver.com"))
    good = q.enqueue(tx(to="b@naver.com"))
    real = mailer.send
    mailer.send = lambda e: (_ for _ in ()).throw(RuntimeError("boom")) if e.to == "a@naver.com" else real(e)
    w.run_once()
    assert q.get(bad).status is JobStatus.QUEUED and "boom" in q.get(bad).last_reason
    assert q.get(good).status is JobStatus.SENT
