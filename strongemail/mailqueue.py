"""발송 큐와 재시도 워커.

Mailer.send 는 한 통을 한 번 시도하고 SENT / DEFERRED(retry_after) / REJECTED 를 돌려준다.
큐는 그 결과로 재시도 일정을 잡는다.

  * 거래성 메일 우선 (인증번호가 광고 뒤에 밀리지 않게)
  * DEFERRED: retry_after 와 지수 백오프 중 큰 값 후 재시도. 다른 IP 로 나갈 수 있다
  * 실제 SMTP 시도만 시도 횟수로 센다 (웜업 한도·평판 중지 같은 대기는 횟수에 넣지 않음)
  * 만료 시간이 지나면 포기 (인증번호는 짧게, 광고는 길게)
  * 같은 배치에서 (고객사, 종류, 포털)이 통째로 막히면 나머지는 send 를 부르지 않고 바로 미룸
  * 워커가 죽어도 lease 가 끝나면 다른 워커가 다시 가져감
  * idempotency_key 로 같은 요청이 두 번 들어와도 한 번만 발송
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum

from .providers import provider_for
from .reputation import Store
from .sender import Category, Consent, Mailer, OutgoingEmail, SendResult, Status


class JobStatus(str, Enum):
    QUEUED = "queued"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"        # 재시도해도 안 되는 거부 (수신제외, 동의 없음, 하드바운스 ...)
    EXPIRED = "expired"      # 만료 시간까지 못 보냄
    CANCELED = "canceled"


DEFAULT_TTL = {Category.TRANSACTIONAL: 6 * 3600, Category.MARKETING: 72 * 3600}
PRIORITY = {Category.TRANSACTIONAL: 0, Category.MARKETING: 10}


def _encode(email: OutgoingEmail) -> str:
    d = asdict(email)
    d["category"] = email.category.value
    if email.consent:
        d["consent"] = {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in asdict(email.consent).items()}
    return json.dumps(d, ensure_ascii=False)


def _decode(payload: str) -> OutgoingEmail:
    d = json.loads(payload)
    d["category"] = Category(d["category"])
    if d.get("consent"):
        c = d["consent"]
        for k in ("marketing_opt_in_at", "last_confirmed_at"):
            c[k] = datetime.fromisoformat(c[k]) if c.get(k) else None
        d["consent"] = Consent(**c)
    return OutgoingEmail(**d)


@dataclass
class Job:
    id: int
    status: JobStatus
    tenant_id: str
    to: str
    category: Category
    attempts: int
    next_attempt_at: float
    expires_at: float
    created_at: float
    last_reason: str
    last_ip: str
    email: OutgoingEmail


class MailQueue:
    _COLS = ("id, status, tenant_id, rcpt, category, attempts, next_attempt_at, expires_at, created_at, "
             "last_reason, last_ip, payload")

    def __init__(self, store: Store, clock=time.time, lease_seconds: float = 300):
        self._s = store
        self._clock = clock
        self.lease_seconds = lease_seconds
        store.execute("""CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT NOT NULL, tenant_id TEXT NOT NULL,
            rcpt TEXT NOT NULL, provider TEXT NOT NULL, category TEXT NOT NULL, priority INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at REAL NOT NULL, expires_at REAL NOT NULL,
            lease_until REAL, created_at REAL NOT NULL, updated_at REAL NOT NULL,
            last_reason TEXT NOT NULL DEFAULT '', last_ip TEXT NOT NULL DEFAULT '', smtp_code INTEGER,
            idempotency_key TEXT, payload TEXT NOT NULL)""")
        store.execute("CREATE INDEX IF NOT EXISTS jobs_ready ON jobs (status, priority, next_attempt_at)")
        store.execute("CREATE UNIQUE INDEX IF NOT EXISTS jobs_idem ON jobs (tenant_id, idempotency_key) "
                      "WHERE idempotency_key IS NOT NULL")

    def _row(self, r) -> Job:
        return Job(r[0], JobStatus(r[1]), r[2], r[3], Category(r[4]), r[5], r[6], r[7], r[8], r[9], r[10],
                   _decode(r[11]))

    def enqueue(self, email: OutgoingEmail, *, send_at: float | None = None, ttl: float | None = None,
                idempotency_key: str | None = None) -> int:
        now = self._clock()
        if idempotency_key:
            rows = self._s.execute("SELECT id FROM jobs WHERE tenant_id = ? AND idempotency_key = ?",
                                   (email.tenant_id, idempotency_key))
            if rows:
                return rows[0][0]
        start = max(now, send_at or now)
        rows = self._s.execute(
            "INSERT INTO jobs (status, tenant_id, rcpt, provider, category, priority, next_attempt_at, expires_at, "
            "created_at, updated_at, idempotency_key, payload) VALUES ('queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "RETURNING id",
            (email.tenant_id, email.to.lower(), provider_for(email.to).key, email.category.value,
             PRIORITY[email.category], start, start + (ttl or DEFAULT_TTL[email.category]), now, now,
             idempotency_key, _encode(email)))
        return rows[0][0]

    def get(self, job_id: int) -> Job | None:
        rows = self._s.execute(f"SELECT {self._COLS} FROM jobs WHERE id = ?", (job_id,))
        return self._row(rows[0]) if rows else None

    def cancel(self, job_id: int, tenant_id: str | None = None) -> bool:
        sql = "UPDATE jobs SET status = 'canceled', updated_at = ? WHERE id = ? AND status = 'queued'"
        params: tuple = (self._clock(), job_id)
        if tenant_id is not None:
            sql += " AND tenant_id = ?"
            params += (tenant_id,)
        return bool(self._s.execute(sql + " RETURNING id", params))

    def claim(self, limit: int = 100) -> list[Job]:
        """준비된 작업을 원자적으로 가져온다 (만료된 lease 의 'sending' 도 회수)."""
        now = self._clock()
        rows = self._s.execute(
            f"""UPDATE jobs SET status = 'sending', lease_until = ?, updated_at = ?
                WHERE id IN (SELECT id FROM jobs
                             WHERE (status = 'queued' AND next_attempt_at <= ?)
                                OR (status = 'sending' AND lease_until < ?)
                             ORDER BY priority, next_attempt_at LIMIT ?)
                RETURNING {self._COLS}""",
            (now + self.lease_seconds, now, now, now, limit))
        return sorted((self._row(r) for r in rows), key=lambda j: (PRIORITY[j.category], j.next_attempt_at))

    def _finish(self, job: Job, status: JobStatus, reason: str, *, attempts: int, ip: str = "",
                smtp_code: int | None = None, next_at: float | None = None) -> None:
        self._s.execute(
            "UPDATE jobs SET status = ?, last_reason = ?, attempts = ?, last_ip = COALESCE(NULLIF(?, ''), last_ip), "
            "smtp_code = COALESCE(?, smtp_code), next_attempt_at = COALESCE(?, next_attempt_at), lease_until = NULL, "
            "updated_at = ? WHERE id = ?",
            (status.value, reason[:500], attempts, ip, smtp_code, next_at, self._clock(), job.id))

    def stats(self, tenant_id: str | None = None) -> dict[str, int]:
        sql, params = "SELECT status, COUNT(*) FROM jobs", ()
        if tenant_id:
            sql, params = sql + " WHERE tenant_id = ?", (tenant_id,)
        return dict(self._s.execute(sql + " GROUP BY status", params))


@dataclass(frozen=True)
class RetryPolicy:
    base: float = 60.0          # 1분, 2분, 4분 ...
    max_delay: float = 3600.0
    max_attempts: int = 8       # 실제 SMTP 시도 횟수

    def delay(self, attempts: int) -> float:
        return min(self.max_delay, self.base * 2 ** max(attempts - 1, 0))


class Worker:
    def __init__(self, queue: MailQueue, mailer: Mailer, policy: RetryPolicy = RetryPolicy(), clock=time.time):
        self.queue = queue
        self.mailer = mailer
        self.policy = policy
        self._clock = clock

    def run_once(self, batch: int = 100) -> dict[str, int]:
        """한 배치 처리. 처리 결과 개수를 돌려준다."""
        done = {"sent": 0, "deferred": 0, "failed": 0, "expired": 0}
        blocked_groups: dict[tuple, tuple[float, str]] = {}
        for job in self.queue.claim(batch):
            now = self._clock()
            if now >= job.expires_at:
                self.queue._finish(job, JobStatus.EXPIRED, f"만료 (마지막 사유: {job.last_reason or '-'})",
                                   attempts=job.attempts)
                done["expired"] += 1
                continue
            group = (job.tenant_id, job.category, provider_for(job.to).key)
            if group in blocked_groups:
                retry_after, reason = blocked_groups[group]
                self._defer(job, retry_after, reason, job.attempts)
                done["deferred"] += 1
                continue
            crashed = False
            try:
                result = self.mailer.send(job.email)
            except Exception as e:  # 한 통의 예외가 배치 전체를 멈추지 않게
                crashed = True
                result = SendResult(Status.DEFERRED, f"내부 오류: {e.__class__.__name__}: {e}", retry_after=300)
            attempted = result.smtp_code is not None
            attempts = job.attempts + (1 if attempted else 0)
            if result.status is Status.SENT:
                self.queue._finish(job, JobStatus.SENT, "OK", attempts=attempts, ip=result.ip or "",
                                   smtp_code=result.smtp_code)
                done["sent"] += 1
            elif result.status is Status.REJECTED:
                self.queue._finish(job, JobStatus.FAILED, result.reason, attempts=attempts, ip=result.ip or "",
                                   smtp_code=result.smtp_code)
                done["failed"] += 1
            elif attempts >= self.policy.max_attempts:
                self.queue._finish(job, JobStatus.FAILED, f"재시도 {attempts}회 초과: {result.reason}",
                                   attempts=attempts, ip=result.ip or "", smtp_code=result.smtp_code)
                done["failed"] += 1
            else:
                delay = max(result.retry_after, self.policy.delay(attempts) if attempted else 0)
                if not attempted and not crashed:
                    # 평판 중지·웜업 한도·풀 중지 등 → 같은 그룹은 이번 배치에서 send 생략
                    blocked_groups[group] = (delay, result.reason)
                self._defer(job, delay, result.reason, attempts, result.ip or "", result.smtp_code)
                done["deferred"] += 1
        return done

    def _defer(self, job: Job, delay: float, reason: str, attempts: int, ip: str = "", smtp_code=None) -> None:
        next_at = self._clock() + max(delay, 1.0)
        if next_at >= job.expires_at:
            self.queue._finish(job, JobStatus.EXPIRED, f"만료 전 발송 불가: {reason}", attempts=attempts, ip=ip,
                               smtp_code=smtp_code)
            return
        self.queue._finish(job, JobStatus.QUEUED, reason, attempts=attempts, ip=ip, smtp_code=smtp_code,
                           next_at=next_at)

    def run_forever(self, stop: threading.Event, *, batch: int = 100, idle_sleep: float = 1.0) -> None:
        while not stop.is_set():
            done = self.run_once(batch)
            if not any(done.values()):
                stop.wait(idle_sleep)
