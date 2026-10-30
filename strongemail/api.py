"""고객용 HTTP API (WSGI).

인증: `Authorization: Bearer <API 키>` (고객사), 관리자 API 는 `Bearer <관리자 토큰>`.

    POST   /v1/domains                     {"domain"}           발신 도메인 등록 → DKIM 키 생성, 등록할 DNS 레코드 반환
    GET    /v1/domains                                          내 도메인 목록·검증 상태
    GET    /v1/domains/<domain>                                 레코드·검증 상태
    POST   /v1/domains/<domain>/verify                          DNS 검증 실행
    DELETE /v1/domains/<domain>
    POST   /v1/messages                    {...}                발송 요청 (큐 등록, 202)
    GET    /v1/messages/<id>                                    발송 상태
    DELETE /v1/messages/<id>                                    대기 중 발송 취소
    GET    /v1/stats                                            큐 현황·평판 지표

    POST   /v1/admin/tenants               {"id","name","sender_name","sender_contact","pools"?}  → API 키
    POST   /v1/admin/tenants/<id>/suspend  {"reason"}  /  .../resume
    GET    /v1/admin/incidents                                  진행 중 IP 차단 사고

    GET|POST /unsubscribe?t=...                                 원클릭 수신거부 (RFC 8058)
"""

from __future__ import annotations

import hmac
import json
import re
from dataclasses import asdict
from datetime import datetime

from .dns_audit import DnsLookupError, DnsPythonResolver
from .domain_setup import customer_records, dkim_txt_from_private_key, generate_dkim_key
from .domains import organizational_domain
from .mailqueue import MailQueue
from .providers import PROVIDERS
from .sender import KST, Category, Consent, Mailer, OutgoingEmail
from .tenant_store import SqliteTenantRegistry
from .tenants import SenderDomain, Tenant
from .compliance import SenderIdentity
from .unsubscribe import make_wsgi_app

MAX_BODY = 2 * 1024 * 1024
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL_RE = re.compile(r"^[^@\s<>\"]+@[^@\s<>\"]+\.[^@\s<>\"]+$")
# 포털·무료메일 도메인은 고객 발신 도메인으로 등록할 수 없다 (해당 포털 DMARC 로 거부되고 사칭이다)
_RESERVED = {d for p in PROVIDERS.values() for d in p.domains} | {"daum.net", "hanmail.net", "icloud.com", "me.com"}


class ApiError(Exception):
    def __init__(self, status: int, message: str, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


_STATUS_TEXT = {200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 400: "Bad Request",
                401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
                409: "Conflict", 413: "Payload Too Large", 422: "Unprocessable Entity"}


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, KST).isoformat() if ts else None


def _parse_time(value) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        raise ApiError(400, f"날짜 형식이 올바르지 않습니다 (ISO 8601): {value}")
    return dt if dt.tzinfo else dt.replace(tzinfo=KST)


class Api:
    def __init__(self, mailer: Mailer, queue: MailQueue, registry: SqliteTenantRegistry, *, service_domain: str,
                 admin_token: str):
        if len(admin_token) < 24:
            raise ValueError("admin token must be at least 24 characters")
        self.mailer, self.queue, self.registry = mailer, queue, registry
        self.service_domain = service_domain.lower()
        self.admin_token = admin_token
        self._unsub = make_wsgi_app(mailer.tokens, mailer.handle_unsubscribe)
        self._routes = [
            ("POST", r"/v1/domains", self.create_domain),
            ("GET", r"/v1/domains", self.list_domains),
            ("GET", r"/v1/domains/(?P<domain>[^/]+)", self.get_domain),
            ("POST", r"/v1/domains/(?P<domain>[^/]+)/verify", self.verify_domain),
            ("DELETE", r"/v1/domains/(?P<domain>[^/]+)", self.delete_domain),
            ("POST", r"/v1/messages", self.create_message),
            ("GET", r"/v1/messages/(?P<job_id>\d+)", self.get_message),
            ("DELETE", r"/v1/messages/(?P<job_id>\d+)", self.cancel_message),
            ("GET", r"/v1/stats", self.stats),
            ("POST", r"/v1/admin/tenants", self.admin_create_tenant),
            ("POST", r"/v1/admin/tenants/(?P<tenant_id>[^/]+)/suspend", self.admin_suspend),
            ("POST", r"/v1/admin/tenants/(?P<tenant_id>[^/]+)/resume", self.admin_resume),
            ("GET", r"/v1/admin/incidents", self.admin_incidents),
        ]

    # ------------------------------------------------------------ plumbing

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == "/unsubscribe":
            return self._unsub(environ, start_response)
        method = environ.get("REQUEST_METHOD", "GET")
        try:
            allowed = False
            for m, pattern, handler in self._routes:
                match = re.fullmatch(pattern, path)
                if not match:
                    continue
                allowed = True
                if m == method:
                    status, body = handler(environ, **match.groupdict())
                    break
            else:
                raise ApiError(405 if allowed else 404, "허용되지 않는 메서드입니다" if allowed else "없는 경로입니다")
        except ApiError as e:
            status, body = e.status, {"error": e.message, **e.extra}
        payload = b"" if status == 204 else json.dumps(body, ensure_ascii=False, default=str).encode()
        start_response(f"{status} {_STATUS_TEXT.get(status, '')}",
                       [("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(payload)))])
        return [payload]

    @staticmethod
    def _json(environ) -> dict:
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            raise ApiError(413, "요청 본문이 너무 큽니다")
        raw = environ["wsgi.input"].read(length) if length else b""
        try:
            data = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise ApiError(400, "JSON 본문이 올바르지 않습니다")
        if not isinstance(data, dict):
            raise ApiError(400, "JSON 객체가 필요합니다")
        return data

    @staticmethod
    def _bearer(environ) -> str:
        auth = environ.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Bearer "):
            raise ApiError(401, "Authorization: Bearer <API 키> 헤더가 필요합니다")
        return auth[7:].strip()

    def _tenant(self, environ) -> Tenant:
        tenant = self.registry.tenant_for_key(self._bearer(environ))
        if tenant is None:
            raise ApiError(401, "유효하지 않은 API 키입니다")
        return tenant

    def _admin(self, environ) -> None:
        if not hmac.compare_digest(self._bearer(environ), self.admin_token):
            raise ApiError(403, "관리자 권한이 필요합니다")

    # ------------------------------------------------------------- domains

    def _domain_view(self, tenant: Tenant, sd: SenderDomain, *, with_records: bool = True) -> dict:
        ok, reason = self.mailer.domains.status(sd.domain)
        view = {"domain": sd.domain, "dkim_selector": sd.dkim_selector, "return_path": sd.return_path,
                "verified": ok, "status_reason": reason or None}
        if with_records:
            existing = None  # 고객의 기존 SPF 가 있으면 합친 값을 안내
            try:
                resolver = self.mailer.domains._resolver or DnsPythonResolver()
                existing = next((t for t in resolver.txt(sd.domain) if t.lower().startswith("v=spf1")), None)
            except DnsLookupError:
                pass
            view["dns_records"] = [asdict(r) for r in customer_records(
                sd.domain, service_domain=self.service_domain, selector=sd.dkim_selector,
                dkim_txt=dkim_txt_from_private_key(sd.dkim_private_key), existing_spf=existing,
                bounce_subdomain=sd.bounce_subdomain)]
        return view

    def _own_domain(self, tenant: Tenant, domain: str) -> SenderDomain:
        sd = tenant.domains.get(domain.lower())
        if sd is None:
            raise ApiError(404, f"{domain} 은 등록된 발신 도메인이 아닙니다")
        return sd

    def create_domain(self, environ):
        tenant = self._tenant(environ)
        domain = str(self._json(environ).get("domain", "")).strip().lower().rstrip(".")
        if not _DOMAIN_RE.match(domain):
            raise ApiError(422, "올바른 도메인이 아닙니다")
        if domain in _RESERVED or organizational_domain(domain) in _RESERVED:
            raise ApiError(422, "포털·무료메일 도메인은 발신 도메인으로 쓸 수 없습니다. 회사 도메인을 등록하세요")
        if domain == self.service_domain or domain.endswith("." + self.service_domain):
            raise ApiError(422, "서비스 도메인은 등록할 수 없습니다")
        owner = self.registry.owner_of(domain)
        if owner == tenant.id:
            return 200, self._domain_view(tenant, tenant.domains[domain])
        if owner is not None:
            raise ApiError(409, "이미 다른 고객사가 등록한 도메인입니다. 소유자라면 고객센터로 문의하세요")
        pem, _ = generate_dkim_key()
        selector = "se" + datetime.fromtimestamp(self.mailer._clock(), KST).strftime("%Y%m")
        sd = SenderDomain(domain, selector, pem)
        self.registry.add_domain(tenant.id, sd)
        return 201, self._domain_view(tenant, sd)

    def list_domains(self, environ):
        tenant = self._tenant(environ)
        return 200, {"domains": [self._domain_view(tenant, sd, with_records=False) for sd in tenant.domains.values()]}

    def get_domain(self, environ, domain):
        tenant = self._tenant(environ)
        return 200, self._domain_view(tenant, self._own_domain(tenant, domain))

    def verify_domain(self, environ, domain):
        tenant = self._tenant(environ)
        sd = self._own_domain(tenant, domain)
        result = self.mailer.verify_tenant_domain(tenant.id, sd.domain)
        return 200, {"domain": sd.domain, "verified": result.verified,
                     "findings": [{"code": f.code, "severity": f.severity.value, "message": f.message}
                                  for f in result.findings]}

    def delete_domain(self, environ, domain):
        tenant = self._tenant(environ)
        sd = self._own_domain(tenant, domain)
        self.registry.remove_domain(tenant.id, sd.domain)
        self.mailer.monitor.store.execute("DELETE FROM sender_domains WHERE domain = ?", (sd.domain,))
        return 204, None

    # ------------------------------------------------------------ messages

    def create_message(self, environ):
        tenant = self._tenant(environ)
        d = self._json(environ)
        for field in ("from", "to", "subject"):
            if not d.get(field):
                raise ApiError(422, f"'{field}' 가 필요합니다")
        if not d.get("text") and not d.get("html"):
            raise ApiError(422, "'text' 또는 'html' 이 필요합니다")
        for field in ("from", "to"):
            if not _EMAIL_RE.match(str(d[field])):
                raise ApiError(422, f"'{field}' 이메일 주소가 올바르지 않습니다")
        sd = tenant.sender_domain_for(d["from"])
        if sd is None:
            raise ApiError(422, f"{d['from']} 은 등록된 발신 도메인 주소가 아닙니다. 먼저 /v1/domains 로 등록하세요")
        if self.mailer.cfg.require_verified_domain:
            ok, why = self.mailer.domains.status(sd.domain)
            if not ok:
                raise ApiError(422, why, domain=sd.domain)
        try:
            category = Category(d.get("category", "transactional"))
        except ValueError:
            raise ApiError(422, "category 는 transactional 또는 marketing 입니다")
        consent = None
        if c := d.get("consent"):
            consent = Consent(_parse_time(c.get("opted_in_at")), _parse_time(c.get("last_confirmed_at")),
                              bool(c.get("night_opt_in", False)))
        if category is Category.MARKETING and consent is None:
            raise ApiError(422, "광고 메일은 수신동의 정보(consent.opted_in_at)가 필요합니다 (정보통신망법 제50조)")
        headers = d.get("headers") or {}
        if not isinstance(headers, dict) or any(k.lower() in {"from", "to", "subject", "dkim-signature", "return-path",
                                                              "list-unsubscribe", "list-unsubscribe-post"}
                                                for k in headers):
            raise ApiError(422, "headers 로 바꿀 수 없는 헤더가 포함되어 있습니다")
        text = d.get("text") or re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", d["html"])).strip()
        email = OutgoingEmail(
            tenant_id=tenant.id, from_address=d["from"], from_name=d.get("from_name", ""), to=d["to"],
            subject=d["subject"], text=text, html=d.get("html"), category=category, consent=consent,
            list_id=str(d.get("list_id", "default"))[:64], reply_to=d.get("reply_to"), headers=headers)
        send_at = _parse_time(d.get("send_at"))
        ttl = d.get("ttl_seconds")
        job_id = self.queue.enqueue(email, send_at=send_at.timestamp() if send_at else None,
                                    ttl=float(ttl) if ttl else None, idempotency_key=d.get("idempotency_key"))
        return 202, {"id": job_id, "status": self.queue.get(job_id).status.value}

    def _own_job(self, tenant: Tenant, job_id: str):
        job = self.queue.get(int(job_id))
        if job is None or job.tenant_id != tenant.id:
            raise ApiError(404, "없는 발송 요청입니다")
        return job

    def get_message(self, environ, job_id):
        tenant = self._tenant(environ)
        j = self._own_job(tenant, job_id)
        return 200, {"id": j.id, "status": j.status.value, "to": j.to, "category": j.category.value,
                     "attempts": j.attempts, "last_reason": j.last_reason or None, "ip": j.last_ip or None,
                     "created_at": _iso(j.created_at), "next_attempt_at": _iso(j.next_attempt_at),
                     "expires_at": _iso(j.expires_at)}

    def cancel_message(self, environ, job_id):
        tenant = self._tenant(environ)
        self._own_job(tenant, job_id)
        if not self.queue.cancel(int(job_id), tenant.id):
            raise ApiError(409, "대기 중인 발송만 취소할 수 있습니다")
        return 204, None

    def stats(self, environ):
        tenant = self._tenant(environ)
        h = self.mailer.monitor.health(tenant=tenant.id)
        return 200, {"queue": self.queue.stats(tenant.id),
                     "reputation_24h": {"health": h.health.value, "sent": h.sent,
                                        "hard_bounce_rate": h.hard_bounce_rate, "complaint_rate": h.complaint_rate,
                                        "blocked_rate": h.blocked_rate, "reasons": list(h.reasons)},
                     "suspended": tenant.suspended}

    # --------------------------------------------------------------- admin

    def admin_create_tenant(self, environ):
        self._admin(environ)
        d = self._json(environ)
        tid = str(d.get("id", ""))
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,40}", tid):
            raise ApiError(422, "id 는 영문 소문자·숫자·-_ 2~41자입니다")
        if self.registry.get(tid):
            raise ApiError(409, "이미 있는 고객사 id 입니다")
        for field in ("name", "sender_name", "sender_contact"):
            if not d.get(field):
                raise ApiError(422, f"'{field}' 가 필요합니다 (광고 메일 전송자 표기에 사용)")
        tenant = Tenant(tid, d["name"], SenderIdentity(d["sender_name"], d["sender_contact"]))
        if pools := d.get("pools"):
            unknown = set(pools.values()) - set(self.mailer.ips.pools)
            if unknown:
                raise ApiError(422, f"없는 IP 풀: {', '.join(sorted(unknown))}")
            tenant.pools = dict(pools)
        self.registry.add(tenant)
        return 201, {"id": tid, "api_key": self.registry.issue_api_key(tid),
                     "note": "API 키는 다시 보여주지 않습니다. 안전한 곳에 보관하세요."}

    def _set_suspended(self, environ, tenant_id, reason):
        self._admin(environ)
        tenant = self.registry.get(tenant_id)
        if tenant is None:
            raise ApiError(404, "없는 고객사입니다")
        tenant.suspended = reason
        self.registry.update(tenant)
        return 200, {"id": tenant_id, "suspended": reason}

    def admin_suspend(self, environ, tenant_id):
        reason = self._json(environ).get("reason") or "관리자 정지"
        return self._set_suspended(environ, tenant_id, reason)

    def admin_resume(self, environ, tenant_id):
        return self._set_suspended(environ, tenant_id, None)

    def admin_incidents(self, environ):
        self._admin(environ)
        return 200, {"incidents": [
            {"id": i.id, "ip": i.ip, "target": i.target, "state": i.state.value, "opened_at": _iso(i.opened_at),
             "evidence": i.evidence, "actions": i.actions, "appeal_count": i.appeal_count}
            for i in self.mailer.incidents.active()]}
