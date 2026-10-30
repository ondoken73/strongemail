import io
import json

import pytest

from strongemail.server import build_service, init_secrets
from strongemail.tenant_store import SqliteTenantRegistry
from test_dns_audit import FakeResolver
from test_sender import FakeTransport

ADMIN = "admin-token-0123456789abcdef"
CONFIG = {
    "db": ":memory:", "service_domain": "svc.kr", "unsubscribe_base_url": "https://mail.svc.kr",
    "pools": {"shared-transactional": [{"ip": "203.0.113.1", "helo": "mail1.svc.kr"}],
              "shared-marketing": [{"ip": "203.0.113.11", "helo": "mk1.svc.kr"},
                                   {"ip": "198.51.100.11", "helo": "mk2.svc.kr"}]},
}


@pytest.fixture
def svc(tmp_path):
    env = dict(line.split()[1].split("=", 1) for line in init_secrets().splitlines())
    env["STRONGEMAIL_ADMIN_TOKEN"] = ADMIN
    resolver = FakeResolver(txt={"_spf.svc.kr": ["v=spf1 ip4:203.0.113.1 ip4:203.0.113.11 ip4:198.51.100.11 -all"]})
    transport = FakeTransport()
    config = {**CONFIG, "db": str(tmp_path / "t.db")}
    service = build_service(config, env, transport=transport, resolver=resolver)
    return service, resolver, transport, env, config


def call(service, method, path, body=None, token=None):
    raw = json.dumps(body).encode() if body is not None else b""
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "", "CONTENT_LENGTH": str(len(raw)),
               "wsgi.input": io.BytesIO(raw)}
    if token:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    status = []
    out = b"".join(service.api(environ, lambda s, h: status.append(s)))
    return int(status[0].split()[0]), (json.loads(out) if out else None)


def onboard(service, tid="shop"):
    code, body = call(service, "POST", "/v1/admin/tenants",
                      {"id": tid, "name": "예시상점", "sender_name": "(주)예시상점", "sender_contact": "02-123-4567"}, ADMIN)
    assert code == 201, body
    return body["api_key"]


def publish(resolver, records):
    for r in records:
        if r["type"] == "TXT":
            resolver._txt[r["name"]] = [r["value"]]


def test_full_customer_flow(svc):
    service, resolver, transport, _, _ = svc
    key = onboard(service)

    code, dom = call(service, "POST", "/v1/domains", {"domain": "Shop.co.kr"}, key)
    assert code == 201 and dom["domain"] == "shop.co.kr" and not dom["verified"]
    rec = {(r["name"], r["type"]): r["value"] for r in dom["dns_records"]}
    assert rec[("shop.co.kr", "TXT")] == "v=spf1 include:_spf.svc.kr ~all"
    assert rec[("bounce.shop.co.kr", "MX")] == "10 mx.svc.kr"
    assert any(n.endswith("._domainkey.shop.co.kr") for n, _ in rec)

    # DNS 등록 전에는 검증 실패
    code, v = call(service, "POST", "/v1/domains/shop.co.kr/verify", None, key)
    assert code == 200 and not v["verified"] and {"SPF_MISSING", "DKIM_MISSING"} <= {f["code"] for f in v["findings"]}

    publish(resolver, dom["dns_records"])
    code, v = call(service, "POST", "/v1/domains/shop.co.kr/verify", None, key)
    assert v["verified"], v

    code, m = call(service, "POST", "/v1/messages", {
        "from": "news@shop.co.kr", "from_name": "예시상점", "to": "user@naver.com",
        "subject": "(광고) 가을 세일", "html": "<p>가을 세일을 시작합니다.</p>", "category": "marketing",
        "consent": {"opted_in_at": "2026-03-01T10:00:00+09:00"}, "idempotency_key": "c1:user"}, key)
    assert code == 202 and m["status"] == "queued"
    assert call(service, "POST", "/v1/messages", {
        "from": "news@shop.co.kr", "to": "user@naver.com", "subject": "(광고) x", "text": "x",
        "category": "marketing", "consent": {"opted_in_at": "2026-03-01"}, "idempotency_key": "c1:user"},
        key)[1]["id"] == m["id"]

    assert service.worker.run_once()["sent"] == 1
    code, st = call(service, "GET", f"/v1/messages/{m['id']}", None, key)
    assert st["status"] == "sent" and st["ip"] in ("203.0.113.11", "198.51.100.11")
    mail_from, _, data, _ = transport.sent[0]
    assert mail_from == "bounces@bounce.shop.co.kr" and b"d=shop.co.kr" in data

    code, stats = call(service, "GET", "/v1/stats", None, key)
    assert stats["queue"] == {"sent": 1} and stats["reputation_24h"]["sent"] == 1


def test_domain_rules(svc):
    service, *_ = svc
    a, b = onboard(service, "shop"), onboard(service, "cafe")
    assert call(service, "POST", "/v1/domains", {"domain": "naver.com"}, a)[0] == 422
    assert call(service, "POST", "/v1/domains", {"domain": "mail.svc.kr"}, a)[0] == 422
    assert call(service, "POST", "/v1/domains", {"domain": "not a domain"}, a)[0] == 422
    assert call(service, "POST", "/v1/domains", {"domain": "shop.co.kr"}, a)[0] == 201
    assert call(service, "POST", "/v1/domains", {"domain": "shop.co.kr"}, a)[0] == 200   # 같은 고객 재요청
    assert call(service, "POST", "/v1/domains", {"domain": "shop.co.kr"}, b)[0] == 409   # 다른 고객
    assert call(service, "GET", "/v1/domains/shop.co.kr", None, b)[0] == 404
    assert call(service, "DELETE", "/v1/domains/shop.co.kr", None, a)[0] == 204
    assert call(service, "POST", "/v1/domains", {"domain": "shop.co.kr"}, b)[0] == 201


def test_message_validation_and_isolation(svc):
    service, *_ = svc
    a, b = onboard(service, "shop"), onboard(service, "cafe")
    call(service, "POST", "/v1/domains", {"domain": "shop.co.kr"}, a)
    base = {"from": "news@shop.co.kr", "to": "u@naver.com", "subject": "안내", "text": "안내"}
    code, body = call(service, "POST", "/v1/messages", base, a)
    assert code == 422 and "검증" in body["error"]           # DNS 검증 전에는 접수하지 않음
    service.mailer.domains.mark_verified("shop.co.kr")
    assert call(service, "POST", "/v1/messages", {**base, "from": "ceo@bank.com"}, a)[0] == 422
    assert call(service, "POST", "/v1/messages", base, b)[0] == 422            # 남의 도메인
    assert call(service, "POST", "/v1/messages", {**base, "category": "marketing"}, a)[0] == 422  # 동의 없음
    assert call(service, "POST", "/v1/messages", {**base, "headers": {"DKIM-Signature": "x"}}, a)[0] == 422
    assert call(service, "POST", "/v1/messages", {**base, "send_at": "내일"}, a)[0] == 400
    code, m = call(service, "POST", "/v1/messages", {**base, "send_at": "2099-01-01T09:00:00"}, a)
    assert code == 202
    assert call(service, "GET", f"/v1/messages/{m['id']}", None, b)[0] == 404
    assert call(service, "DELETE", f"/v1/messages/{m['id']}", None, b)[0] == 404
    assert call(service, "DELETE", f"/v1/messages/{m['id']}", None, a)[0] == 204
    assert call(service, "DELETE", f"/v1/messages/{m['id']}", None, a)[0] == 409


def test_auth_and_admin(svc):
    service, *_ = svc
    assert call(service, "GET", "/v1/domains")[0] == 401
    assert call(service, "GET", "/v1/domains", None, "se_wrong")[0] == 401
    key = onboard(service)
    assert call(service, "POST", "/v1/admin/tenants", {"id": "x1"}, key)[0] == 403
    assert call(service, "POST", "/v1/admin/tenants/shop/suspend", {"reason": "구매 DB 발송"}, ADMIN)[0] == 200
    assert call(service, "GET", "/v1/stats", None, key)[1]["suspended"] == "구매 DB 발송"
    assert call(service, "GET", "/v1/admin/incidents", None, ADMIN) == (200, {"incidents": []})
    assert call(service, "PUT", "/v1/domains", None, key)[0] == 405
    assert call(service, "GET", "/nope", None, key)[0] == 404


def test_persistence_and_key_encryption(svc):
    service, resolver, transport, env, config = svc
    key = onboard(service)
    call(service, "POST", "/v1/domains", {"domain": "shop.co.kr"}, key)
    pem = service.registry.get("shop").domains["shop.co.kr"].dkim_private_key
    enc = service.store.execute("SELECT dkim_key_enc FROM tenant_domains")[0][0]
    assert b"PRIVATE KEY" not in enc
    assert service.store.execute("SELECT COUNT(*) FROM api_keys WHERE key_hash = ?", (key,))[0][0] == 0

    again = build_service(config, env, transport=transport, resolver=resolver)  # 재시작
    assert again.registry.get("shop").domains["shop.co.kr"].dkim_private_key == pem
    assert again.registry.tenant_for_key(key).id == "shop"
    with pytest.raises(Exception):
        SqliteTenantRegistry(again.store, init_secrets().split("=", 1)[1].split()[0])  # 다른 마스터 키


def test_reverify_and_service_spf(svc):
    service, resolver, *_ = svc
    key = onboard(service)
    _, dom = call(service, "POST", "/v1/domains", {"domain": "shop.co.kr"}, key)
    publish(resolver, dom["dns_records"])
    assert service.reverify_all() == {"shop.co.kr": True}
    del resolver._txt["shop.co.kr"]  # 고객이 SPF 를 지움
    assert service.reverify_all() == {"shop.co.kr": False}
    assert service.service_spf().value == "v=spf1 ip4:203.0.113.1 ip4:203.0.113.11 ip4:198.51.100.11 -all"
