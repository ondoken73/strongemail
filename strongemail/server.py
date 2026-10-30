"""설정 파일로 Mailer·큐·API 를 조립하고 API 서버 + 발송 워커 + 도메인 재검증을 함께 실행.

비밀값은 설정 파일이 아니라 환경변수로 받는다.
    STRONGEMAIL_MASTER_KEY    DKIM 개인키 암호화 키 (`strongemail init-secrets` 로 생성)
    STRONGEMAIL_UNSUB_SECRET  수신거부 링크 서명 키
    STRONGEMAIL_ADMIN_TOKEN   관리자 API 토큰

설정 예 (config.json):
{
  "db": "strongemail.db",
  "service_domain": "svc.kr",
  "unsubscribe_base_url": "https://mail.svc.kr",
  "listen": "127.0.0.1:8080",
  "transport": {"type": "relay", "host": "kumomta.internal", "port": 587},
  "pools": {
    "shared-transactional": [{"ip": "203.0.113.1", "helo": "mail1.svc.kr"}],
    "shared-marketing": [{"ip": "198.51.100.11", "helo": "mk1.svc.kr", "warmup_started": "2026-11-01"}]
  }
}
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import date

from .api import Api
from .domain_setup import service_spf_record
from .ip_pool import IPPool, SendingIP
from .mailqueue import MailQueue, Worker
from .reputation import ReputationMonitor, Store
from .sender import DirectMXTransport, Mailer, MailerConfig, RelayTransport
from .tenant_store import SqliteTenantRegistry, new_master_key

log = logging.getLogger("strongemail")
REVERIFY_INTERVAL = 24 * 3600


@dataclass
class Service:
    config: dict
    store: Store
    registry: SqliteTenantRegistry
    mailer: Mailer
    queue: MailQueue
    worker: Worker
    api: Api

    def all_ips(self) -> list[str]:
        return [ip.address for ip in self.mailer.ips.all_ips()]

    def service_spf(self):
        return service_spf_record(self.config["service_domain"], self.all_ips())

    def reverify_all(self) -> dict[str, bool]:
        """모든 고객 도메인 재검증. 고객이 DNS 를 지우거나 바꾸면 여기서 걸러진다."""
        results = {}
        for tenant in list(self.registry):
            for domain in list(tenant.domains):
                try:
                    results[domain] = self.mailer.verify_tenant_domain(tenant.id, domain).verified
                except Exception:  # 한 도메인 오류가 전체 재검증을 막지 않게
                    log.exception("reverify failed for %s", domain)
        return results


def _env(name: str, env) -> str:
    value = env.get(name)
    if not value:
        raise SystemExit(f"환경변수 {name} 가 필요합니다 (strongemail init-secrets 참고)")
    return value


def build_service(config: dict, env=os.environ, *, transport=None, resolver=None) -> Service:
    store = Store(config.get("db", "strongemail.db"))
    registry = SqliteTenantRegistry(store, _env("STRONGEMAIL_MASTER_KEY", env))
    pools = [IPPool(name, [SendingIP(i["ip"], i["helo"],
                                     date.fromisoformat(i["warmup_started"]) if i.get("warmup_started") else None,
                                     int(i.get("weight", 1))) for i in ips])
             for name, ips in config["pools"].items()]
    if transport is None:
        t = config.get("transport", {"type": "direct"})
        transport = (RelayTransport(t["host"], int(t.get("port", 587)), t.get("username"), env.get("STRONGEMAIL_RELAY_PASSWORD"),
                                    t.get("egress_header", "X-Egress-IP"))
                     if t["type"] == "relay" else DirectMXTransport())
    monitor = ReputationMonitor(store)
    mailer = Mailer(MailerConfig(config["unsubscribe_base_url"], _env("STRONGEMAIL_UNSUB_SECRET", env).encode()),
                    registry, pools, monitor, transport)
    if resolver is not None:
        mailer.domains._resolver = resolver
    queue = MailQueue(store)
    worker = Worker(queue, mailer)
    api = Api(mailer, queue, registry, service_domain=config["service_domain"],
              admin_token=_env("STRONGEMAIL_ADMIN_TOKEN", env))
    return Service(config, store, registry, mailer, queue, worker, api)


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def init_secrets() -> str:
    return "\n".join([
        f"export STRONGEMAIL_MASTER_KEY={new_master_key()}",
        f"export STRONGEMAIL_UNSUB_SECRET={secrets.token_urlsafe(32)}",
        f"export STRONGEMAIL_ADMIN_TOKEN={secrets.token_urlsafe(32)}",
    ])


def serve(service: Service) -> None:
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    stop = threading.Event()
    threading.Thread(target=service.worker.run_forever, args=(stop,), name="worker", daemon=True).start()

    def reverify_loop():
        while not stop.is_set():
            service.reverify_all()
            stop.wait(REVERIFY_INTERVAL)

    threading.Thread(target=reverify_loop, name="reverify", daemon=True).start()
    host, _, port = service.config.get("listen", "127.0.0.1:8080").rpartition(":")

    class QuietHandler(WSGIRequestHandler):
        def log_message(self, fmt, *args):
            log.info("%s - %s", self.address_string(), fmt % args)

    # wsgiref 는 개발/소규모용. 운영에서는 gunicorn 등으로 `service.api` 를 띄우고 워커는 별도 프로세스로.
    with make_server(host, int(port), service.api, handler_class=QuietHandler) as httpd:
        print(f"API: http://{host}:{port}  (워커·도메인 재검증 실행 중)")
        try:
            httpd.serve_forever()
        finally:
            stop.set()
