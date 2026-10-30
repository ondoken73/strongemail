"""고객사·발신 도메인·API 키 영구 저장. DKIM 개인키는 마스터 키로 암호화해 저장한다.

마스터 키는 DB 와 분리해 보관한다 (환경변수 STRONGEMAIL_MASTER_KEY, 운영에서는 KMS/Vault).
DB 가 유출되어도 고객 도메인으로 서명할 수 없어야 한다.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time

from cryptography.fernet import Fernet

from .compliance import SenderIdentity
from .reputation import Store
from .tenants import SenderDomain, Tenant, TenantRegistry


def new_master_key() -> str:
    return Fernet.generate_key().decode()


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


class SqliteTenantRegistry(TenantRegistry):
    def __init__(self, store: Store, master_key: str | bytes, clock=time.time):
        super().__init__()
        self._s = store
        self._fernet = Fernet(master_key)
        self._clock = clock
        store.execute("""CREATE TABLE IF NOT EXISTS tenants (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, sender_name TEXT NOT NULL, sender_contact TEXT NOT NULL,
            pools TEXT NOT NULL, suspended TEXT, created_at REAL NOT NULL)""")
        store.execute("""CREATE TABLE IF NOT EXISTS tenant_domains (
            domain TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), selector TEXT NOT NULL,
            dkim_key_enc BLOB NOT NULL, bounce_subdomain TEXT NOT NULL, created_at REAL NOT NULL)""")
        store.execute("""CREATE TABLE IF NOT EXISTS api_keys (
            key_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, label TEXT NOT NULL, created_at REAL NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0)""")
        self._load()

    def _load(self) -> None:
        for tid, name, sname, scontact, pools, suspended, _ in self._s.execute("SELECT * FROM tenants"):
            t = Tenant(tid, name, SenderIdentity(sname, scontact), pools=json.loads(pools), suspended=suspended)
            super().add(t)
        for dom, tid, sel, enc, bounce, _ in self._s.execute("SELECT * FROM tenant_domains"):
            super().add_domain(tid, SenderDomain(dom, sel, self._fernet.decrypt(enc), bounce))

    # ------------------------------------------------------------- tenants

    def add(self, tenant: Tenant) -> Tenant:
        super().add(tenant)
        self._save_tenant(tenant)
        for d in tenant.domains.values():
            self._save_domain(tenant.id, d)
        return tenant

    def _save_tenant(self, t: Tenant) -> None:
        self._s.execute("INSERT OR REPLACE INTO tenants VALUES (?, ?, ?, ?, ?, ?, COALESCE("
                        "(SELECT created_at FROM tenants WHERE id = ?), ?))",
                        (t.id, t.name, t.sender_identity.name, t.sender_identity.contact, json.dumps(t.pools),
                         t.suspended, t.id, self._clock()))

    def update(self, tenant: Tenant) -> None:
        """이름·연락처·풀·정지 상태 변경 후 저장."""
        self._save_tenant(tenant)

    # ------------------------------------------------------------- domains

    def add_domain(self, tenant_id: str, d: SenderDomain) -> None:
        super().add_domain(tenant_id, d)
        self._save_domain(tenant_id, d)

    def _save_domain(self, tenant_id: str, d: SenderDomain) -> None:
        self._s.execute("INSERT OR REPLACE INTO tenant_domains VALUES (?, ?, ?, ?, ?, ?)",
                        (d.domain.lower(), tenant_id, d.dkim_selector, self._fernet.encrypt(d.dkim_private_key),
                         d.bounce_subdomain, self._clock()))

    def remove_domain(self, tenant_id: str, domain: str) -> None:
        super().remove_domain(tenant_id, domain)
        self._s.execute("DELETE FROM tenant_domains WHERE domain = ? AND tenant_id = ?", (domain.lower(), tenant_id))

    # ------------------------------------------------------------ API keys

    def issue_api_key(self, tenant_id: str, label: str = "default") -> str:
        """새 API 키. 원문은 이때 한 번만 보여주고 DB 에는 해시만 저장."""
        key = "se_" + secrets.token_urlsafe(32)
        self._s.execute("INSERT INTO api_keys VALUES (?, ?, ?, ?, 0)", (_hash_key(key), tenant_id, label, self._clock()))
        return key

    def revoke_api_key(self, api_key: str) -> None:
        self._s.execute("UPDATE api_keys SET revoked = 1 WHERE key_hash = ?", (_hash_key(api_key),))

    def tenant_for_key(self, api_key: str) -> Tenant | None:
        rows = self._s.execute("SELECT tenant_id FROM api_keys WHERE key_hash = ? AND revoked = 0", (_hash_key(api_key),))
        return self.get(rows[0][0]) if rows else None
