"""고객사(tenant)와 고객사 발신 도메인.

서비스를 쓰는 고객은 자기 도메인 주소(예: news@shop.co.kr)로 발송한다. 그러려면
  * 고객 도메인에 우리 발송 IP 를 SPF 로 허용 (보통 `include:_spf.<서비스도메인>` 한 줄),
  * 고객 도메인 이름으로 DKIM 서명 (고객 DNS 에 공개키 또는 우리 쪽으로의 CNAME),
  * DMARC 존재,
가 필요하고, 고객이 *자기가 등록·검증한 도메인으로만* 보낼 수 있어야 한다
(다른 고객이나 남의 도메인을 사칭하는 것을 막는다).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .compliance import SenderIdentity
from .domains import domain_of


@dataclass
class SenderDomain:
    domain: str
    dkim_selector: str
    dkim_private_key: bytes
    bounce_subdomain: str = "bounce"  # 반송 주소: bounces@bounce.<domain> (SPF 정렬)

    @property
    def return_path(self) -> str:
        return f"bounces@{self.bounce_subdomain}.{self.domain}"


@dataclass
class Tenant:
    id: str
    name: str
    sender_identity: SenderIdentity          # 광고 본문에 들어갈 고객사 상호·연락처
    domains: dict[str, SenderDomain] = field(default_factory=dict)
    # 메일 종류별 IP 풀. 대량 고객은 전용 풀을 주면 다른 고객의 평판과 분리된다.
    pools: dict[str, str] = field(default_factory=lambda: {"transactional": "shared-transactional",
                                                           "marketing": "shared-marketing"})
    allowed_from: set[str] = field(default_factory=set)  # 비어 있으면 검증 도메인의 모든 주소 허용
    suspended: str | None = None                          # 정지 사유 (약관 위반, 평판 사고 등)

    def add_domain(self, d: SenderDomain) -> None:
        self.domains[d.domain.lower()] = d

    def sender_domain_for(self, from_address: str) -> SenderDomain | None:
        """From 주소가 이 고객의 도메인(또는 그 하위 도메인)인가."""
        dom = domain_of(from_address)
        if self.allowed_from and from_address.lower() not in self.allowed_from:
            return None
        if dom in self.domains:
            return self.domains[dom]
        # news.shop.co.kr → shop.co.kr 에 등록된 키로 서명 (DMARC relaxed 정렬)
        for name, d in self.domains.items():
            if dom.endswith("." + name):
                return d
        return None

    def pool_for(self, category: str) -> str:
        return self.pools.get(category, self.pools.get("transactional", "shared-transactional"))


class TenantRegistry:
    """메모리 레지스트리. 운영에서는 DB + 비밀키 저장소(KMS 등)로 교체한다."""

    def __init__(self):
        self._tenants: dict[str, Tenant] = {}
        self._domain_owner: dict[str, str] = {}

    def add(self, tenant: Tenant) -> Tenant:
        for dom in tenant.domains:
            self._claim(dom, tenant.id)
        self._tenants[tenant.id] = tenant
        return tenant

    def _claim(self, domain: str, tenant_id: str) -> None:
        owner = self._domain_owner.get(domain)
        if owner and owner != tenant_id:
            raise ValueError(f"{domain} 은 이미 다른 고객({owner})이 등록한 도메인입니다")
        self._domain_owner[domain] = tenant_id

    def add_domain(self, tenant_id: str, d: SenderDomain) -> None:
        self._claim(d.domain.lower(), tenant_id)
        self._tenants[tenant_id].add_domain(d)

    def get(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def __iter__(self):
        return iter(self._tenants.values())
