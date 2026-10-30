"""발신 도메인 설정: SPF/DKIM/DMARC 레코드 생성, DMARC 단계적 적용, 발신 도메인 검증.

발신 도메인은 검증(우리 발송 IP가 SPF에 포함, DKIM 공개키 일치, DMARC 존재)을
통과해야만 발송할 수 있다. 검증 결과는 Store 에 기록되고 Mailer 가 확인한다.
"""

from __future__ import annotations

import base64
import ipaddress
import time
from dataclasses import dataclass

from .dns_audit import DnsLookupError, DnsPythonResolver, Resolver, _tag_list, check_dmarc, check_spf
from .domains import organizational_domain
from .findings import Finding, Severity, has_errors
from .reputation import Store


@dataclass(frozen=True)
class DnsRecord:
    name: str
    type: str
    value: str
    note: str = ""

    def __str__(self) -> str:
        return f"{self.name}  {self.type}  \"{self.value}\"" + (f"\n    └ {self.note}" if self.note else "")


# ---------------------------------------------------------------- SPF 생성

def spf_record(ips: list[str], includes: list[str] = (), existing: str | None = None, all_qualifier: str = "~all") -> str:
    """새 SPF 를 만들거나, 기존 SPF 에 우리 발송 IP/include 를 합친다 (SPF 는 도메인당 1개만 허용)."""
    mechanisms: list[str] = []
    if existing:
        for term in existing.split()[1:]:
            if term.lstrip("+-~?").lower() == "all":
                q = term[0] if term[0] in "+-~?" else "+"
                # 기존 정책이 -all/~all 이면 유지, +all/?all 은 위험하므로 교체
                if q in "-~":
                    all_qualifier = f"{q}all"
            elif not term.lower().startswith("redirect="):
                mechanisms.append(term)
    for ip in ips:
        net = ipaddress.ip_network(ip, strict=False)
        mech = f"{'ip4' if net.version == 4 else 'ip6'}:{ip}"
        if mech not in mechanisms:
            mechanisms.append(mech)
    for inc in includes:
        if f"include:{inc}" not in mechanisms:
            mechanisms.append(f"include:{inc}")
    return " ".join(["v=spf1", *mechanisms, all_qualifier])


# -------------------------------------------------------------- DMARC 단계

@dataclass(frozen=True)
class DmarcStage:
    policy: str
    pct: int
    min_days: int
    goal: str


DMARC_ROLLOUT = (
    DmarcStage("none", 100, 14, "rua 리포트로 정상 발송원이 모두 SPF/DKIM 정렬 통과하는지 확인"),
    DmarcStage("quarantine", 25, 7, "일부만 격리 — 누락된 발송원(그룹웨어, CRM, 결제 알림 등)이 있는지 확인"),
    DmarcStage("quarantine", 100, 14, "전체 격리 — 정렬 실패율 0.5% 미만 유지"),
    DmarcStage("reject", 100, 0, "최종 단계 — 위조 메일 차단, BIMI 로고 표시 조건 충족"),
)


def dmarc_record(rua: str, stage: DmarcStage = DMARC_ROLLOUT[0], *, subdomain_policy: str | None = None,
                 strict: bool = False) -> str:
    parts = ["v=DMARC1", f"p={stage.policy}"]
    if stage.pct != 100:
        parts.append(f"pct={stage.pct}")
    if subdomain_policy:
        parts.append(f"sp={subdomain_policy}")
    parts.append(f"rua=mailto:{rua}")
    if strict:
        parts += ["adkim=s", "aspf=s"]
    return "; ".join(parts)


# ---------------------------------------------------------------- DKIM 키

def generate_dkim_key(bits: int = 2048) -> tuple[bytes, str]:
    """(PEM 개인키, DKIM TXT 값) 을 만든다. 개인키는 발송 서버에만 보관."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"


def dkim_txt_from_private_key(pem: bytes) -> str:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(pem, password=None)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"


# ---------------------------------------------------------- 설정 안내 생성

def setup_plan(domain: str, *, ips: list[str], includes: list[str] = (), selector: str, dkim_txt: str,
               rua: str | None = None, bounce_subdomain: str = "bounce",
               resolver: Resolver | None = None) -> list[DnsRecord]:
    """발신 도메인에 등록해야 할 DNS 레코드 목록. 기존 SPF 가 있으면 합친다."""
    resolver = resolver or DnsPythonResolver()
    org = organizational_domain(domain)
    rua = rua or f"dmarc-reports@{org}"
    try:
        existing = next((t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")), None)
    except DnsLookupError:
        existing = None
    bounce = f"{bounce_subdomain}.{domain}"
    records = [
        DnsRecord(domain, "TXT", spf_record(ips, includes, existing),
                  "기존 SPF 에 합친 값입니다 — 새 레코드를 추가하지 말고 기존 것을 교체하세요." if existing else
                  "모든 발송원이 확인되면 ~all → -all 로 강화하세요."),
        DnsRecord(f"{selector}._domainkey.{domain}", "TXT", dkim_txt, "2048비트. 255자 넘으면 DNS 업체 안내대로 분할 입력."),
        DnsRecord(f"_dmarc.{org}", "TXT", dmarc_record(rua),
                  "1단계(p=none). `strongemail dmarc-plan` 의 일정대로 quarantine → reject 상향."),
        DnsRecord(bounce, "TXT", spf_record(ips, includes, all_qualifier="-all"),
                  f"Return-Path(반송 주소)용 하위 도메인. SPF 정렬을 위해 bounces@{bounce} 사용."),
    ]
    if ips:
        records.append(DnsRecord(bounce, "MX", f"10 mx.{domain}", "반송 메일(DSN)을 받을 서버."))
        for ip in ips:
            records.append(DnsRecord(ip, "PTR", f"mail.{domain}",
                                     "IP 소유자(IDC/클라우드)에 요청. mail.<도메인> 의 A 레코드도 같은 IP 로 등록 (FCrDNS)."))
    return records


# ---------------------------------------------------------- SPF 평가 (검증용)

def spf_authorizes(resolver: Resolver, domain: str, ip: str, _depth: int = 0) -> bool:
    """이 IP 가 domain 의 SPF 에서 pass 되는가 (ip4/ip6/a/mx/include/redirect 지원)."""
    if _depth > 10:
        return False
    records = [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]
    if len(records) != 1:
        return False
    addr = ipaddress.ip_address(ip)
    redirect = None
    for term in records[0].split()[1:]:
        qualifier = term[0] if term[0] in "+-~?" else "+"
        mech = term.lstrip("+-~?")
        if mech.lower().startswith("redirect="):
            redirect = mech.split("=", 1)[1]
            continue
        name, _, arg = mech.partition(":")
        name = name.lower().split("/")[0]  # "a/24", "mx/24" (CIDR 접미사는 단순화를 위해 무시)
        arg = arg.split("/")[0] if name in ("a", "mx") else arg
        matched = False
        if name in ("ip4", "ip6"):
            try:
                matched = addr in ipaddress.ip_network(arg, strict=False)
            except ValueError:
                matched = False
        elif name == "a":
            matched = ip in resolver.addresses(arg or domain)
        elif name == "mx":
            matched = any(ip in resolver.addresses(mx) for mx in resolver.mx(arg or domain))
        elif name == "include":
            matched = spf_authorizes(resolver, arg, ip, _depth + 1)
        elif name == "all":
            return qualifier == "+"
        if matched:
            return qualifier == "+"
    return spf_authorizes(resolver, redirect, ip, _depth + 1) if redirect else False


# ------------------------------------------------------------ 발신 도메인 검증

@dataclass(frozen=True)
class VerificationResult:
    domain: str
    verified: bool
    findings: list[Finding]


class SenderDomainRegistry:
    """발신 도메인 검증 상태. 검증 통과 도메인만 발송 허용."""

    REVERIFY_SECONDS = 24 * 3600  # 고객이 DNS 를 바꿀 수 있으므로 매일 재검증

    def __init__(self, store: Store, resolver: Resolver | None = None, clock=time.time):
        self._s = store
        self._resolver = resolver
        self._clock = clock
        store.execute("""CREATE TABLE IF NOT EXISTS sender_domains (
            domain TEXT PRIMARY KEY, verified INTEGER NOT NULL, checked_at REAL NOT NULL, detail TEXT NOT NULL)""")

    def verify(self, domain: str, *, sending_ips: list[str], selector: str, dkim_txt: str) -> VerificationResult:
        resolver = self._resolver or DnsPythonResolver()
        domain = domain.lower()
        findings: list[Finding] = []
        try:
            spf_issues = check_spf(resolver, domain)
            findings += spf_issues
            if not any(f.code in ("SPF_MISSING", "SPF_MULTIPLE") for f in spf_issues):
                for ip in sending_ips:
                    if not spf_authorizes(resolver, domain, ip):
                        findings.append(Finding("SPF_NOT_AUTHORIZED", Severity.ERROR,
                                                f"{domain} 의 SPF 에 발송 IP {ip} 가 포함되어 있지 않습니다."))
            published = [t for t in resolver.txt(f"{selector}._domainkey.{domain}") if "p=" in t]
            want = _tag_list(dkim_txt).get("p", "").replace(" ", "")
            if not published:
                findings.append(Finding("DKIM_MISSING", Severity.ERROR,
                                        f"{selector}._domainkey.{domain} 에 DKIM 공개키가 등록되지 않았습니다."))
            elif _tag_list(published[0]).get("p", "").replace(" ", "") != want:
                findings.append(Finding("DKIM_KEY_MISMATCH", Severity.ERROR,
                                        "등록된 DKIM 공개키가 발송 서버의 개인키와 맞지 않습니다."))
            findings += check_dmarc(resolver, domain)
        except DnsLookupError as e:
            findings.append(Finding("DNS_LOOKUP_FAILED", Severity.ERROR, f"DNS 조회 실패({e}) — 잠시 후 다시 검증하세요."))
        ok = not has_errors(findings)
        detail = "; ".join(f.code for f in findings if f.severity is Severity.ERROR)
        self._s.execute("INSERT OR REPLACE INTO sender_domains VALUES (?, ?, ?, ?)",
                        (domain, int(ok), self._clock(), detail))
        return VerificationResult(domain, ok, findings)

    def status(self, domain: str) -> tuple[bool, str]:
        """(발송 가능 여부, 사유)."""
        rows = self._s.execute("SELECT verified, checked_at, detail FROM sender_domains WHERE domain = ?",
                               (domain.lower(),))
        if not rows:
            return False, "발신 도메인 검증 이력이 없습니다 (SPF/DKIM/DMARC 등록 후 verify 실행)"
        verified, checked_at, detail = rows[0]
        if not verified:
            return False, f"발신 도메인 검증 실패: {detail}"
        if self._clock() - checked_at > self.REVERIFY_SECONDS * 2:
            return False, "발신 도메인 검증이 만료되었습니다 (재검증 필요)"
        return True, ""

    def mark_verified(self, domain: str) -> None:
        """테스트/수동 승인용."""
        self._s.execute("INSERT OR REPLACE INTO sender_domains VALUES (?, 1, ?, '')", (domain.lower(), self._clock()))
