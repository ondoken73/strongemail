"""Sending-domain DNS audit: SPF, DKIM, DMARC, MX, PTR/FCrDNS, MTA-STS, TLS-RPT, BIMI.

These are the records every major portal checks before it even looks at content.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from typing import Protocol

from .domains import organizational_domain
from .findings import Finding, Severity

SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4


class DnsLookupError(Exception):
    """The resolver could not get an answer (timeout, SERVFAIL) - not the same as 'no record'."""


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...
    def mx(self, name: str) -> list[str]: ...
    def addresses(self, name: str) -> list[str]: ...
    def ptr(self, ip: str) -> list[str]: ...


class DnsPythonResolver:
    """Resolver backed by dnspython. Missing records yield empty lists."""

    def __init__(self, timeout: float = 5.0):
        import dns.resolver

        self._dns = dns
        self._r = dns.resolver.Resolver()
        self._r.lifetime = timeout

    def _query(self, name: str, rtype: str):
        try:
            return list(self._r.resolve(name, rtype))
        except (self._dns.resolver.NXDOMAIN, self._dns.resolver.NoAnswer):
            return []
        except (self._dns.resolver.NoNameservers, self._dns.exception.Timeout) as e:
            raise DnsLookupError(f"{name} {rtype}: {e.__class__.__name__}") from e

    def txt(self, name: str) -> list[str]:
        return [b"".join(r.strings).decode("utf-8", "replace") for r in self._query(name, "TXT")]

    def mx(self, name: str) -> list[str]:
        return [str(r.exchange).rstrip(".") for r in self._query(name, "MX")]

    def addresses(self, name: str) -> list[str]:
        return [r.address for t in ("A", "AAAA") for r in self._query(name, t)]

    def ptr(self, ip: str) -> list[str]:
        import dns.reversename

        return [str(r).rstrip(".") for r in self._query(str(dns.reversename.from_address(ip)), "PTR")]


def _tag_list(record: str) -> dict[str, str]:
    tags = {}
    for part in record.split(";"):
        key, sep, value = part.strip().partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip()
    return tags


# --------------------------------------------------------------------------- SPF

def _spf_records(resolver: Resolver, domain: str) -> list[str]:
    return [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]


def _spf_lookups(resolver: Resolver, domain: str, seen: set[str]) -> int:
    """Count DNS-querying mechanisms, following include/redirect recursively."""
    if domain in seen:
        return 0
    seen.add(domain)
    records = _spf_records(resolver, domain)
    if len(records) != 1:
        return 0
    count = 0
    for term in records[0].split()[1:]:
        term = term.lstrip("+-~?").lower()
        name, _, arg = term.replace("=", ":", 1).partition(":")
        if name in ("include", "redirect"):
            count += 1 + _spf_lookups(resolver, arg, seen)
        elif name in ("a", "mx", "ptr", "exists"):
            count += 1
    return count


def check_spf(resolver: Resolver, domain: str) -> list[Finding]:
    records = _spf_records(resolver, domain)
    if not records:
        return [Finding("SPF_MISSING", Severity.ERROR,
                        f"{domain} 에 SPF 레코드가 없습니다. 네이버·다음·Gmail 모두 미인증 메일로 분류합니다. "
                        f"예: \"v=spf1 ip4:<발송IP> include:<릴레이> -all\"")]
    if len(records) > 1:
        return [Finding("SPF_MULTIPLE", Severity.ERROR,
                        f"SPF 레코드가 {len(records)}개입니다. 하나로 합치지 않으면 permerror 로 인증 실패합니다.")]
    findings = []
    record = records[0]
    terms = record.lower().split()
    all_terms = [t for t in terms if t.lstrip("+-~?") == "all"]
    if not all_terms and not any(t.startswith("redirect=") for t in terms):
        findings.append(Finding("SPF_NO_ALL", Severity.WARN, "SPF 끝에 '~all' 또는 '-all' 이 없습니다."))
    elif all_terms and all_terms[-1] in ("all", "+all"):
        findings.append(Finding("SPF_PASS_ALL", Severity.ERROR,
                                "'+all' 은 누구나 이 도메인으로 발송할 수 있게 허용합니다. 즉시 '-all' 로 바꾸세요."))
    elif all_terms and all_terms[-1] == "?all":
        findings.append(Finding("SPF_NEUTRAL", Severity.WARN, "'?all' 은 보호 효과가 없습니다. '~all' 또는 '-all' 권장."))
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        findings.append(Finding("SPF_PTR", Severity.WARN, "'ptr' 메커니즘은 폐기 권고(RFC 7208)되었습니다."))
    lookups = _spf_lookups(resolver, domain, set())
    if lookups > SPF_LOOKUP_LIMIT:
        findings.append(Finding("SPF_TOO_MANY_LOOKUPS", Severity.ERROR,
                                f"SPF DNS 조회 횟수 {lookups}회 > {SPF_LOOKUP_LIMIT}회. permerror 로 인증 실패합니다. "
                                f"include 를 줄이거나 ip4/ip6 로 펼치세요."))
    elif lookups >= SPF_LOOKUP_LIMIT - 2:
        findings.append(Finding("SPF_LOOKUPS_NEAR_LIMIT", Severity.WARN,
                                f"SPF DNS 조회 {lookups}회 — 한도(10) 근접."))
    return findings


# -------------------------------------------------------------------------- DKIM

def _rsa_key_bits(p_value: str) -> int | None:
    try:
        der = base64.b64decode(p_value)
    except ValueError:
        return None
    try:
        from dkim.crypto import parse_public_key

        return parse_public_key(der)["modulus"].bit_length()
    except Exception:
        return None


def check_dkim(resolver: Resolver, domain: str, selectors: list[str]) -> list[Finding]:
    if not selectors:
        return [Finding("DKIM_NO_SELECTOR", Severity.INFO,
                        "DKIM selector 를 지정하지 않아 확인을 건너뜁니다 (--selector).")]
    findings = []
    for selector in selectors:
        name = f"{selector}._domainkey.{domain}"
        records = [t for t in resolver.txt(name) if "p=" in t]
        if not records:
            findings.append(Finding("DKIM_MISSING", Severity.ERROR,
                                    f"{name} 에 DKIM 공개키가 없습니다. Gmail·Yahoo·MS 대량 발송 필수 요건입니다."))
            continue
        tags = _tag_list(records[0])
        p = tags.get("p", "")
        if not p:
            findings.append(Finding("DKIM_REVOKED", Severity.ERROR, f"{name} 의 키가 폐기(p= 비어있음) 상태입니다."))
            continue
        if tags.get("k", "rsa") == "rsa":
            bits = _rsa_key_bits(p)
            if bits is not None and bits < 1024:
                findings.append(Finding("DKIM_WEAK_KEY", Severity.ERROR,
                                        f"{name} RSA 키 {bits}비트 — 1024비트 미만은 무시됩니다."))
            elif bits is not None and bits < 2048:
                findings.append(Finding("DKIM_KEY_1024", Severity.WARN,
                                        f"{name} RSA 키 {bits}비트 — 2048비트 권장."))
        if tags.get("t", "").lower().startswith("y"):
            findings.append(Finding("DKIM_TEST_MODE", Severity.WARN, f"{name} 가 테스트 모드(t=y)입니다."))
    return findings


# ------------------------------------------------------------------------- DMARC

def check_dmarc(resolver: Resolver, domain: str) -> list[Finding]:
    records = [t for t in resolver.txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
    org = organizational_domain(domain)
    if not records and org != domain:
        records = [t for t in resolver.txt(f"_dmarc.{org}") if t.lower().startswith("v=dmarc1")]
    if not records:
        return [Finding("DMARC_MISSING", Severity.ERROR,
                        f"DMARC 레코드가 없습니다. 대량 발송 필수 요건입니다. 시작값: "
                        f"_dmarc.{org} TXT \"v=DMARC1; p=none; rua=mailto:dmarc@{org}\"")]
    if len(records) > 1:
        return [Finding("DMARC_MULTIPLE", Severity.ERROR, "DMARC 레코드가 여러 개라 무시됩니다.")]
    tags = _tag_list(records[0])
    findings = []
    policy = tags.get("p", "").lower()
    if policy not in ("none", "quarantine", "reject"):
        findings.append(Finding("DMARC_BAD_POLICY", Severity.ERROR, f"p= 값이 올바르지 않습니다: '{policy}'"))
    elif policy == "none":
        findings.append(Finding("DMARC_POLICY_NONE", Severity.WARN,
                                "p=none 은 최소 요건만 충족합니다. rua 리포트로 정렬을 확인한 뒤 "
                                "quarantine → reject 로 단계 상향하세요."))
    if "rua" not in tags:
        findings.append(Finding("DMARC_NO_RUA", Severity.WARN,
                                "rua(집계 리포트 수신 주소)가 없어 인증 실패를 관측할 수 없습니다."))
    pct = tags.get("pct")
    if pct and pct != "100":
        findings.append(Finding("DMARC_PARTIAL", Severity.INFO, f"pct={pct} — 정책이 일부 메일에만 적용됩니다."))
    return findings


# ------------------------------------------------------------------ MX / PTR

def check_mx(resolver: Resolver, domain: str) -> list[Finding]:
    if resolver.mx(domain):
        return []
    return [Finding("MX_MISSING", Severity.WARN,
                    f"{domain} 에 MX 가 없습니다. 답장·반송을 받을 수 없고 일부 포털은 발신 도메인 신뢰도를 낮춥니다.")]


_GENERIC_PTR = re.compile(r"(\d{1,3}[-.]){3}\d{1,3}|dynamic|dhcp|dsl|cable|pool|static|broadband", re.I)


def check_ptr(resolver: Resolver, ip: str) -> list[Finding]:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return [Finding("PTR_BAD_IP", Severity.ERROR, f"올바른 IP 가 아닙니다: {ip}")]
    names = resolver.ptr(ip)
    if not names:
        return [Finding("PTR_MISSING", Severity.ERROR,
                        f"{ip} 에 PTR(역방향 DNS)이 없습니다. Gmail·다음 등은 PTR 없는 IP를 거부합니다. "
                        f"IP 제공자(IDC/클라우드)에 PTR 등록을 요청하세요.")]
    findings = []
    if not any(ip in resolver.addresses(n) for n in names):
        findings.append(Finding("FCRDNS_MISMATCH", Severity.ERROR,
                                f"PTR {names[0]} 의 정방향 조회 결과에 {ip} 가 없습니다 (FCrDNS 불일치)."))
    if _GENERIC_PTR.search(names[0]):
        findings.append(Finding("PTR_GENERIC", Severity.WARN,
                                f"PTR '{names[0]}' 이 가정용/동적 IP 처럼 보입니다. mail.<도메인> 형태로 바꾸세요."))
    return findings


def check_transport_security(resolver: Resolver, domain: str) -> list[Finding]:
    findings = []
    if not any(t.lower().startswith("v=stsv1") for t in resolver.txt(f"_mta-sts.{domain}")):
        findings.append(Finding("MTA_STS_MISSING", Severity.INFO, "MTA-STS 미설정 (수신 TLS 강제, 선택사항)."))
    if not any(t.lower().startswith("v=tlsrptv1") for t in resolver.txt(f"_smtp._tls.{domain}")):
        findings.append(Finding("TLSRPT_MISSING", Severity.INFO, "TLS-RPT 미설정 (TLS 실패 리포트, 선택사항)."))
    if not any(t.lower().startswith("v=bimi1") for t in resolver.txt(f"default._bimi.{domain}")):
        findings.append(Finding("BIMI_MISSING", Severity.INFO,
                                "BIMI 미설정 (DMARC p=quarantine/reject 이후 Gmail·Yahoo·네이버 로고 표시)."))
    return findings


def audit_domain(domain: str, *, selectors: list[str] | None = None, sending_ips: list[str] | None = None,
                 resolver: Resolver | None = None) -> list[Finding]:
    """Run every check for a sending domain (and optionally its sending IPs)."""
    resolver = resolver or DnsPythonResolver()
    domain = domain.lower().rstrip(".")
    checks = [
        lambda: check_spf(resolver, domain),
        lambda: check_dkim(resolver, domain, selectors or []),
        lambda: check_dmarc(resolver, domain),
        lambda: check_mx(resolver, domain),
        *[(lambda ip=ip: check_ptr(resolver, ip)) for ip in sending_ips or []],
        lambda: check_transport_security(resolver, domain),
    ]
    findings = []
    for check in checks:
        try:
            findings += check()
        except DnsLookupError as e:
            findings.append(Finding("DNS_LOOKUP_FAILED", Severity.ERROR,
                                    f"DNS 조회 실패({e}) — 레코드 유무를 판단할 수 없습니다. 네트워크/리졸버를 확인하세요."))
    return findings
