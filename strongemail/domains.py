"""Domain helpers: organizational domain (DMARC alignment) and mailbox provider lookup."""

from __future__ import annotations

# Multi-label public suffixes we care about. A production system should use the
# full Public Suffix List (e.g. the `publicsuffix2` package); this covers the
# common Korean and global cases without an extra dependency.
_MULTI_LABEL_SUFFIXES = {
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr", "pe.kr", "ms.kr",
    "hs.kr", "es.kr", "sc.kr", "kg.kr", "mil.kr",
    "seoul.kr", "busan.kr", "incheon.kr", "daegu.kr", "gwangju.kr", "daejeon.kr",
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "ne.jp", "or.jp",
    "com.cn", "com.tw", "com.hk", "com.sg", "co.nz", "com.br",
}


def domain_of(address: str) -> str:
    """Return the lower-cased domain part of an e-mail address."""
    _, _, domain = address.rstrip(">").rpartition("@")
    return domain.strip().lower().rstrip(".")


def organizational_domain(domain: str) -> str:
    """Approximate the DMARC organizational domain (RFC 7489 §3.2)."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def aligned(domain_a: str, domain_b: str, strict: bool = False) -> bool:
    """DMARC identifier alignment between two domains."""
    a, b = domain_a.lower().rstrip("."), domain_b.lower().rstrip(".")
    if strict:
        return a == b
    return organizational_domain(a) == organizational_domain(b)
