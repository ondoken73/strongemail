import base64

from strongemail.dns_audit import audit_domain, check_dkim, check_dmarc, check_ptr, check_spf


class FakeResolver:
    def __init__(self, txt=None, mx=None, addresses=None, ptr=None):
        self._txt, self._mx = txt or {}, mx or {}
        self._addr, self._ptr = addresses or {}, ptr or {}

    def txt(self, name):
        return self._txt.get(name, [])

    def mx(self, name):
        return self._mx.get(name, [])

    def addresses(self, name):
        return self._addr.get(name, [])

    def ptr(self, ip):
        return self._ptr.get(ip, [])


def codes(findings):
    return {f.code for f in findings}


def test_spf_missing_and_multiple():
    assert codes(check_spf(FakeResolver(), "ex.co.kr")) == {"SPF_MISSING"}
    r = FakeResolver(txt={"ex.co.kr": ["v=spf1 -all", "v=spf1 ~all"]})
    assert codes(check_spf(r, "ex.co.kr")) == {"SPF_MULTIPLE"}


def test_spf_plus_all_and_lookup_limit():
    assert "SPF_PASS_ALL" in codes(check_spf(FakeResolver(txt={"a.com": ["v=spf1 +all"]}), "a.com"))
    includes = " ".join(f"include:i{i}.com" for i in range(11))
    r = FakeResolver(txt={"a.com": [f"v=spf1 {includes} -all"]})
    assert "SPF_TOO_MANY_LOOKUPS" in codes(check_spf(r, "a.com"))


def test_spf_good():
    r = FakeResolver(txt={"a.com": ["v=spf1 ip4:1.2.3.4 include:_spf.relay.com -all"],
                          "_spf.relay.com": ["v=spf1 ip4:5.6.7.0/24 -all"]})
    assert check_spf(r, "a.com") == []


def test_dkim(dkim_key):
    _, pub = dkim_key
    p = base64.b64encode(pub).decode()
    r = FakeResolver(txt={"s1._domainkey.a.com": [f"v=DKIM1; k=rsa; p={p}"],
                          "old._domainkey.a.com": ["v=DKIM1; p="]})
    assert check_dkim(r, "a.com", ["s1"]) == []
    assert codes(check_dkim(r, "a.com", ["old"])) == {"DKIM_REVOKED"}
    assert codes(check_dkim(r, "a.com", ["nope"])) == {"DKIM_MISSING"}


def test_dmarc_falls_back_to_org_domain():
    r = FakeResolver(txt={"_dmarc.ex.co.kr": ["v=DMARC1; p=reject; rua=mailto:d@ex.co.kr"]})
    assert check_dmarc(r, "news.ex.co.kr") == []
    assert codes(check_dmarc(FakeResolver(), "ex.co.kr")) == {"DMARC_MISSING"}
    r = FakeResolver(txt={"_dmarc.a.com": ["v=DMARC1; p=none"]})
    assert codes(check_dmarc(r, "a.com")) == {"DMARC_POLICY_NONE", "DMARC_NO_RUA"}


def test_ptr():
    r = FakeResolver(ptr={"1.2.3.4": ["mail.a.com"]}, addresses={"mail.a.com": ["1.2.3.4"]})
    assert check_ptr(r, "1.2.3.4") == []
    assert codes(check_ptr(FakeResolver(), "1.2.3.4")) == {"PTR_MISSING"}
    r = FakeResolver(ptr={"1.2.3.4": ["1-2-3-4.dynamic.isp.net"]})
    assert codes(check_ptr(r, "1.2.3.4")) == {"FCRDNS_MISMATCH", "PTR_GENERIC"}


def test_full_audit_runs():
    findings = audit_domain("a.com", selectors=[], sending_ips=["1.2.3.4"], resolver=FakeResolver())
    assert {"SPF_MISSING", "DMARC_MISSING", "PTR_MISSING", "MX_MISSING"} <= codes(findings)


def test_lookup_failure_is_not_reported_as_missing():
    from strongemail.dns_audit import DnsLookupError

    class Broken(FakeResolver):
        def txt(self, name):
            raise DnsLookupError(name)

    found = codes(audit_domain("a.com", resolver=Broken()))
    assert "DNS_LOOKUP_FAILED" in found and "SPF_MISSING" not in found
