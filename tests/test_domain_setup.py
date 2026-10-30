from strongemail.domain_setup import (DMARC_ROLLOUT, SenderDomainRegistry, dkim_txt_from_private_key, dmarc_record,
                                      generate_dkim_key, setup_plan, spf_authorizes, spf_record)
from strongemail.reputation import Store
from test_dns_audit import FakeResolver


def test_spf_record_new_and_merge():
    assert spf_record(["203.0.113.10"]) == "v=spf1 ip4:203.0.113.10 ~all"
    merged = spf_record(["203.0.113.10"], existing="v=spf1 include:_spf.google.com -all")
    assert merged == "v=spf1 include:_spf.google.com ip4:203.0.113.10 -all"
    # 위험한 +all 은 교체
    assert spf_record(["1.2.3.4"], existing="v=spf1 +all").endswith(" ~all")
    assert "ip6:2001:db8::1" in spf_record(["2001:db8::1"])


def test_dmarc_record_stages():
    assert dmarc_record("d@a.com") == "v=DMARC1; p=none; rua=mailto:d@a.com"
    assert dmarc_record("d@a.com", DMARC_ROLLOUT[1]) == "v=DMARC1; p=quarantine; pct=25; rua=mailto:d@a.com"
    assert DMARC_ROLLOUT[-1].policy == "reject"


def test_dkim_key_roundtrip():
    pem, txt = generate_dkim_key()
    assert txt.startswith("v=DKIM1; k=rsa; p=") and dkim_txt_from_private_key(pem) == txt


def test_spf_authorizes():
    r = FakeResolver(txt={"a.com": ["v=spf1 include:relay.com a:out.a.com -all"],
                          "relay.com": ["v=spf1 ip4:198.51.100.0/24 -all"]},
                     addresses={"out.a.com": ["192.0.2.5"]})
    assert spf_authorizes(r, "a.com", "198.51.100.7")
    assert spf_authorizes(r, "a.com", "192.0.2.5")
    assert not spf_authorizes(r, "a.com", "203.0.113.1")


def test_setup_plan_merges_existing_spf():
    r = FakeResolver(txt={"shop.co.kr": ["v=spf1 include:_spf.google.com ~all"]})
    plan = setup_plan("shop.co.kr", ips=["203.0.113.10"], selector="se1", dkim_txt="v=DKIM1; p=AAA", resolver=r)
    spf = plan[0]
    assert spf.value == "v=spf1 include:_spf.google.com ip4:203.0.113.10 ~all" and "교체" in spf.note
    names = {(x.name, x.type) for x in plan}
    assert ("se1._domainkey.shop.co.kr", "TXT") in names and ("_dmarc.shop.co.kr", "TXT") in names
    assert ("203.0.113.10", "PTR") in names


def test_sender_domain_verification():
    pem, txt = generate_dkim_key()
    good = FakeResolver(txt={"shop.co.kr": ["v=spf1 ip4:203.0.113.10 -all"],
                             "se1._domainkey.shop.co.kr": [txt],
                             "_dmarc.shop.co.kr": ["v=DMARC1; p=none; rua=mailto:d@shop.co.kr"]})
    reg = SenderDomainRegistry(Store(), resolver=good)
    assert reg.status("shop.co.kr")[0] is False
    res = reg.verify("shop.co.kr", sending_ips=["203.0.113.10"], selector="se1", dkim_txt=txt)
    assert res.verified and reg.status("shop.co.kr") == (True, "")

    _, other = generate_dkim_key()
    bad = FakeResolver(txt={"shop.co.kr": ["v=spf1 include:_spf.google.com -all"],
                            "se1._domainkey.shop.co.kr": [other]})
    reg = SenderDomainRegistry(Store(), resolver=bad)
    codes = {f.code for f in reg.verify("shop.co.kr", sending_ips=["203.0.113.10"], selector="se1",
                                        dkim_txt=txt).findings}
    assert {"SPF_NOT_AUTHORIZED", "DKIM_KEY_MISMATCH", "DMARC_MISSING"} <= codes
    assert reg.status("shop.co.kr")[0] is False
