from io import BytesIO

from strongemail.providers import PROVIDERS, provider_for
from strongemail.throttle import ProviderThrottle
from strongemail.unsubscribe import UnsubscribeTokens, make_wsgi_app


def test_provider_lookup():
    assert provider_for("a@Naver.com").key == "naver"
    assert provider_for("a@hanmail.net").key == "kakao"
    assert provider_for("a@corp.co.kr").key == "other"


def test_throttle_rate_and_backoff():
    now = [0.0]
    t = ProviderThrottle(clock=lambda: now[0])
    nate = PROVIDERS["nate"]  # 100/min
    allowed = sum(t.acquire(nate) == 0 for _ in range(10))
    assert allowed < 10
    now[0] += 60
    assert t.acquire(nate) == 0
    t.report_throttled(nate, pause_seconds=30)
    assert 29 < t.acquire(nate) <= 30


def test_tokens_roundtrip_and_tamper():
    tok = UnsubscribeTokens(b"x" * 32)
    token = tok.make("A@naver.com", "news")
    assert tok.verify(token) == ("a@naver.com", "news")
    assert tok.verify(token[:-2] + "AA") is None
    assert tok.verify("garbage") is None


def test_wsgi_one_click():
    tok = UnsubscribeTokens(b"x" * 32)
    seen = []
    app = make_wsgi_app(tok, lambda a, l: seen.append((a, l)))

    def call(method, token):
        status = []
        body = app({"PATH_INFO": "/unsubscribe", "QUERY_STRING": f"t={token}", "REQUEST_METHOD": method,
                    "wsgi.input": BytesIO(b"List-Unsubscribe=One-Click")}, lambda s, h: status.append(s))
        return status[0], b"".join(body).decode()

    assert call("GET", tok.make("a@gmail.com"))[0].startswith("200") and seen == []
    assert call("POST", tok.make("a@gmail.com"))[0].startswith("200")
    assert seen == [("a@gmail.com", "default")]
    assert call("POST", "bad")[0].startswith("400")
