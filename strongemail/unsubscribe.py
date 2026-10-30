"""RFC 8058 one-click unsubscribe: signed tokens and a minimal WSGI endpoint.

Gmail/Yahoo POST `List-Unsubscribe=One-Click` to the URL in the List-Unsubscribe
header without any user interaction; the request must be honoured (within 2 days)
and must not require login or confirmation. Recipients clicking the link in the
body get a GET, which shows a page with a single confirm button.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from html import escape
from typing import Callable
from urllib.parse import parse_qs, quote


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class UnsubscribeTokens:
    def __init__(self, secret: bytes):
        if len(secret) < 16:
            raise ValueError("unsubscribe secret must be at least 16 bytes")
        self._secret = secret

    def make(self, address: str, list_id: str = "default") -> str:
        payload = f"{address.lower()}\n{list_id}".encode()
        sig = hmac.new(self._secret, payload, hashlib.sha256).digest()[:16]
        return f"{_b64(payload)}.{_b64(sig)}"

    def verify(self, token: str) -> tuple[str, str] | None:
        try:
            p, s = token.split(".", 1)
            payload, sig = _unb64(p), _unb64(s)
        except (ValueError, TypeError):
            return None
        expected = hmac.new(self._secret, payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(sig, expected):
            return None
        address, _, list_id = payload.decode().partition("\n")
        return address, list_id

    def url(self, base_url: str, address: str, list_id: str = "default") -> str:
        return f"{base_url.rstrip('/')}/unsubscribe?t={quote(self.make(address, list_id))}"


def make_wsgi_app(tokens: UnsubscribeTokens, on_unsubscribe: Callable[[str, str], None]):
    """WSGI app serving GET/POST /unsubscribe?t=<token>."""

    def app(environ, start_response):
        def reply(status: str, body: str):
            start_response(status, [("Content-Type", "text/html; charset=utf-8")])
            return [body.encode()]

        if environ.get("PATH_INFO") != "/unsubscribe":
            return reply("404 Not Found", "not found")
        token = parse_qs(environ.get("QUERY_STRING", "")).get("t", [""])[0]
        parsed = tokens.verify(token)
        if parsed is None:
            return reply("400 Bad Request", "잘못된 수신거부 링크입니다.")
        method = environ.get("REQUEST_METHOD", "GET")
        if method == "POST":
            on_unsubscribe(*parsed)
            return reply("200 OK", "<p>수신거부 처리되었습니다. 더 이상 광고 메일을 보내지 않습니다.</p>")
        if method == "GET":
            # Don't unsubscribe on GET: link scanners/prefetchers would trigger it.
            t = escape(token, quote=True)
            return reply("200 OK", f"""<!doctype html><meta charset="utf-8">
<p>{escape(parsed[0])} 주소의 광고 메일 수신을 거부하시겠습니까?</p>
<form method="post" action="?t={t}"><button type="submit">수신거부</button></form>""")
        return reply("405 Method Not Allowed", "method not allowed")

    return app
