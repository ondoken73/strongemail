"""Per-message compliance lint.

Two rule sets:
  * Portal / RFC rules  — what Gmail, Yahoo, MS, Naver, Daum check on every message.
  * 정보통신망법 제50조 / 시행령 제61조 — Korean law for commercial (광고성) e-mail.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import getaddresses

from .domains import aligned, domain_of
from .findings import Finding, Severity

REQUIRED_HEADERS = ("From", "To", "Subject", "Date", "Message-ID")
GMAIL_CLIP_BYTES = 102 * 1024
URL_SHORTENERS = ("bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "han.gl", "me2.do", "vo.la", "url.kr", "is.gd")
OPT_OUT_PATTERN = re.compile(r"수신\s*거부|수신을?\s*원하지\s*않|unsubscribe|구독\s*해지|수신\s*해지", re.I)
AD_PREFIX = "(광고)"


@dataclass(frozen=True)
class SenderIdentity:
    """정보통신망법: 광고 메일 본문에 전송자 명칭과 연락처를 밝혀야 함."""
    name: str
    contact: str  # 전화번호, 이메일 또는 주소


def _parts(msg: EmailMessage) -> tuple[str, str]:
    text, html = "", ""
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text += part.get_content()
        elif ctype == "text/html":
            html += part.get_content()
    return text, html


def _visible_text(html: str) -> str:
    html = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def lint_message(msg: EmailMessage, *, marketing: bool, dkim_domain: str | None = None,
                 return_path: str | None = None, sender: SenderIdentity | None = None) -> list[Finding]:
    findings: list[Finding] = []
    F = findings.append

    # --- RFC 5322 basics -----------------------------------------------------
    for h in REQUIRED_HEADERS:
        if not msg.get(h):
            F(Finding("HEADER_MISSING", Severity.ERROR, f"{h} 헤더가 없습니다."))
    from_addrs = getaddresses(msg.get_all("From", []))
    if len(from_addrs) != 1 or "@" not in from_addrs[0][1]:
        F(Finding("FROM_INVALID", Severity.ERROR, "From 에는 정확히 하나의 올바른 주소가 있어야 합니다."))
        return findings
    from_domain = domain_of(from_addrs[0][1])
    if from_domain in {"gmail.com", "naver.com", "daum.net", "hanmail.net", "yahoo.com", "outlook.com", "kakao.com"}:
        F(Finding("FROM_FREEMAIL", Severity.ERROR,
                  f"From 이 무료메일({from_domain})입니다. 해당 포털의 DMARC 정책으로 거부됩니다. 자체 도메인을 쓰세요."))

    # --- Authentication alignment (DMARC) -----------------------------------
    if dkim_domain is None:
        F(Finding("DKIM_UNSIGNED", Severity.ERROR, "DKIM 서명 없이 발송하려고 합니다."))
    elif not aligned(from_domain, dkim_domain):
        F(Finding("DKIM_NOT_ALIGNED", Severity.ERROR,
                  f"DKIM d={dkim_domain} 가 From 도메인 {from_domain} 과 정렬되지 않아 DMARC 실패합니다."))
    if return_path and not aligned(from_domain, domain_of(return_path)):
        F(Finding("SPF_NOT_ALIGNED", Severity.WARN,
                  f"Return-Path {domain_of(return_path)} 가 From 과 정렬되지 않습니다. DKIM 정렬만으로 DMARC 는 "
                  f"통과하지만, bounce.{from_domain} 같은 하위 도메인을 쓰면 둘 다 통과합니다."))

    # --- Bulk-sender unsubscribe (Gmail/Yahoo 2024, RFC 8058) ---------------
    lu = msg.get("List-Unsubscribe", "")
    lup = msg.get("List-Unsubscribe-Post", "")
    if marketing:
        if not lu:
            F(Finding("LIST_UNSUB_MISSING", Severity.ERROR, "광고/대량 메일에 List-Unsubscribe 헤더가 없습니다."))
        else:
            if "<https://" not in lu:
                F(Finding("LIST_UNSUB_NO_HTTPS", Severity.ERROR,
                          "원클릭 수신거부에는 List-Unsubscribe 에 https URL 이 있어야 합니다."))
            if lup.replace(" ", "").lower() != "list-unsubscribe=one-click":
                F(Finding("LIST_UNSUB_NO_ONE_CLICK", Severity.ERROR,
                          "List-Unsubscribe-Post: List-Unsubscribe=One-Click 헤더가 없습니다 (RFC 8058)."))

    # --- Content --------------------------------------------------------------
    subject = str(msg.get("Subject", ""))
    text, html = _parts(msg)
    visible = text or _visible_text(html)
    if html and not text:
        F(Finding("NO_TEXT_PART", Severity.WARN, "text/plain 대체 본문이 없습니다. multipart/alternative 권장."))
    if html and len(html.encode()) > GMAIL_CLIP_BYTES:
        F(Finding("HTML_TOO_LARGE", Severity.WARN,
                  f"HTML {len(html.encode()) // 1024}KB — 102KB 초과 시 Gmail 이 본문을 자르고 수신거부 링크가 가려집니다."))
    if html and re.search(r"<img\b", html, re.I) and len(_visible_text(html)) < 200:
        F(Finding("IMAGE_ONLY", Severity.WARN, "이미지 위주 메일(텍스트 200자 미만)은 스팸 필터 점수가 높습니다."))
    body = f"{text}\n{html}"
    for short in URL_SHORTENERS:
        if re.search(rf"https?://(www\.)?{re.escape(short)}/", body, re.I):
            F(Finding("URL_SHORTENER", Severity.WARN,
                      f"단축 URL({short})은 스팸 발송에 많이 쓰여 차단 목록에 자주 오릅니다. 자체 도메인 링크를 쓰세요."))
            break
    letters = re.sub(r"[^A-Za-z]", "", subject)
    if len(letters) >= 10 and letters.isupper():
        F(Finding("SUBJECT_ALL_CAPS", Severity.WARN, "제목이 모두 대문자입니다."))
    if subject.count("!") >= 3 or re.search(r"[!?]{3,}", subject):
        F(Finding("SUBJECT_PUNCTUATION", Severity.WARN, "제목의 과도한 느낌표/물음표는 스팸 점수를 높입니다."))

    # --- 정보통신망법 (광고성 정보) ------------------------------------------
    if marketing:
        if not subject.lstrip().startswith(AD_PREFIX):
            F(Finding("KR_AD_PREFIX", Severity.ERROR,
                      f"광고성 메일 제목은 '{AD_PREFIX}' 로 시작해야 합니다 (시행령 제61조, 과태료 대상)."))
        if not OPT_OUT_PATTERN.search(visible):
            F(Finding("KR_OPT_OUT_MISSING", Severity.ERROR,
                      "본문에 수신거부 방법 안내가 없습니다. 무료로 수신거부할 수 있는 링크/방법을 명시해야 합니다."))
        if sender is None:
            F(Finding("KR_SENDER_UNKNOWN", Severity.WARN,
                      "전송자 정보(명칭·연락처)가 설정되지 않아 본문 표기를 확인하지 못했습니다."))
        else:
            if sender.name not in visible:
                F(Finding("KR_SENDER_NAME", Severity.ERROR, f"본문에 전송자 명칭 '{sender.name}' 이 없습니다."))
            if sender.contact not in visible:
                F(Finding("KR_SENDER_CONTACT", Severity.ERROR, f"본문에 전송자 연락처 '{sender.contact}' 가 없습니다."))
    elif subject.lstrip().startswith(AD_PREFIX):
        F(Finding("AD_MARKED_TRANSACTIONAL", Severity.WARN,
              "제목에 (광고)가 있는데 거래성 메일로 분류되었습니다. 광고라면 marketing 으로 발송해 수신동의를 검사하세요."))
    return findings
