"""Command line: `python -m strongemail audit|lint|providers`."""

from __future__ import annotations

import argparse
import sys
from email import policy
from email.parser import BytesParser

from .compliance import SenderIdentity, lint_message
from .dns_audit import audit_domain
from .findings import Finding, Severity, has_errors
from .providers import PROVIDERS


def _print(findings: list[Finding]) -> int:
    order = {Severity.ERROR: 0, Severity.WARN: 1, Severity.INFO: 2}
    for f in sorted(findings, key=lambda f: order[f.severity]):
        print(f)
    errors = sum(f.severity is Severity.ERROR for f in findings)
    warns = sum(f.severity is Severity.WARN for f in findings)
    print(f"\n오류 {errors}건, 경고 {warns}건" + (" — 발송 전에 오류를 해결하세요." if errors else " — 통과"))
    return 1 if has_errors(findings) else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="strongemail")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="발송 도메인/IP DNS 점검 (SPF, DKIM, DMARC, PTR ...)")
    a.add_argument("domain")
    a.add_argument("--selector", action="append", default=[], help="DKIM selector (여러 번 지정 가능)")
    a.add_argument("--ip", action="append", default=[], help="발송 IP (PTR/FCrDNS 확인)")

    l = sub.add_parser("lint", help=".eml 파일 규정 점검")
    l.add_argument("eml")
    l.add_argument("--marketing", action="store_true", help="광고성 메일로 검사")
    l.add_argument("--dkim-domain")
    l.add_argument("--sender-name")
    l.add_argument("--sender-contact")

    sub.add_parser("providers", help="포털별 기준 요약")

    args = ap.parse_args(argv)
    if args.cmd == "audit":
        return _print(audit_domain(args.domain, selectors=args.selector, sending_ips=args.ip))
    if args.cmd == "lint":
        with open(args.eml, "rb") as fh:
            msg = BytesParser(policy=policy.default).parse(fh)
        dkim_domain = args.dkim_domain
        if dkim_domain is None and (sig := msg.get("DKIM-Signature")):
            tags = dict(p.strip().split("=", 1) for p in str(sig).split(";") if "=" in p)
            dkim_domain = tags.get("d")
        sender = SenderIdentity(args.sender_name, args.sender_contact) if args.sender_name and args.sender_contact else None
        return _print(lint_message(msg, marketing=args.marketing, dkim_domain=dkim_domain,
                                   return_path=msg.get("Return-Path"), sender=sender))
    if args.cmd == "providers":
        for p in PROVIDERS.values():
            print(f"■ {p.name}  ({', '.join(sorted(p.domains))})  시작 속도 {p.max_per_minute}/분")
            for n in p.notes:
                print(f"   - {n}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
