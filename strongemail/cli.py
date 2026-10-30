"""Command line: `python -m strongemail audit|lint|providers`."""

from __future__ import annotations

import argparse
import sys
from email import policy
from email.parser import BytesParser

from .blocklist import APPEAL_CHANNELS, AppealContext, IncidentLog, build_appeal, check_dnsbls
from .compliance import SenderIdentity, lint_message
from .dns_audit import DnsPythonResolver, audit_domain
from .domain_setup import (DMARC_ROLLOUT, SenderDomainRegistry, dkim_txt_from_private_key, dmarc_record,
                           generate_dkim_key, setup_plan)
from .reputation import ReputationMonitor, Store
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

    st = sub.add_parser("setup", help="발신 도메인에 등록할 SPF/DKIM/DMARC 레코드 생성 (DKIM 키 생성 포함)")
    st.add_argument("domain")
    st.add_argument("--ip", action="append", default=[], help="발송 IP")
    st.add_argument("--include", action="append", default=[], help="SPF include (외부 릴레이)")
    st.add_argument("--selector", default="se1")
    st.add_argument("--key", help="기존 DKIM 개인키(PEM). 없으면 새로 만들어 <selector>.<domain>.pem 으로 저장")
    st.add_argument("--rua", help="DMARC 리포트 수신 주소")

    dp = sub.add_parser("dmarc-plan", help="DMARC 단계적 강화 일정")
    dp.add_argument("--rua", required=True)

    v = sub.add_parser("verify", help="발신 도메인 검증 (통과해야 발송 가능)")
    v.add_argument("domain")
    v.add_argument("--ip", action="append", required=True)
    v.add_argument("--selector", required=True)
    v.add_argument("--key", required=True, help="발송 서버의 DKIM 개인키(PEM)")
    v.add_argument("--db", default="strongemail.db")

    b = sub.add_parser("blocklist", help="발송 IP 공용 차단목록(DNSBL) 등재 확인")
    b.add_argument("ip")

    inc = sub.add_parser("incident", help="IP 차단 사고 관리 및 소명서 생성")
    inc.add_argument("--db", default="strongemail.db")
    isub = inc.add_subparsers(dest="action", required=True)
    isub.add_parser("list")
    o = isub.add_parser("open")
    o.add_argument("ip")
    o.add_argument("target", choices=sorted(APPEAL_CHANNELS))
    o.add_argument("evidence", help="수신 서버 거부 응답 원문")
    ac = isub.add_parser("action", help="원인 조치 내역 기록")
    ac.add_argument("id", type=int)
    ac.add_argument("text")
    ap_ = isub.add_parser("appeal", help="준비 상태 점검 + 소명서 출력")
    ap_.add_argument("id", type=int)
    ap_.add_argument("--company", required=True)
    ap_.add_argument("--name", required=True)
    ap_.add_argument("--email", required=True)
    ap_.add_argument("--phone", required=True)
    ap_.add_argument("--domain", required=True)
    ap_.add_argument("--selector", action="append", default=[])
    ap_.add_argument("--mail-type", default="회원 대상 서비스 알림 및 수신동의 회원 대상 뉴스레터")
    ap_.add_argument("--consent", default="회원가입 시 별도 체크박스(기본 해제)로 광고 수신동의, 2년마다 재확인")
    ap_.add_argument("--daily-volume", type=int, default=0)
    ap_.add_argument("--submitted", action="store_true", help="소명서를 제출했다고 기록")
    r = isub.add_parser("resolve", help="해제 확인 → 해당 포털 재웜업 시작")
    r.add_argument("id", type=int)

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
    if args.cmd == "setup":
        if args.key:
            pem = open(args.key, "rb").read()
            dkim_txt = dkim_txt_from_private_key(pem)
        else:
            pem, dkim_txt = generate_dkim_key()
            path = f"{args.selector}.{args.domain}.pem"
            with open(path, "wb") as fh:
                fh.write(pem)
            print(f"DKIM 개인키를 {path} 에 저장했습니다. 발송 서버에만 두고 외부에 공유하지 마세요.\n")
        print("아래 레코드를 DNS 에 등록하세요:\n")
        for rec in setup_plan(args.domain, ips=args.ip, includes=args.include, selector=args.selector,
                              dkim_txt=dkim_txt, rua=args.rua):
            print(rec, "\n")
        print(f"등록 후: strongemail verify {args.domain} --selector {args.selector} --key <pem> "
              + " ".join(f"--ip {i}" for i in args.ip))
        return 0
    if args.cmd == "dmarc-plan":
        day = 0
        for i, stage in enumerate(DMARC_ROLLOUT, 1):
            print(f"{i}단계 (D+{day}): {dmarc_record(args.rua, stage)}\n    목표: {stage.goal}"
                  + (f" — 최소 {stage.min_days}일 유지" if stage.min_days else ""))
            day += stage.min_days
        return 0
    if args.cmd == "verify":
        reg = SenderDomainRegistry(Store(args.db))
        res = reg.verify(args.domain, sending_ips=args.ip, selector=args.selector,
                         dkim_txt=dkim_txt_from_private_key(open(args.key, "rb").read()))
        code = _print(res.findings)
        print("✓ 발신 도메인 검증 통과 — 발송 가능" if res.verified else "✗ 검증 실패 — 발송이 차단됩니다")
        return code
    if args.cmd == "blocklist":
        listed = False
        for res in check_dnsbls(args.ip, DnsPythonResolver()):
            state = {True: "✗ 등재됨", False: "✓ 정상", None: "? 확인 불가"}[res.listed]
            ch = APPEAL_CHANNELS.get(res.list_key)
            print(f"{state:8} {res.list_key:10} {res.note}" + (f"  → 해제: {ch.url}" if res.listed and ch else ""))
            listed |= bool(res.listed)
        return 1 if listed else 0
    if args.cmd == "incident":
        store = Store(args.db)
        log = IncidentLog(store)
        if args.action == "list":
            for i in log.active():
                print(f"#{i.id} {i.ip} → {i.target} [{i.state.value}] 조치 {len(i.actions)}건 / 소명 {i.appeal_count}회\n"
                      f"    {i.evidence}")
            return 0
        if args.action == "open":
            i = log.open(args.ip, args.target, args.evidence)
            print(f"사고 #{i.id} 기록 — {APPEAL_CHANNELS[args.target].name} 발송을 중지합니다.")
            return 0
        if args.action == "action":
            log.add_action(args.id, args.text)
            return 0
        if args.action == "resolve":
            log.resolve(args.id)
            print("해제 처리했습니다. 해당 포털은 오늘부터 웜업 한도로 다시 시작합니다.")
            return 0
        if args.action == "appeal":
            i = log.get(args.id)
            resolver = DnsPythonResolver()
            ctx = AppealContext(
                company=args.company, contact_name=args.name, contact_email=args.email, contact_phone=args.phone,
                sending_domain=args.domain, mail_type=args.mail_type, consent_method=args.consent,
                daily_volume=args.daily_volume,
                dns_findings=audit_domain(args.domain, selectors=args.selector, sending_ips=[i.ip], resolver=resolver),
                health=ReputationMonitor(store).health(args.domain, i.target),
                dnsbl_results=check_dnsbls(i.ip, resolver),
            )
            packet = build_appeal(i, ctx)
            if packet.channel:
                ch = packet.channel
                print(f"■ 제출처: {ch.name}\n  방법: {ch.how}\n  주소: {ch.url} (경로 변경 가능, 확인 필요)\n"
                      f"  예상 처리: {ch.typical_wait}\n")
            if not packet.ready:
                print("✗ 아직 소명하면 안 됩니다:")
                for blk in packet.blockers:
                    print(f"  - {blk}")
                print("\n(초안은 아래와 같습니다)\n")
            print(packet.letter)
            if args.submitted:
                log.mark_appealed(i.id)
                print("소명 제출로 기록했습니다.")
            return 0 if packet.ready else 1
    if args.cmd == "providers":
        for p in PROVIDERS.values():
            print(f"■ {p.name}  ({', '.join(sorted(p.domains))})  시작 속도 {p.max_per_minute}/분")
            for n in p.notes:
                print(f"   - {n}")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
