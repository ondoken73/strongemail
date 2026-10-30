# strongemail

**평판과 포털(네이버·다음·Gmail·Outlook 등) 수신 기준을 지키는 이메일 발송 코어.**

SMTP로 메일을 "보내는 것"은 쉽습니다. 어려운 것은 **받은편지함에 들어가는 것**입니다.
포털은 아래 세 가지를 보고 우리 메일을 받을지, 스팸함에 넣을지, 거부할지 결정합니다.

| 축 | 포털이 보는 것 | strongemail 모듈 |
|---|---|---|
| **인증** | SPF, DKIM, DMARC 정렬, PTR/FCrDNS, TLS | `dns_audit.py`, `sender.py`(DKIM 서명) |
| **평판** | 하드바운스율, 스팸 신고율, 발송량 급증, 정책 차단 응답 | `reputation.py`, `throttle.py` |
| **규정/콘텐츠** | 원클릭 수신거부(RFC 8058), 정보통신망법 광고 표기, 본문 품질 | `compliance.py`, `unsubscribe.py` |

모든 메일은 발송 전에 아래 관문을 순서대로 통과해야 SMTP로 나갑니다.

```
수신제외 목록 → 수신동의(2년 재확인) → 평판 상태(중지 여부) → 웜업 일일 한도
→ 포털별 속도 제한 → 메시지 생성 + DKIM 서명 → 규정 검사 → SMTP → 결과 분류·기록
```

## 빠른 시작

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest

# 1) 발송 도메인/IP DNS 점검
strongemail audit example.co.kr --selector s1 --ip 203.0.113.10

# 2) 완성된 메일(.eml) 규정 점검
strongemail lint campaign.eml --marketing --sender-name "(주)예시상점" --sender-contact 02-123-4567

# 3) 포털별 기준 요약
strongemail providers
```

```python
from strongemail import *

mailer = Mailer(
    MailerConfig(
        from_address="news@example.co.kr", from_name="예시상점",
        return_path="bounces@bounce.example.co.kr",          # SPF 정렬용 하위 도메인
        dkim_selector="s1", dkim_private_key=open("dkim.pem", "rb").read(),
        sender_identity=SenderIdentity("(주)예시상점", "02-123-4567"),
        unsubscribe_base_url="https://mail.example.co.kr",
        unsubscribe_secret=b"...32바이트 이상 비밀값...",
        warmup_started=date(2026, 11, 1),                    # 새 IP면 웜업 시작일
    ),
    ReputationMonitor(Store("strongemail.db")),
    SMTPTransport("relay.internal", 587),
)

r = mailer.send(OutgoingEmail(
    to="user@naver.com", subject="(광고) 가을 세일", text="...", html="...",
    category=Category.MARKETING,
    consent=Consent(marketing_opt_in_at=datetime(2026, 3, 1, tzinfo=KST)),
))
# r.status: SENT / DEFERRED(retry_after 초 후 재시도) / REJECTED(재시도 금지)
```

비동기 피드백도 같은 모니터로 모아야 평판 계산이 맞습니다.

- 반송 메일(DSN) 수신함 파서 → `mailer.handle_dsn(addr, code, text)`
- 피드백 루프(ARF: Microsoft JMRP, Yahoo CFL 등) → `mailer.handle_complaint(addr)`
- 원클릭 수신거부 엔드포인트 → `unsubscribe.make_wsgi_app(mailer.tokens, mailer.handle_unsubscribe)`

## 발송 전 체크리스트

### 1. DNS / 인프라 (`strongemail audit`)
- [ ] **SPF**: 레코드 1개, `-all`(또는 `~all`), DNS 조회 10회 이하
- [ ] **DKIM**: 2048비트 RSA, 발신 도메인(From)과 같은 조직 도메인으로 서명
- [ ] **DMARC**: `p=none; rua=...`로 시작 → 리포트로 정렬 확인 → `quarantine` → `reject`
- [ ] **PTR**: 발송 IP의 역방향 DNS가 `mail.example.co.kr` 형태이고 정방향 조회와 일치(FCrDNS)
- [ ] **Return-Path**: `bounce.example.co.kr` 같은 하위 도메인으로 SPF도 정렬
- [ ] **TLS**: 릴레이/MTA에서 STARTTLS 사용
- [ ] 마케팅과 거래성(인증번호·영수증) 메일은 **하위 도메인 또는 IP 분리**: 광고 평판이 나빠져도 인증 메일은 계속 들어가게

### 2. 평판 운영 (`reputation.py`)
- 기본 기준 (24시간 이동 창, 200통 이상일 때 판정)

  | 지표 | 경고 | 자동 중지 |
  |---|---|---|
  | 스팸 신고율 | 0.1% | 0.3% (Gmail/Yahoo 제재선) |
  | 하드바운스율 | 2% | 5% |
  | 정책 차단(5.7.x) 응답률 | 2.5% | 5% |
  | 인증 실패(5.7.26, 5.7.515 등) | – | 1건이라도 발생 시 |

- 하드바운스·스팸신고 → 영구 제외. 수신거부 → 광고만 제외. 소프트바운스 3회 연속 → 제외
- **새 IP 웜업**: 포털별 하루 50통에서 시작해 매일 약 1.8배 증가. 처음에는 참여도가 높은(최근 열람한) 수신자부터 보내기
- 421 / 4.7.x 응답을 받으면 해당 포털 속도를 절반으로 줄이고 60초 정지한 뒤 서서히 회복
- **관측 도구 등록**: Google Postmaster Tools, Microsoft SNDS/JMRP, Yahoo Sender Hub, DMARC rua 리포트 분석

### 3. 정보통신망법 (광고성 이메일): `compliance.py`가 강제
- [ ] **사전 수신동의** (제50조): 동의 기록이 없으면 발송 거부
- [ ] **2년마다 수신동의 재확인 통지**: 마지막 동의/재확인 후 2년이 지나면 발송 거부
- [ ] 야간(21시~08시) 광고 별도 동의는 **전자우편은 법적 예외**(시행령 제61조). SMS·푸시와 같은 정책을 쓰려면 `enforce_night_consent=True`
- [ ] 제목 맨 앞 **`(광고)`** 표기
- [ ] 본문에 **전송자 명칭·연락처**, **무료 수신거부 방법**: 광고 메일에는 자동으로 하단 문구를 붙임
- [ ] 수신거부/동의 철회 처리 결과를 14일 이내 수신자에게 통지 (운영 프로세스)

### 4. 콘텐츠
- text/plain 대체 본문 포함, HTML 102KB 이하(넘으면 Gmail이 본문을 잘라 수신거부 링크가 가려짐)
- 이미지 한 장짜리 메일, 단축 URL(bit.ly 등), 전부 대문자이거나 느낌표를 남발한 제목 피하기
- From 에 무료메일(naver.com, gmail.com 등) 사용 금지: 해당 포털 DMARC 정책으로 거부됨

## 구조

```
strongemail/
  dns_audit.py    SPF/DKIM/DMARC/MX/PTR/MTA-STS/TLS-RPT/BIMI 점검
  compliance.py   메시지 규정 검사 (RFC, 포털 대량발송 기준, 정보통신망법)
  reputation.py   SMTP 응답 분류, 수신제외 목록, 평판 지표, 웜업 계획 (SQLite)
  throttle.py     포털별 토큰버킷 + 4xx 적응형 감속
  unsubscribe.py  RFC 8058 원클릭 수신거부 토큰/엔드포인트
  sender.py       발송 파이프라인 (관문 → DKIM 서명 → SMTP → 결과 기록)
  providers.py    포털 프로필 (도메인, 시작 속도, 요건)
```

## 다음 단계 (아직 없는 것)

- 발송 큐/워커 (`DEFERRED` 재시도 스케줄링). 대량이면 KumoMTA·Postfix 같은 MTA 앞단에 이 코어를 둠
- 반송(DSN)·ARF 메일함 파서, DMARC 집계 리포트(rua) 분석기
- 참여도 기반 수신자 정리 (6~12개월 무반응 수신자 제외)
- 관리 대시보드 / API 서버

> 포털별 속도값은 공개된 수치가 아닌 **보수적 시작값**입니다. 실제 4xx 지연 응답 비율을 보고 조정하세요.
> 법규 요약은 개발 참고용이며 법률 자문이 아닙니다. 최신 KISA 「불법스팸 방지를 위한 정보통신망법 안내서」를 확인하세요.
