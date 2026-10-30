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
발신 도메인 검증(SPF·DKIM·DMARC) → 발송 IP 차단 사고 여부 → 수신제외 목록 → 수신동의(2년 재확인) → 평판 상태(중지 여부) → 웜업 일일 한도
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

## 발신 도메인 설정: SPF · DKIM · DMARC

**검증을 통과하지 않은 발신 도메인은 발송할 수 없습니다** (`MailerConfig.require_verified_domain=True`).

```bash
# 1) 등록할 레코드 생성 — DKIM 2048비트 키를 만들고, 기존 SPF 가 있으면 합친 값을 보여줌
strongemail setup shop.co.kr --ip 203.0.113.10 --selector se1

# 2) DNS 등록 후 검증 (SPF 에 발송 IP 포함? DKIM 공개키가 개인키와 일치? DMARC 존재?)
strongemail verify shop.co.kr --ip 203.0.113.10 --selector se1 --key se1.shop.co.kr.pem

# 3) DMARC 단계적 강화 일정
strongemail dmarc-plan --rua dmarc-reports@shop.co.kr
```

| 레코드 | 위치 | 핵심 |
|---|---|---|
| SPF | `shop.co.kr TXT` | 도메인당 **1개**. 이미 있으면 새로 만들지 말고 합치기. DNS 조회 10회 이하 |
| SPF (반송용) | `bounce.shop.co.kr TXT` | Return-Path 를 하위 도메인으로 두어 SPF 도 DMARC 정렬 |
| DKIM | `se1._domainkey.shop.co.kr TXT` | 2048비트 RSA, 개인키는 발송 서버에만 보관 |
| DMARC | `_dmarc.shop.co.kr TXT` | `p=none` → (14일) → `quarantine pct=25` → (7일) → `quarantine` → (14일) → `reject` |
| PTR | IP 제공자에 요청 | `mail.shop.co.kr` + 같은 이름의 A 레코드 (FCrDNS) |

발신 도메인 검증은 하루 한 번 다시 돌리세요(`SenderDomainRegistry.verify`). 고객이 DNS 를 바꾸거나 지우면
48시간 뒤 자동으로 발송이 막힙니다.

**DKIM 키 교체 (6~12개월마다 권장)**
1. 새 selector 로 키 생성: `strongemail setup shop.co.kr --selector se2 ...` → `se2._domainkey` 등록
2. `verify --selector se2` 통과 확인 후 발송 서버 설정을 se2 키로 변경
3. 이미 발송된 메일 검증을 위해 기존 `se1` 레코드는 7일 이상 유지한 뒤 `p=` 를 비워 폐기

## 발송 IP 차단과 소명

```
차단 응답(5.7.x) 수신 → 사고 자동 기록 → 해당 포털로만 발송 중지 (공용 차단목록이면 전체 중지)
→ 원인 조치·기록 → 소명 준비 점검 → 소명서 제출 → 해제 확인 → 그 포털만 웜업부터 재시작
```

```bash
strongemail blocklist 203.0.113.10                 # Spamhaus/Barracuda/SpamCop 등재 확인
strongemail incident list                          # 진행 중 차단 사고
strongemail incident action 1 "구매 DB 발송 중단, 6개월 무반응 수신자 12,000명 제외"
strongemail incident appeal 1 --company "(주)예시상점" --name 홍길동 \
    --email postmaster@shop.co.kr --phone 02-123-4567 --domain shop.co.kr --selector se1 --daily-volume 20000
strongemail incident appeal 1 ... --submitted      # 제출했다고 기록
strongemail incident resolve 1                     # 해제 확인 → 해당 포털 재웜업
```

`appeal` 은 **소명해도 되는 상태인지 먼저 점검**합니다. 원인을 그대로 둔 채 소명하면 거절되고, 반복될수록 해제가 어려워지기 때문입니다.
- DNS 인증 오류(SPF/DKIM/DMARC/PTR)가 남아 있으면 → 보류
- 현재 하드바운스율/신고율이 중지 기준을 넘으면 → 보류
- 원인 조치 내역이 기록되지 않았으면 → 보류
- Gmail/MS/Yahoo 는 차단 후 12시간 이내면 → 보류 (조치 효과가 지표에 반영될 시간)
- 다른 공용 차단목록에도 올라 있으면 → 함께 처리하라고 안내

소명서는 국내 포털(네이버·다음·네이트)은 한국어, 해외(Gmail·MS·Yahoo·Spamhaus 등)는 영어로 생성되며
발송 정보, 인증 상태, 수신동의 방법, 원인과 조치 내역, 현재 지표, 재발 방지 약속이 들어갑니다.
같은 포털에서 다시 차단되면 이전 소명 횟수를 반영해 재발 방지책을 강조합니다.

> 소명 제출 경로(고객센터 메뉴, URL)는 각 사가 자주 바꿉니다. `APPEAL_CHANNELS` 의 안내는 출발점이며 제출 전 최신 경로를 확인하세요.
> Gmail 은 개별 해제보다 **원인 제거 후 발송량을 줄여 평판이 자동 회복되기를 기다리는 것**이 원칙입니다.

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
  domain_setup.py SPF/DKIM/DMARC 레코드 생성·병합, DKIM 키 생성, DMARC 단계 계획, 발신 도메인 검증
  blocklist.py    DNSBL 조회, 차단 원인 판별, 차단 사고 기록, 소명 준비 점검·소명서 생성
  providers.py    포털 프로필 (도메인, 시작 속도, 요건)
```

## 다음 단계 (아직 없는 것)

- 발송 큐/워커 (`DEFERRED` 재시도 스케줄링). 대량이면 KumoMTA·Postfix 같은 MTA 앞단에 이 코어를 둠
- 반송(DSN)·ARF 메일함 파서, DMARC 집계 리포트(rua) 분석기
- 참여도 기반 수신자 정리 (6~12개월 무반응 수신자 제외)
- 관리 대시보드 / API 서버

> 포털별 속도값은 공개된 수치가 아닌 **보수적 시작값**입니다. 실제 4xx 지연 응답 비율을 보고 조정하세요.
> 법규 요약은 개발 참고용이며 법률 자문이 아닙니다. 최신 KISA 「불법스팸 방지를 위한 정보통신망법 안내서」를 확인하세요.
