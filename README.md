# ZeroScan WAF

ZeroScan WAF는 Python으로 만든 간단한 웹 위협 탐지 도구입니다.  
문자열 입력이나 웹사이트 응답 내용을 검사해서 SQL Injection, XSS, LFI 같은 위험 징후를 탐지하고, 위험하면 경고를 출력합니다.

## 주요 기능

- 입력값 정규화
  - HTML 엔티티와 URL 인코딩을 복원해서 우회된 패턴도 검사합니다.
- 정적 패턴 탐지
  - SQLi, XSS, LFI 관련 정규식과 블랙리스트 기반으로 빠르게 탐지합니다.
- 동적 위험 점수 계산
  - 특수문자 비율, SQL 키워드 밀도, 주석 문자 등을 기준으로 위험도를 계산합니다.
- 웹사이트 검사
  - 사용자가 입력한 `http/https` URL에 접속한 뒤 응답 내용까지 검사합니다.
- 경고 메시지 출력
  - 위험 징후가 있거나 접속이 비정상이면 경고 메시지를 보여 줍니다.

## 동작 방식

1. 사용자가 검사할 문자열 또는 웹사이트 주소를 입력합니다.
2. 입력값을 정규화합니다.
3. 블랙리스트와 정규식 규칙으로 먼저 검사합니다.
4. 정적 규칙에 걸리지 않으면 위험 점수를 계산합니다.
5. 임계값 이상이면 차단으로 판단합니다.

웹사이트 검사에서는 추가로 다음도 확인합니다.

- URL 형식이 올바른지
- 사이트에 실제 접속 가능한지
- HTTP 응답이 비정상인지
- 응답 본문에 위험 패턴이 포함되어 있는지

## 실행 방법

### Windows

```bash
python zeroscan_waf.py
```

### Linux / macOS

```bash
python3 zeroscan_waf.py
```

실행 후 검사할 웹사이트 주소를 입력하면 됩니다.

예시:

```text
검사할 웹사이트 주소를 입력하세요: https://example.com
```

## 코드 사용 예시

### 1. 일반 문자열 검사

```python
from zeroscan_waf import ZeroScanWAF

waf = ZeroScanWAF(risk_threshold=0.8)

result = waf.inspect("<script>alert(1)</script>")

print(result.allowed)
print(result.reason)
print(result.risk_score)
print(result.matched_rule)
```

### 2. 웹사이트 검사

```python
from zeroscan_waf import ZeroScanWAF

waf = ZeroScanWAF(risk_threshold=0.8)

result = waf.inspect_website("https://example.com")

print(result.url)
print(result.reachable)
print(result.allowed)
print(result.alert_message)
print(result.status_code)
print(result.risk_score)
print(result.matched_rule)
```

## 반환 값

### `inspect()`

- `allowed`: 허용 여부
- `reason`: 판정 이유
- `risk_score`: 위험 점수
- `matched_rule`: 탐지된 규칙 이름 또는 블랙리스트 문자열

### `inspect_website()`

- `url`: 검사한 주소
- `reachable`: 접속 가능 여부
- `allowed`: 안전 여부
- `alert_message`: 사용자에게 보여 줄 메시지
- `risk_score`: 위험 점수
- `matched_rule`: 탐지된 규칙
- `status_code`: HTTP 상태 코드

## 한계

- 이 프로젝트는 패턴 기반 탐지이므로 악성 사이트를 100% 판별하지 못합니다.
- 정상 사이트가 오탐될 수 있습니다.
- JavaScript 실행 결과나 동적 렌더링 이후 내용까지는 분석하지 않습니다.
- 외부 평판 DB, DNS 분석, 인증서 평판, 샌드박스 분석 같은 고급 보안 기능은 포함되어 있지 않습니다.

## 기술 스택

- Python 3
- 표준 라이브러리만 사용
  - `re`
  - `html`
  - `urllib`
  - `dataclasses`
