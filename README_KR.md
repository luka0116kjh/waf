# ZeroScan Sentinel

[![English](https://img.shields.io/badge/lang-English-blue?style=flat-square)](README.md)
[![Korean](https://img.shields.io/badge/lang-한국어-red?style=flat-square)](README_KR.md)

ZeroScan Sentinel은 FastAPI 기반의 간단한 WAF 분석 서버와 Chrome 확장 프로그램을 결합한 실시간 웹 위험 감지 프로젝트입니다.

기본 동작은 `알림 모드`이며, 위험 징후가 감지되면 현재 페이지 상단에 경고 배너를 표시합니다. 필요하면 확장 프로그램 팝업에서 `차단 모드`로 전환해 위험 사이트를 전용 차단 페이지로 넘길 수 있습니다.

## 주요 기능

- **실시간 URL 검사**: Chrome 확장 프로그램이 메인 프레임 이동을 감지하고 로컬 WAF API에 URL 검사를 요청합니다.
- **알림 모드**: 기본값입니다. 위험 사이트로 판단되면 현재 페이지 상단에 경고 배너를 표시합니다.
- **차단 모드**: 위험 사이트로 판단되면 확장 프로그램 내부 차단 페이지로 이동시킵니다.
- **예외 허용**: 차단 페이지에서 `이번만 계속 접속` 또는 `이 도메인 항상 허용`을 선택할 수 있습니다.
- **직접 페이로드 검사**: 대시보드 UI에서 URL 또는 텍스트 페이로드를 직접 검사할 수 있습니다.
- **하이브리드 탐지**: 정적 패턴 매칭과 간단한 위험 점수 계산을 함께 사용합니다.

## 빠른 시작

### 1. Python 패키지 설치

```powershell
pip install fastapi uvicorn
```

### 2. API 서버 실행

```powershell
python app.py
```

서버는 기본적으로 `http://127.0.0.1:8000`에서 실행됩니다.

### 3. Chrome 확장 프로그램 로드

1. Chrome에서 `chrome://extensions/`로 이동합니다.
2. 오른쪽 상단의 `개발자 모드`를 켭니다.
3. `압축해제된 확장 프로그램을 로드합니다`를 클릭합니다.
4. 이 프로젝트의 `extension` 폴더를 선택합니다.

확장 프로그램은 `http://127.0.0.1:8000/api/scan`에 연결됩니다.
즉, 평소에는 `python app.py`만 실행되어 있으면 확장 프로그램이 자동으로 동작합니다.
코드를 수정한 뒤에는 확장 프로그램 카드에서 `새로고침`을 눌러 반영합니다.

## 사용 방법

### 웹 대시보드

- 브라우저에서 `http://127.0.0.1:8000` 접속
- 검사할 URL 입력 후 분석
- 또는 텍스트/페이로드를 직접 입력해 검사

### 확장 프로그램

- 기본값은 `알림 모드`
- 팝업에서 `차단 모드`로 전환 가능
- 차단 모드에서 위험 페이지 접근 시 차단 페이지로 이동
- 차단 페이지에서 다음 중 하나 선택 가능:
  - `이번만 계속 접속`
  - `이 도메인 항상 허용`
  - `이전 페이지로 돌아가기`
  - `탭 닫기`

## 권장 테스트 절차

1. 터미널에서 `python app.py` 실행
2. 브라우저에서 `http://127.0.0.1:8000` 접속 확인
3. `chrome://extensions/`에서 확장 프로그램이 로드되어 있는지 확인
4. 필요하면 확장 프로그램 `새로고침`
5. 테스트 URL 접속 후 알림 또는 차단 동작 확인

## 동작 방식

### 백엔드

- **`app.py`**: FastAPI 서버를 실행합니다.
  - `/api/scan`: 웹사이트 URL 검사
  - `/api/inspect`: 텍스트 페이로드 검사
- **`zeroscan_waf.py`**:
  - SQLi, XSS, LFI 관련 패턴 검사
  - URL 자체 검사
  - 웹 응답에서 고위험 능동형 패턴 탐지

### 프런트엔드

- `static/index.html`
- `static/script.js`
- `static/style.css`

브라우저에서 직접 URL과 페이로드를 넣어 검사 결과를 확인하는 대시보드입니다.

### Chrome 확장 프로그램

- **`extension/background.js`**: 페이지 이동 감시, 알림/차단 처리, 예외 허용 처리
- **`extension/popup.html` / `popup.js`**: 알림 모드 / 차단 모드 전환 UI
- **`extension/blocked.html` / `blocked.js`**: 차단 페이지, 이번만 허용, 도메인 허용 로직

## 현재 제한 사항

- `/api/scan`은 서버가 직접 URL에 접속하는 구조라 SSRF 방어가 아직 충분하지 않습니다.
- 탐지 정확도는 데모 수준이며, 오탐과 미탐이 남아 있을 수 있습니다.
- 로컬 API 서버가 실행 중이어야 확장 프로그램이 정상 동작합니다.

## 프로젝트 구조

```text
waf/
|-- app.py
|-- zeroscan_waf.py
|-- README.md
|-- README_KR.md
|-- static/
|   |-- index.html
|   |-- script.js
|   `-- style.css
`-- extension/
    |-- background.js
    |-- blocked.html
    |-- blocked.js
    |-- manifest.json
    |-- popup.html
    `-- popup.js
```

## 참고 사항

이 프로젝트는 학습 및 프로토타이핑 목적의 보안 감지 도구입니다. 실제 운영 환경에 적용하려면 SSRF 방어, 정밀한 정책 설계, 로그 관리, 예외 정책 관리, 탐지 정확도 개선이 추가로 필요합니다.
