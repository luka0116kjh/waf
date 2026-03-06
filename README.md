#  ZeroScan Sentinel: Hybrid WAF & Real-time Guard

ZeroScan Sentinel은 정적 패턴 매칭과 동적 리스크 스코어링 결합한 **하이브리드 웹 보안 엔진**입니다. 단순한 로그 분석을 넘어, 브라우저 확장 프로그램과 연동하여 사용자가 접속하는 모든 웹사이트를 실시간으로 감시하고 보호합니다.

##  주요 기능

1.  **실시간 브라우저 감시 (Guard Mode):**
    *   브라우저 확장 프로그램을 통해 사용자가 방문하는 모든 URL을 실시간 스캔합니다.
    *   위험 사이트 접속 시 브라우저 상단에 즉각적인 경고 알림을 표시합니다.
2.  **지능형 리스크 스코어링 (Dynamic Analysis):**
    *   2024~2026년 최신 공격 트렌드를 반영한 페이로드 탐지.
    *   특수 문자 밀도 및 키워드 빈도를 기반으로 0~100% 사이의 위험도를 계산합니다.
3.  **프리미엄 보안 대시보드:**
    *   웹 UI를 통해 특정 URL이나 텍스트(페이로드)를 직접 정밀 분석할 수 있습니다.
    *   탐지된 규칙, HTTP 상태 코드, 상세 리포트를 시각적으로 제공합니다.

---

##  설치 및 실행 방법

### 1단계: 백엔드 API 서버 실행
시스템의 중심 엔진인 Python 서버를 먼저 실행해야 합니다.

#### [Windows]
```powershell
# 필수 라이브러리 설치
pip install fastapi uvicorn

# 서버 실행
python app.py
```

#### [Linux]
리눅스 환경에서는 `python3`와 `pip3`를 사용하며, 서버를 백그라운드에서 유지하는 것이 좋습니다.
```bash
# 필수 패키지 및 라이브러리 설치
sudo apt update && sudo apt install python3-pip -y
pip3 install fastapi uvicorn

# 서버 실행 (백그라운드 유지 예시)
nohup python3 app.py > waf.log 2>&1 &
```
*   서버는 기본적으로 `http://localhost:8000`에서 작동합니다. 리눅스 서버 IP가 다를 경우 `app.py`의 호스트 설정을 확인하세요.

### 2단계: 실시간 브라우저 확장 프로그램 설치
평소 브라우저 서핑 시 실시간으로 보호를 받으려면 확장을 설치해야 합니다.

1.  크롬(Chrome) 브라우저에서 `chrome://extensions/` 주소로 이동합니다.
2.  우측 상단의 **'개발자 모드(Developer mode)'**를 활성화합니다.
3.  **'압축해제된 확장 프로그램을 로드(Load unpacked)'** 버튼을 클릭합니다.
4.  프로젝트 폴더 내의 `extension` 디렉토리를 선택합니다.

---

## 기술 사양 (탐지 범위)

*   **SQL Injection:** Union Selection, Error-based, Time-based, Stacked Query 등
*   **Cross-Site Scripting (XSS):** Script tags, Event handlers, JS URI, Polyglot hints 등
*   **Local File Inclusion (LFI):** Directory Traversal, Sensitive file access (/etc/passwd 등)
*   **Anomaly Detection:** 비정상적인 특수문자 조합 및 위험 키워드 밀도 분석

##  프로젝트 구조

*   `zeroscan_waf.py`: 핵심 WAF 로직 및 리스크 알고리즘
*   `app.py`: FastAPI 기반의 보안 분석 API 서버
*   `/static`: 보안 대시보드 웹 프런트엔드
*   `/extension`: 실시간 감시용 브라우저 확장 프로그램 소스

---
*본 프로젝트는 보안 학습 및 실시간 웹 위협 탐지 데모를 목적으로 제작되었습니다.*
