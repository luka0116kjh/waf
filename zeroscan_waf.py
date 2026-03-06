import html
import re
from dataclasses import dataclass
from typing import Dict, List
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class InspectionResult:
    allowed: bool
    reason: str
    risk_score: float
    matched_rule: str = ""


@dataclass(frozen=True)
class WebsiteInspectionResult:
    url: str
    reachable: bool
    allowed: bool
    alert_message: str
    risk_score: float
    matched_rule: str = ""
    status_code: int = 0


class ZeroScanWAF:
    """Hybrid WAF: static regex rules + lightweight anomaly scoring."""

    def __init__(self, risk_threshold: float = 0.8) -> None:
        self.risk_threshold = risk_threshold

        # Stage 1) Attack payload DB (2024-2026 commonly observed families)
        self.payload_blacklist: List[str] = [
            "' OR 1=1 --",
            "' OR 'a'='a' --",
            "' UNION SELECT NULL,NULL --",
            "'/**/UNION/**/SELECT/**/1,2,3--",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,user(),0x7e),1)--",
            "' AND SLEEP(5)--",
            "' OR IF(1=1,SLEEP(5),0)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "<script>alert(1)</script>",
            '\"><svg/onload=alert(1)>',
            "javascript:alert(document.domain)",
            "<img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<svg><script xlink:href=data:,alert(1)></script>",
            "../../../../etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "/proc/self/environ",
        ]

        # (?is) => case-insensitive + dot matches newline
        self.regex_rules: Dict[str, str] = {
            "SQLI_UNION_SELECT": r"(?is)\bu\W*n\W*i\W*o\W*n\W*(?:/\*.*?\*/|\s|\+|%[0-9a-f]{2})*s\W*e\W*l\W*e\W*c\W*t\b",
            "SQLI_STACKED_OR_DANGEROUS": r"(?is)(?:;\s*(?:drop|alter|truncate|create)\b)|(?:\b(?:or|and)\b\s+\d+\s*=\s*\d+)",
            "SQLI_ERROR_BASED": r"(?is)\b(?:extractvalue|updatexml|floor\s*\(\s*rand\s*\()\b",
            "SQLI_TIME_BASED": r"(?is)\b(?:sleep\s*\(|benchmark\s*\(|waitfor\s+delay)\b",
            "XSS_SCRIPT_TAG": r"(?is)<\s*script\b[^>]*>.*?<\s*/\s*script\s*>",
            "XSS_EVENT_HANDLER": r"(?is)<[^>]+\bon\w+\s*=\s*['\"]?[^>]+>",
            "XSS_JS_URI": r"(?is)\bjavascript\s*:\s*[^\s]+",
            "XSS_POLYGLOT_HINT": r"(?is)(?:<svg\b|<math\b|xlink:href|data\s*:\s*text/html)",
            "LFI_TRAVERSAL": r"(?is)(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e\\)+",
            "LFI_SENSITIVE_FILES": r"(?is)(?:/etc/passwd|/proc/self/environ|/windows/win\.ini)",
        }

        self.sql_keywords_pattern = re.compile(
            r"\b(select|insert|update|delete|union|from|where|sleep|benchmark|waitfor|extractvalue|updatexml|drop|alter|truncate)\b",
            re.IGNORECASE,
        )
        self.special_chars_pattern = re.compile(r"['\"<>\-\/;()=]", re.IGNORECASE)

    def _normalize_input(self, user_input: str) -> str:
        normalized = user_input or ""
        normalized = html.unescape(normalized)

        for _ in range(2):
            decoded = unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded

        return normalized

    def calculate_risk_score(self, user_input: str) -> float:
        if not user_input:
            return 0.0

        text = self._normalize_input(user_input)
        length = max(len(text), 1)

        special_count = len(self.special_chars_pattern.findall(text))
        special_ratio = special_count / length

        sql_keywords = self.sql_keywords_pattern.findall(text)
        keyword_density = len(sql_keywords) / max(len(text.split()), 1)

        bonus = 0.0
        if re.search(r"(?is)(--|/\*|\*/|#)", text):
            bonus += 0.15
        if re.search(r"(?is)<\s*script|\bon\w+\s*=|javascript\s*:", text):
            bonus += 0.2
        if re.search(r"(?is)\.\./|%2e%2e%2f|/etc/passwd|/proc/self/environ", text):
            bonus += 0.2

        score = (special_ratio * 0.5) + (keyword_density * 0.5) + bonus
        return min(score, 1.0)

    def inspect(self, user_input: str) -> InspectionResult:
        normalized = self._normalize_input(user_input)

        for payload in self.payload_blacklist:
            if payload.lower() in normalized.lower():
                return InspectionResult(
                    allowed=False,
                    reason="Payload blacklist matched",
                    risk_score=1.0,
                    matched_rule=payload,
                )

        for rule_name, pattern in self.regex_rules.items():
            if re.search(pattern, normalized):
                return InspectionResult(
                    allowed=False,
                    reason="Pattern matched (static)",
                    risk_score=1.0,
                    matched_rule=rule_name,
                )

        risk_score = self.calculate_risk_score(normalized)
        if risk_score >= self.risk_threshold:
            return InspectionResult(
                allowed=False,
                reason="High risk score (dynamic)",
                risk_score=risk_score,
            )

        return InspectionResult(
            allowed=True,
            reason="Safe",
            risk_score=risk_score,
        )

    def inspect_website(self, url: str, timeout: int = 5) -> WebsiteInspectionResult:
        parsed = urlparse(url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return WebsiteInspectionResult(
                url=url,
                reachable=False,
                allowed=False,
                alert_message="경고: 올바른 http/https 웹사이트 주소가 아닙니다.",
                risk_score=1.0,
            )

        request = Request(
            url,
            headers={
                "User-Agent": "ZeroScanWAF/1.0",
                "Accept": "text/html,application/xhtml+xml",
            },
        )

        try:
            with urlopen(request, timeout=timeout) as response:
                status_code = getattr(response, "status", 200)
                content_type = response.headers.get("Content-Type", "")
                body = response.read(200000).decode("utf-8", errors="ignore")
        except HTTPError as exc:
            return WebsiteInspectionResult(
                url=url,
                reachable=True,
                allowed=False,
                alert_message=f"경고: 웹사이트 응답이 비정상입니다. HTTP {exc.code}",
                risk_score=0.95,
                status_code=exc.code,
            )
        except URLError as exc:
            return WebsiteInspectionResult(
                url=url,
                reachable=False,
                allowed=False,
                alert_message=f"경고: 웹사이트에 접속할 수 없습니다. {exc.reason}",
                risk_score=1.0,
            )
        except Exception as exc:
            return WebsiteInspectionResult(
                url=url,
                reachable=False,
                allowed=False,
                alert_message=f"경고: 검사 중 오류가 발생했습니다. {exc}",
                risk_score=1.0,
            )

        combined_text = "\n".join([url, content_type, body])
        inspection = self.inspect(combined_text)

        if not inspection.allowed:
            return WebsiteInspectionResult(
                url=url,
                reachable=True,
                allowed=False,
                alert_message="경고: 위험 징후가 감지된 웹사이트입니다.",
                risk_score=inspection.risk_score,
                matched_rule=inspection.matched_rule,
                status_code=status_code,
            )

        return WebsiteInspectionResult(
            url=url,
            reachable=True,
            allowed=True,
            alert_message="정상: 현재 확인된 위험 징후가 없습니다.",
            risk_score=inspection.risk_score,
            status_code=status_code,
        )


if __name__ == "__main__":
    waf = ZeroScanWAF(risk_threshold=0.8)
    target_url = input("검사할 웹사이트 주소를 입력하세요: ").strip()
    result = waf.inspect_website(target_url)
    print(
        {
            "url": result.url,
            "reachable": result.reachable,
            "allowed": result.allowed,
            "alert_message": result.alert_message,
            "matched_rule": result.matched_rule,
            "status_code": result.status_code,
            "risk_score": round(result.risk_score, 3),
        }
    )
