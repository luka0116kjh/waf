import html
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple
from urllib.parse import unquote


@dataclass(frozen=True)
class InspectionResult:
    allowed: bool
    reason: str
    risk_score: float
    matched_rule: str = ""


class ZeroScanWAF:
    """Hybrid WAF: static regex rules + lightweight anomaly scoring."""

    def __init__(self, risk_threshold: float = 0.8) -> None:
        self.risk_threshold = risk_threshold

        # Stage 1) Attack payload DB (2024-2026 commonly observed families)
        self.payload_blacklist: List[str] = [
            "' OR 1=1 --",  # SQLi: classic auth bypass
            "' OR 'a'='a' --",  # SQLi: boolean-based bypass
            "' UNION SELECT NULL,NULL --",  # SQLi: UNION-based column probing
            "'/**/UNION/**/SELECT/**/1,2,3--",  # SQLi: comment-obfuscated UNION SELECT
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",  # SQLi: MySQL error-based leak
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))--",  # SQLi: XML function error-based leak
            "' AND UPDATEXML(1,CONCAT(0x7e,user(),0x7e),1)--",  # SQLi: UPDATEXML error-based leak
            "' AND SLEEP(5)--",  # SQLi: time-based blind probe
            "' OR IF(1=1,SLEEP(5),0)--",  # SQLi: conditional time-based blind probe
            "'; WAITFOR DELAY '0:0:5'--",  # SQLi: MSSQL time-based blind probe
            "<script>alert(1)</script>",  # XSS: basic reflected script execution
            "\"><svg/onload=alert(1)>",  # XSS: attribute-break + SVG event
            "javascript:alert(document.domain)",  # XSS: javascript URI execution
            "<img src=x onerror=alert(1)>",  # XSS: image error-event execution
            "<details open ontoggle=alert(1)>",  # XSS: HTML5 event handler payload
            "<svg><script xlink:href=data:,alert(1)></script>",  # XSS: SVG/script polyglot style payload
            "../../../../etc/passwd",  # LFI: directory traversal to sensitive file
            "..%2f..%2f..%2f..%2fetc%2fpasswd",  # LFI: URL-encoded traversal
            "....//....//....//etc/passwd",  # LFI: traversal bypass variant
            "/proc/self/environ",  # LFI: process environment leakage
        ]

        # Stage 2) Regex rules hardened for case changes, comments, spacing, and mild encoding tricks
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
        """Normalize common obfuscation layers before matching."""
        normalized = user_input or ""

        # Decode HTML entities (&lt;, &#x27;, ...)
        normalized = html.unescape(normalized)

        # Decode URL encoding multiple rounds for double-encoding tricks
        for _ in range(2):
            decoded = unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded

        return normalized

    def calculate_risk_score(self, user_input: str) -> float:
        """
        Risk score in [0.0, 1.0].
        Components:
        - special character ratio (density)
        - SQL keyword density
        - suspicious token bonuses
        """
        if not user_input:
            return 0.0

        text = self._normalize_input(user_input)
        length = max(len(text), 1)

        special_count = len(self.special_chars_pattern.findall(text))
        special_ratio = special_count / length  # 0..1+

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


if __name__ == "__main__":
    waf = ZeroScanWAF(risk_threshold=0.8)

    test_inputs = [
        "union/**/select 1,2,3",
        "'; DROP TABLE users; --",
        "<img src=x onerror=alert(1)>",
        "../../../../etc/passwd",
        "hello world",
    ]

    for item in test_inputs:
        result = waf.inspect(item)
        print(
            {
                "input": item,
                "allowed": result.allowed,
                "reason": result.reason,
                "matched_rule": result.matched_rule,
                "risk_score": round(result.risk_score, 3),
            }
        )
