"""S1 — Prompt Injection Phrase Detector.

Flags classic prompt-hijacking vocabulary that attempts to override the host
agent's instructions ("ignore previous instructions", "you are now", role
prefixes like "system:" etc.). These phrases have no legitimate place in a
tool description; their appearance is the canonical signature of an indirect
prompt injection payload embedded in a tool spec.

References:
- Greshake et al., "Not what you've signed up for: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection", 2023.
- OWASP LLM Top 10, LLM01: Prompt Injection.
"""
import re

from ..base import Detector
from ...models import Finding, Severity, ToolInfo


_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(all\s+|the\s+)?previous\s+instructions",
        r"disregard\s+(all\s+|the\s+)?(previous\s+|prior\s+|above\s+)?instructions",
        r"you\s+are\s+now",
        r"forget\s+(everything|all\s+previous|what\s+i\s+told\s+you)",
        r"new\s+instructions:?",
        r"developer\s+mode",
        r"jailbreak",
        r"from\s+now\s+on",
        r"pretend\s+(to\s+be|you\s+are)",
        r"act\s+as\s+(if\s+you\s+are|a)",
        r"override\s+(the\s+|your\s+)?(system|safety|previous)",
        r"system\s*:",
        r"assistant\s*:",
    )
)


class InjectionPhrasesDetector(Detector):
    rule_id = "S1"
    severity = Severity.HIGH
    description = "Detects classic prompt-injection phrases that override agent instructions."

    _SUGGESTED_FIX = (
        "Tool description contains instruction-override language. Verify this "
        "is not a prompt injection attempt and have the server author remove "
        "directives aimed at LLMs."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        for field, text in tool.labelled_text_fields:
            if not text:
                continue
            for pattern in _INJECTION_PATTERNS:
                match = pattern.search(text)
                if match:
                    findings.append(
                        self._make_finding(
                            tool=tool,
                            field=field,
                            evidence=match.group(0),
                            message=(
                                f"Field '{field}' contains injection phrase "
                                f"'{match.group(0)}'."
                            ),
                            suggested_fix=self._SUGGESTED_FIX,
                        )
                    )
        return self._dedupe(findings)
