"""S5 — Secrecy / Concealment Instruction Detector.

Flags tool descriptions that direct the model to hide information from the
user — "do not mention", "silently", "without telling the user", etc.
If a tool description instructs the LLM to conceal something, there is
essentially no legitimate use case; this is the defining mark of a malicious
or backdoored tool.

References:
- Invariant Labs, "Tool Poisoning Attacks", 2025 (specifically the
  "concealment instructions" sub-pattern).
"""
import re

from ..base import Detector
from ...models import Finding, Severity, ToolInfo


_SECRECY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"do(?:\s+not|n[’‘']?t)\s+(mention|tell|inform|reveal|show)",
        r"without\s+(telling|informing|asking|notifying)\s+(the\s+)?(user|human)",
        r"(silently|secretly|covertly|stealthily)",
        r"(the\s+)?user\s+(should\s+not|must\s+not|cannot)\s+(see|know|be\s+told)",
        r"keep\s+this\s+(secret|hidden|confidential|private)",
        r"under\s+no\s+circumstances\s+(should\s+you|tell|mention|inform)",
        r"before\s+(responding|replying|answering)(\s+to)?(\s+the)?\s+user",
        r"do\s+not\s+include\s+this\s+in\s+(your|the)\s+(response|reply|answer)",
    )
)


class SecrecyInstructionsDetector(Detector):
    rule_id = "S5"
    severity = Severity.CRITICAL
    description = "Detects instructions that tell the LLM to conceal information from the user."

    _SUGGESTED_FIX = (
        "Tool description instructs the LLM to conceal information from the "
        "user. There is no legitimate use case for this pattern — treat this "
        "server as malicious."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        for field, text in tool.labelled_text_fields:
            if not text:
                continue
            for pattern in _SECRECY_PATTERNS:
                match = pattern.search(text)
                if match:
                    findings.append(
                        self._make_finding(
                            tool=tool,
                            field=field,
                            evidence=match.group(0),
                            message=(
                                f"Field '{field}' contains secrecy directive "
                                f"'{match.group(0)}'."
                            ),
                            suggested_fix=self._SUGGESTED_FIX,
                        )
                    )
        return self._dedupe(findings)
