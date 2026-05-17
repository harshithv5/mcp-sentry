"""S2 — Hidden Instruction Tag Detector.

Flags XML-style or model-specific instruction blocks embedded in tool
descriptions (<important>, <system>, <instructions>, [INST]…[/INST],
<<SYS>>…<</SYS>>, etc.). LLMs parse these as command markers while human
reviewers tend to skim over them. This is the canonical tool poisoning
pattern documented by Invariant Labs.

References:
- Invariant Labs, "Tool Poisoning Attacks", 2025.
- Llama / Mistral instruction-format documentation ([INST], <<SYS>>).
"""
from ..base import Detector
from ..patterns import TAG_PATTERNS
from ...models import Finding, Severity, ToolInfo


_EVIDENCE_MAX = 200


class SuspiciousTagsDetector(Detector):
    rule_id = "S2"
    severity = Severity.CRITICAL
    description = "Detects hidden instruction markup (XML or model-specific) inside tool fields."

    _SUGGESTED_FIX = (
        "Tool field contains hidden instruction markup that LLMs will "
        "interpret as commands. This is the canonical tool poisoning pattern "
        "(Invariant Labs, 2025)."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        for field, text in tool.labelled_text_fields:
            if not text:
                continue
            for pattern in TAG_PATTERNS:
                match = pattern.search(text)
                if match:
                    raw = match.group(0)
                    evidence = raw[:_EVIDENCE_MAX] + ("…" if len(raw) > _EVIDENCE_MAX else "")
                    findings.append(
                        self._make_finding(
                            tool=tool,
                            field=field,
                            evidence=evidence,
                            message=(
                                f"Field '{field}' contains hidden instruction "
                                f"block matching pattern '{pattern.pattern}'."
                            ),
                            suggested_fix=self._SUGGESTED_FIX,
                        )
                    )
        return self._dedupe(findings)
