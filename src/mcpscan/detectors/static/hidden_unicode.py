"""S3 — Hidden / Invisible Unicode Detector.

Flags non-printable or invisible Unicode characters embedded in tool fields:
zero-width spaces, bidirectional overrides, the Unicode tag block (U+E0000…),
and variation selectors. Attackers use these to smuggle instructions past
human review while leaving the LLM's tokenizer to interpret them normally.

Categories:
- zero-width:          U+200B U+200C U+200D U+2060 U+FEFF
- directional-override: U+202A-U+202E, U+2066-U+2069
- unicode-tag:         U+E0000-U+E007F (recent jailbreak vector)
- variation-selector:  U+FE00-U+FE0F

Findings are aggregated to one per (field, category) with a count, so a string
containing 50 zero-width spaces produces one finding, not 50.

References:
- Riley Goodside, "Unicode tag-block prompt injection", 2024.
- "Trojan Source" (Boucher & Anderson, 2021) — bidirectional override abuse.
"""
import unicodedata

from ..base import Detector
from ..patterns import categorize_hidden_codepoint
from ...models import Finding, Severity, ToolInfo


class HiddenUnicodeDetector(Detector):
    rule_id = "S3"
    severity = Severity.CRITICAL
    description = "Detects invisible Unicode characters used to smuggle hidden content."

    _SUGGESTED_FIX = (
        "Field contains invisible Unicode characters. Strip non-printable "
        "characters from tool descriptions or reject this server."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        for field, text in tool.labelled_text_fields:
            if not text:
                continue
            buckets: dict[str, list[tuple[int, int]]] = {}  # category -> [(pos, codepoint)]
            for i, char in enumerate(text):
                cat = categorize_hidden_codepoint(ord(char))
                if cat is None:
                    continue
                buckets.setdefault(cat, []).append((i, ord(char)))

            for category, hits in buckets.items():
                count = len(hits)
                first_pos, first_cp = hits[0]
                name = unicodedata.name(chr(first_cp), "UNKNOWN")
                evidence = (
                    f"{count}x {category} (first: {name} (U+{first_cp:04X}) "
                    f"at position {first_pos})"
                )
                findings.append(
                    self._make_finding(
                        tool=tool,
                        field=field,
                        evidence=evidence,
                        message=(
                            f"Field '{field}' contains {count} invisible "
                            f"'{category}' character(s)."
                        ),
                        suggested_fix=self._SUGGESTED_FIX,
                    )
                )
        return self._dedupe(findings)
