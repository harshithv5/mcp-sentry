"""Shared regex pattern banks used by both static and dynamic detectors.

Static detectors run these against tool metadata (name/description/params).
Dynamic detectors run them against live tool responses. Keeping the patterns
in one place means a new injection phrase added here is picked up everywhere
at once.

Banks:
- INJECTION_PATTERNS : prompt-hijacking phrases (S1, D2)
- TAG_PATTERNS       : hidden instruction markup (S2, D2)
- SECRECY_PATTERNS   : "don't tell the user" directives (S5, D2)
- categorize_hidden_codepoint : invisible-Unicode classifier (S3, D2)
"""
import re


# --- Injection phrases (S1, D2) -------------------------------------------
INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
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


# --- Hidden instruction tags (S2, D2) -------------------------------------
TAG_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        r"<\s*important\s*>.*?<\s*/\s*important\s*>",
        r"<\s*system\s*>.*?<\s*/\s*system\s*>",
        r"<\s*instructions?\s*>.*?<\s*/\s*instructions?\s*>",
        r"<\s*admin\s*>.*?<\s*/\s*admin\s*>",
        r"<\s*hidden\s*>.*?<\s*/\s*hidden\s*>",
        r"<\s*secret\s*>.*?<\s*/\s*secret\s*>",
        r"<\s*internal\s*>.*?<\s*/\s*internal\s*>",
        r"\[INST\].*?\[/INST\]",
        r"<<SYS>>.*?<</SYS>>",
    )
)


# --- Secrecy / concealment instructions (S5, D2) --------------------------
SECRECY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
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


# --- Invisible / hidden Unicode (S3, D2) ----------------------------------
_ZERO_WIDTH: set[int] = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}


def categorize_hidden_codepoint(codepoint: int) -> str | None:
    """Return a category label for invisible codepoints, or None if printable."""
    if codepoint in _ZERO_WIDTH:
        return "zero-width"
    if 0x202A <= codepoint <= 0x202E or 0x2066 <= codepoint <= 0x2069:
        return "directional-override"
    if 0xE0000 <= codepoint <= 0xE007F:
        return "unicode-tag"
    if 0xFE00 <= codepoint <= 0xFE0F:
        return "variation-selector"
    return None
