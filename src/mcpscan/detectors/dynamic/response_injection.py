"""D2 — Response Injection detector.

Invokes a tool with safe inputs and inspects the response for prompt-injection
payloads, hidden instruction markup, secrecy directives, invisible Unicode,
and exfiltration vectors (markdown image links to known data-egress endpoints,
oversized base64 blobs, ngrok/webhook.site/requestbin/pipedream URLs).

A server can pass every static check yet still embed malicious instructions in
its responses at runtime — that is exactly what D2 catches. Findings are
confirmed=True because the live response is the evidence.

References:
- Invariant Labs, "Tool Poisoning Attacks", 2025.
- Simon Willison, "Markdown image exfiltration", 2023.
- Greshake et al., "Indirect Prompt Injection", 2023.
"""
import asyncio
import logging
import re
import unicodedata
from mcp import ClientSession
from ..base import DynamicDetector
from ..patterns import (
    INJECTION_PATTERNS,
    SECRECY_PATTERNS,
    TAG_PATTERNS,
    categorize_hidden_codepoint,
)
from ...models import Finding, Severity, ToolInfo
from ...safety import (
    extract_response_text,
    generate_safe_inputs,
    rate_limited_call,
)


logger = logging.getLogger(__name__)

_EVIDENCE_MAX = 200

# Known data-exfiltration endpoints — present in URLs that almost always
# indicate an attacker callback rather than a legitimate tool response.
_EXFIL_DOMAIN_RE = (
    r"(?:ngrok\.io|ngrok-free\.app|webhook\.site|requestbin\.(?:com|net)"
    r"|requestcatcher\.com|pipedream\.(?:com|net)|beeceptor\.com|burpcollaborator\.net)"
)

_MARKDOWN_IMAGE_EXFIL = re.compile(
    rf"!\[[^\]]*\]\(https?://[^\s)]*{_EXFIL_DOMAIN_RE}[^\s)]*\)",
    re.IGNORECASE,
)

_EXFIL_URL = re.compile(
    rf"https?://[^\s)\"']*{_EXFIL_DOMAIN_RE}[^\s)\"']*",
    re.IGNORECASE,
)

# Base64-looking run of 100+ chars. Long enough to skip random tokens / hashes
# but short enough to catch hidden instruction payloads.
_BASE64_BLOCK = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")


def _truncate(text: str) -> str:
    text = text.replace("\n", " ").replace("`", "'")
    if len(text) <= _EVIDENCE_MAX:
        return text
    return text[:_EVIDENCE_MAX] + "..."


class ResponseInjectionDetector(DynamicDetector):
    rule_id = "D2"
    severity = Severity.CRITICAL
    description = "Detects prompt injection payloads hidden in tool responses."

    _SUGGESTED_FIX = (
        "Audit server-side response generation. Tool responses must contain "
        "only data relevant to the tool's purpose. Remove all LLM-directed "
        "instructions, hidden markup, and exfiltration links from response "
        "content."
    )

    async def check(self, tool: ToolInfo, session: ClientSession) -> list[Finding]:
        try:
            safe_inputs = generate_safe_inputs(tool)

            result = await rate_limited_call(session, tool.name, safe_inputs)
            if result is None:
                return []  # timeout — skip cleanly

            response_text = extract_response_text(result)
            if not response_text:
                return []

            findings: list[Finding] = []
            findings.extend(self._scan_regex_bank(tool, response_text, INJECTION_PATTERNS, "injection-phrase"))
            findings.extend(self._scan_regex_bank(tool, response_text, TAG_PATTERNS, "hidden-tag"))
            findings.extend(self._scan_regex_bank(tool, response_text, SECRECY_PATTERNS, "secrecy-directive"))
            findings.extend(self._scan_unicode(tool, response_text))
            findings.extend(self._scan_regex_bank(tool, response_text, (_MARKDOWN_IMAGE_EXFIL,), "markdown-image-exfil"))
            findings.extend(self._scan_regex_bank(tool, response_text, (_EXFIL_URL,), "exfil-url"))
            findings.extend(self._scan_regex_bank(tool, response_text, (_BASE64_BLOCK,), "base64-blob"))

            return self._dedupe(findings)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.debug("D2 skipped %s (transport): %s", tool.name, exc)
            return []
        except Exception as exc:
            logger.debug("D2 skipped %s (tool error): %s", tool.name, exc)
            return []

    def _scan_regex_bank(
        self,
        tool: ToolInfo,
        text: str,
        patterns: tuple[re.Pattern[str], ...],
        category: str,
    ) -> list[Finding]:
        out: list[Finding] = []
        for pattern in patterns:
            match = pattern.search(text)
            if not match:
                continue
            out.append(
                self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=f"[{category}] {_truncate(match.group(0))}",
                    message=(
                        f"Tool response contains {category} payload "
                        f"'{_truncate(match.group(0))}'. Server passed static "
                        f"analysis but emits malicious content at runtime."
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=True,
                )
            )
        return out

    def _scan_unicode(self, tool: ToolInfo, text: str) -> list[Finding]:
        buckets: dict[str, list[tuple[int, int]]] = {}
        for i, char in enumerate(text):
            cat = categorize_hidden_codepoint(ord(char))
            if cat is None:
                continue
            buckets.setdefault(cat, []).append((i, ord(char)))

        out: list[Finding] = []
        for category, hits in buckets.items():
            count = len(hits)
            first_pos, first_cp = hits[0]
            name = unicodedata.name(chr(first_cp), "UNKNOWN")
            evidence = (
                f"[hidden-unicode/{category}] {count}x (first: {name} "
                f"(U+{first_cp:04X}) at position {first_pos})"
            )
            out.append(
                self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=evidence,
                    message=(
                        f"Tool response contains {count} invisible "
                        f"'{category}' character(s) — likely smuggled "
                        f"instructions invisible to human review."
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=True,
                )
            )
        return out
