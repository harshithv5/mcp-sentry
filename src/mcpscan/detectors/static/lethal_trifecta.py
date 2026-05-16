"""S10 — Lethal Trifecta Detector (server-level).

A server exposes the "Lethal Trifecta" (Simon Willison, 2025) when it offers
tools spanning all three of:

- PRIVATE_DATA      — read access to the user's data (files, email, DBs, secrets).
- UNTRUSTED_CONTENT — pulls content from the open web or other untrusted sources.
- EXTERNAL_COMM     — sends data outbound (email, HTTP POST, messaging APIs).

An attacker plants a prompt-injection payload in the untrusted content; the
LLM follows it, reads the private data, and exfiltrates via the external
communication tool. The combination is the exploit; any one tool in
isolation is benign.

This detector is server-level: it inspects the full set of tools, not one
tool at a time. The orchestrator must call `check_server`; the standard
per-tool `check` is a no-op.

References:
- Simon Willison, "The Lethal Trifecta for AI Agents", 2025.
"""
from ..base import Detector
from ...models import Finding, Severity, ToolInfo


_PRIVATE_DATA = (
    "read", "list", "get", "fetch", "load", "open",
    "file", "database", "secret", "key", "credential",
    "email", "calendar", "message",
)
_UNTRUSTED_CONTENT = (
    "fetch_url", "browse", "scrape", "read_url", "download",
    "search_web", "rss",
)
_EXTERNAL_COMM = (
    "send_email", "send_message", "post", "tweet", "publish",
    "webhook", "http_post", "send_sms", "call_api",
)


def _matches_any(text: str, keywords: tuple[str, ...]) -> bool:
    return any(kw in text for kw in keywords)


class LethalTrifectaDetector(Detector):
    rule_id = "S10"
    severity = Severity.CRITICAL
    description = "Detects servers exposing the Lethal Trifecta (private data + untrusted content + external comm)."
    is_server_level = True

    _SUGGESTED_FIX = (
        "Server combines all three components of the Lethal Trifecta "
        "(Willison, 2025). A malicious actor can use the untrusted content "
        "tool to inject prompts that exfiltrate private data via the "
        "external communication tool. Remove or sandbox one leg of the "
        "trifecta — typically the external communication tool."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        # S10 is server-level; per-tool check is a no-op.
        return []

    def check_server(self, tools: list[ToolInfo]) -> list[Finding]:
        priv: list[str] = []
        untrusted: list[str] = []
        external: list[str] = []

        for tool in tools:
            haystack = (tool.name + " " + (tool.description or "")).lower()
            if _matches_any(haystack, _PRIVATE_DATA):
                priv.append(tool.name)
            if _matches_any(haystack, _UNTRUSTED_CONTENT):
                untrusted.append(tool.name)
            if _matches_any(haystack, _EXTERNAL_COMM):
                external.append(tool.name)

        if not (priv and untrusted and external):
            return []

        evidence = (
            f"PRIVATE_DATA: {priv}; "
            f"UNTRUSTED_CONTENT: {untrusted}; "
            f"EXTERNAL_COMM: {external}"
        )
        return [
            Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                tool_name="<server-level>",
                field="server",
                evidence=evidence,
                message=(
                    "Server exposes the Lethal Trifecta: tools covering "
                    "private-data access, untrusted-content ingestion, and "
                    "external communication can be chained for data "
                    "exfiltration via prompt injection."
                ),
                suggested_fix=self._SUGGESTED_FIX,
            )
        ]
