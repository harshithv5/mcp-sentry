"""D5 — Server-Side Request Forgery probe.

Sends URLs targeting cloud-instance metadata (169.254.169.254), loopback,
private RFC1918 ranges, and the `file://` scheme through any URL-shaped tool
parameter. The response is inspected for:

- cloud-metadata fingerprints     → CRITICAL, confirmed SSRF
- internal-service banners        → HIGH,     confirmed SSRF
- non-empty responses from loopback / private ranges → HIGH suspected
- file content via `file://`      → CRITICAL via D3 file-marker reuse
- connection-refused / timeout    → MEDIUM (attempted, not reached)

Tools with no URL-shaped parameter are skipped silently.

D5 actively probes attacker-controlled URLs against the target server, which
in adversarial environments can itself trigger downstream effects. It is gated
behind `--enable-ssrf` in the orchestrator.

References:
- OWASP, "A10:2021 Server-Side Request Forgery".
- CWE-918: Server-Side Request Forgery.
"""
import asyncio
import logging

from mcp import ClientSession

from ..base import DynamicDetector
from .path_traversal import _match_file_marker
from ...models import Finding, Severity, ToolInfo
from ...safety import (
    extract_response_text,
    generate_safe_inputs,
    inject_probe,
    looks_like_error,
    rate_limited_call,
)


logger = logging.getLogger(__name__)


URL_PARAM_NAMES: tuple[str, ...] = (
    "url", "uri", "endpoint", "host", "address",
    "link", "src", "source", "target", "fetch",
    "webhook", "callback",
)

PAYLOADS: dict[str, tuple[str, ...]] = {
    "cloud_metadata": (
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    ),
    "localhost": (
        "http://127.0.0.1:80",
        "http://127.0.0.1:8080",
        "http://localhost:6379",
        "http://localhost:5432",
    ),
    "private_network": (
        "http://10.0.0.1",
        "http://192.168.1.1",
    ),
    "scheme_abuse": (
        "file:///etc/passwd",
        "file:///etc/hostname",
    ),
}

CLOUD_MARKERS: tuple[str, ...] = (
    "ami-id", "instance-id", "security-credentials",
    "meta-data", "computemetadata",
)

SERVICE_MARKERS: tuple[str, ...] = (
    "+ok", "-err", "redis_version", "postgresql", "mongodb",
)


class SsrfProbeDetector(DynamicDetector):
    rule_id = "D5"
    severity = Severity.CRITICAL  # default; per-finding severity is set explicitly
    description = "Probes URL parameters for server-side request forgery."

    _SUGGESTED_FIX = (
        "Allow-list outbound destinations server-side. Reject loopback, "
        "RFC1918, link-local (169.254.0.0/16), and non-HTTP(S) schemes before "
        "issuing the request. Resolve hostnames before validation to defeat "
        "DNS rebinding."
    )

    async def check(self, tool: ToolInfo, session: ClientSession) -> list[Finding]:
        try:
            base = generate_safe_inputs(tool)
            findings: list[Finding] = []

            for category, payloads in PAYLOADS.items():
                for payload in payloads:
                    probed = inject_probe(
                        tool, base, payload,
                        target_param_type="string",
                        name_filter=URL_PARAM_NAMES,
                    )
                    if probed is None:
                        return []  # tool has no URL-like param; skip

                    result = await rate_limited_call(session, tool.name, probed)
                    if result is None:
                        continue

                    response = extract_response_text(result)
                    if not response:
                        continue

                    lowered = response.lower()
                    finding = self._classify(tool, category, payload, response, lowered)
                    if finding is None:
                        continue

                    if finding.severity == Severity.CRITICAL and finding.confirmed:
                        return [finding]
                    findings.append(finding)

            return self._dedupe(findings)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.debug("D5 skipped %s (transport): %s", tool.name, exc)
            return []
        except Exception as exc:
            logger.debug("D5 skipped %s (tool error): %s", tool.name, exc)
            return []

    def _classify(
        self,
        tool: ToolInfo,
        category: str,
        payload: str,
        response: str,
        lowered: str,
    ) -> Finding | None:
        if looks_like_error(lowered):
            if category in ("cloud_metadata", "localhost") and (
                "connection refused" in lowered or "timeout" in lowered
            ):
                return self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=f"Server attempted to reach '{payload}' (got {self._summarise_error(lowered)})",
                    message=(
                        f"Server attempted an outbound request to '{payload}' "
                        f"but the connection failed. The attempt itself "
                        f"confirms missing URL validation."
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=True,
                    severity=Severity.MEDIUM,
                )
            return None

        if category == "cloud_metadata":
            if any(marker in lowered for marker in CLOUD_MARKERS):
                return self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=f"Cloud-metadata fingerprint returned for '{payload}'",
                    message=(
                        f"Tool fetched cloud instance-metadata via '{payload}'. "
                        f"This typically exposes IAM credentials."
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=True,
                    severity=Severity.CRITICAL,
                )

        if category == "localhost":
            if any(marker in lowered for marker in SERVICE_MARKERS):
                return self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=f"Internal service banner returned for '{payload}'",
                    message=(
                        f"Tool reached an internal service at '{payload}'. "
                        f"Server allows outbound requests to loopback."
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=True,
                    severity=Severity.HIGH,
                )
            return self._make_finding(
                tool=tool,
                field="response",
                evidence=f"Non-empty response from loopback '{payload}'",
                message=(
                    f"Tool returned content when pointed at loopback URL "
                    f"'{payload}' — likely SSRF to a local service."
                ),
                suggested_fix=self._SUGGESTED_FIX,
                confirmed=True,
                severity=Severity.HIGH,
            )

        if category == "private_network":
            return self._make_finding(
                tool=tool,
                field="response",
                evidence=f"Non-empty response from private range '{payload}'",
                message=(
                    f"Tool returned content when pointed at RFC1918 address "
                    f"'{payload}'. Server allows outbound requests to private "
                    f"networks."
                ),
                suggested_fix=self._SUGGESTED_FIX,
                confirmed=True,
                severity=Severity.HIGH,
            )

        if category == "scheme_abuse":
            hit = _match_file_marker(response)
            if hit is not None:
                file_category, marker = hit
                return self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=(
                        f"File read via '{payload}' — returned {file_category} "
                        f"content containing '{marker}'"
                    ),
                    message=(
                        f"Tool dereferenced 'file://' scheme and returned local "
                        f"file content for '{payload}'."
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=True,
                    severity=Severity.CRITICAL,
                )

        return None

    @staticmethod
    def _summarise_error(lowered: str) -> str:
        for token in ("connection refused", "timeout", "timed out"):
            if token in lowered:
                return token
        return "error"
