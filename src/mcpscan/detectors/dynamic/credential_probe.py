"""D4 — Credential & Information Disclosure Probe.

Sends two flavours of probe through a tool's string parameters:

1. Template-injection payloads (`${OPENAI_API_KEY}`, `{{config.secret}}`,
   `${7*7}`) — to see whether the server unsafely interpolates user input
   against its environment or templating engine.
2. Error-triggering payloads (empty string, oversized string, lone apostrophe)
   — to surface stack traces, internal file paths, and other server-internals
   that leak into error responses.

Both response bodies are scanned for live credential material (API keys,
private keys, connection strings, JWTs) and for generic information-disclosure
markers (Python tracebacks, /home/, /var/www/, ...). Credential matches are
REDACTED in the evidence string — the scanner must never store actual secrets.

References:
- OWASP, "A04:2021 Insecure Design" / "A05:2021 Security Misconfiguration".
- CWE-209: Information Exposure Through an Error Message.
- CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine.
"""
import asyncio
import logging
import re

from mcp import ClientSession

from ..base import DynamicDetector
from ...models import Finding, Severity, ToolInfo
from ...safety import (
    extract_response_text,
    generate_safe_inputs,
    inject_probe,
    rate_limited_call,
)


logger = logging.getLogger(__name__)


TEMPLATE_PAYLOADS: tuple[str, ...] = (
    "${OPENAI_API_KEY}",
    "${SECRET_KEY}",
    "${DATABASE_URL}",
    "${HOME}",
    "${AWS_ACCESS_KEY_ID}",
    "{{env.OPENAI_API_KEY}}",
    "{{config.secret}}",
    "${7*7}",
)

ERROR_PAYLOADS: tuple[str, ...] = ("", "A" * 10000, "'")


CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"sk-ant-[a-zA-Z0-9_\-]{20,}"), "Anthropic API key"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "AWS access key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub PAT"),
    (re.compile(r"xox[bpras]-[a-zA-Z0-9\-]+"), "Slack token"),
    (
        re.compile(r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
        "JWT token",
    ),
    (re.compile(r"-----BEGIN[\w ]*PRIVATE KEY-----"), "Private key"),
    (re.compile(r"Bearer [a-zA-Z0-9\-._~+/]+=*"), "Bearer token"),
    (re.compile(r"postgres(?:ql)?://\S+"), "Postgres connection string"),
    (re.compile(r"mongodb(?:\+srv)?://\S+"), "MongoDB connection string"),
    (re.compile(r"redis://\S+"), "Redis connection string"),
)


DISCLOSURE_PATTERNS: tuple[tuple[re.Pattern[str], str, Severity], ...] = (
    (
        re.compile(r"Traceback \(most recent call last\)"),
        "Python stack trace",
        Severity.HIGH,
    ),
    (
        re.compile(r'File "[^"]+", line \d+'),
        "Python file path in error",
        Severity.HIGH,
    ),
    (re.compile(r"/home/\w+/"), "User home directory path", Severity.MEDIUM),
    (re.compile(r"/var/www/"), "Web server path", Severity.MEDIUM),
    (re.compile(r"/app/\w+"), "Application path", Severity.MEDIUM),
)


def _redact(secret: str) -> str:
    prefix = secret[:6] if len(secret) >= 6 else secret[: max(1, len(secret) - 1)]
    return f"{prefix}...REDACTED"


class CredentialProbeDetector(DynamicDetector):
    rule_id = "D4"
    severity = Severity.CRITICAL  # default; per-finding severity is set explicitly
    description = "Probes tools for credential leakage and information disclosure."

    _CRED_FIX = (
        "Never interpolate user input against server environment or template "
        "engines. Scrub responses for secret-shaped substrings before returning."
    )
    _DISCLOSURE_FIX = (
        "Catch exceptions server-side and return generic error messages. Never "
        "expose stack traces, file paths, or internal hostnames to clients."
    )
    _TEMPLATE_FIX = (
        "Server is evaluating expressions inside user input. Treat all "
        "parameters as inert data — do not pass them through eval, format, or "
        "any templating engine."
    )

    async def check(self, tool: ToolInfo, session: ClientSession) -> list[Finding]:
        try:
            base = generate_safe_inputs(tool)
            findings: list[Finding] = []

            for payload in TEMPLATE_PAYLOADS:
                probed = inject_probe(tool, base, payload, target_param_type="string")
                if probed is None:
                    return []  # no string param; nothing to probe

                result = await rate_limited_call(session, tool.name, probed)
                if result is None:
                    continue
                response = extract_response_text(result)
                if not response:
                    continue

                if payload == "${7*7}" and "49" in response and "49" not in str(base):
                    findings.append(
                        self._make_finding(
                            tool=tool,
                            field="response",
                            evidence=f"Payload '{payload}' evaluated to 49",
                            message=(
                                "Server evaluated a template expression inside "
                                "user input — strong indicator of unsafe "
                                "interpolation."
                            ),
                            suggested_fix=self._TEMPLATE_FIX,
                            confirmed=True,
                            severity=Severity.MEDIUM,
                        )
                    )

                cred_finding = self._scan_credentials(tool, response, payload)
                if cred_finding is not None:
                    findings.append(cred_finding)
                    return self._dedupe(findings)

                findings.extend(self._scan_disclosure(tool, response, payload))

            for payload in ERROR_PAYLOADS:
                probed = inject_probe(tool, base, payload, target_param_type="string")
                if probed is None:
                    continue
                result = await rate_limited_call(session, tool.name, probed)
                if result is None:
                    continue
                response = extract_response_text(result)
                if not response:
                    continue

                label = payload if payload else "<empty>"
                if len(label) > 16:
                    label = f"{label[:8]}...({len(payload)} chars)"

                cred_finding = self._scan_credentials(tool, response, label)
                if cred_finding is not None:
                    findings.append(cred_finding)
                    return self._dedupe(findings)

                findings.extend(self._scan_disclosure(tool, response, label))

            return self._dedupe(findings)
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.debug("D4 skipped %s (transport): %s", tool.name, exc)
            return []
        except Exception as exc:
            logger.debug("D4 skipped %s (tool error): %s", tool.name, exc)
            return []

    def _scan_credentials(
        self, tool: ToolInfo, response: str, payload_label: str
    ) -> Finding | None:
        for pattern, label in CREDENTIAL_PATTERNS:
            match = pattern.search(response)
            if not match:
                continue
            return self._make_finding(
                tool=tool,
                field="response",
                evidence=f"{label}: {_redact(match.group(0))} (probe: {payload_label})",
                message=(
                    f"Tool response leaked a live secret matching pattern for "
                    f"{label}. Probe payload was '{payload_label}'."
                ),
                suggested_fix=self._CRED_FIX,
                confirmed=True,
                severity=Severity.CRITICAL,
            )
        return None

    def _scan_disclosure(
        self, tool: ToolInfo, response: str, payload_label: str
    ) -> list[Finding]:
        out: list[Finding] = []
        for pattern, label, sev in DISCLOSURE_PATTERNS:
            match = pattern.search(response)
            if not match:
                continue
            out.append(
                self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=f"{label}: '{match.group(0)}' (probe: {payload_label})",
                    message=(
                        f"Tool response exposed {label} when probed with "
                        f"'{payload_label}' — information disclosure."
                    ),
                    suggested_fix=self._DISCLOSURE_FIX,
                    confirmed=True,
                    severity=sev,
                )
            )
        return out
