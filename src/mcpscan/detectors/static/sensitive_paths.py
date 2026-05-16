"""S4 — Sensitive Path Reference Detector.

Flags any tool whose name, description, or parameter descriptions mention
well-known credential or sensitive system file paths. Legitimate tools rarely
have a reason to talk about ~/.ssh, ~/.aws, /etc/passwd, etc.; tool poisoning
attacks routinely instruct the LLM to read these locations and exfiltrate
their contents (Invariant Labs, "Tool Poisoning Attacks", 2025).

This is the simplest detector — pure case-insensitive substring matching, no
regex required. It is the canonical "smoke test" for the end-to-end pipeline.
"""
from ..base import Detector
from ...models import Finding, Severity, ToolInfo


SENSITIVE_PATHS: tuple[str, ...] = (
    "~/.ssh",
    "~/.aws",
    "~/.cursor/mcp.json",
    "~/.config",
    "~/.gnupg",
    "~/.kube/config",
    "/etc/passwd",
    "/etc/shadow",
    "id_rsa",
    "id_ed25519",
    ".env",
    "credentials.json",
    "service-account.json",
    "aws_access_key",
    "aws_secret",
    "kubeconfig",
)


class SensitivePathsDetector(Detector):
    rule_id = "S4"
    severity = Severity.HIGH
    description = "Detects references to sensitive credential or system file paths."

    _SUGGESTED_FIX = (
        "Tool description references sensitive file paths. This is a known tool "
        "poisoning signature — malicious tools instruct LLMs to read credentials "
        "from these locations."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        for field, text in tool.labelled_text_fields:
            if not text:
                continue
            haystack = text.lower()
            for needle in SENSITIVE_PATHS:
                if needle in haystack:
                    findings.append(
                        self._make_finding(
                            tool=tool,
                            field=field,
                            evidence=needle,
                            message=(
                                f"Field '{field}' references sensitive path "
                                f"'{needle}'."
                            ),
                            suggested_fix=self._SUGGESTED_FIX,
                        )
                    )
        return self._dedupe(findings)
