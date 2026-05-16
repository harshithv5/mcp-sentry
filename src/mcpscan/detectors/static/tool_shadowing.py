"""S7 — Tool-Shadowing / Impersonation Detector.

Flags tools whose name shadows a well-known privileged operation
(send_email, read_file, run_command, transfer_funds, …). Operates on the
tool name only.

Two severities:
- Exact match (case-insensitive) → HIGH.
- Levenshtein distance ≤ 2 from a known name (but not exact) → MEDIUM.
  This catches homoglyph / typo-squat names like 'send_emai1' or 'read_fle'
  that look benign in casual review but get auto-completed by an agent.

References:
- "Tool Squatting in MCP Marketplaces", 2025 community discussion.
"""
from ..base import Detector
from ...models import Finding, Severity, ToolInfo


DANGEROUS_NAMES: tuple[str, ...] = (
    "send_email", "send_mail", "sendmail",
    "read_file", "write_file", "delete_file",
    "execute_sql", "run_query", "exec_query",
    "run_command", "execute_command", "shell", "shell_exec",
    "transfer_funds", "make_payment", "process_payment",
    "delete_user", "remove_user", "drop_user",
    "eval", "exec",
    "list_secrets", "read_secret", "get_credentials",
    "post_message", "send_message", "broadcast",
)


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


class ToolShadowingDetector(Detector):
    rule_id = "S7"
    severity = Severity.HIGH  # default; fuzzy matches downgrade to MEDIUM
    description = "Detects tool names that shadow or impersonate known privileged operations."

    _SUGGESTED_FIX = (
        "Tool name shadows a common privileged operation. Verify this tool's "
        "behavior matches user expectations for tools with this name."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        name = tool.name.lower()

        if name in DANGEROUS_NAMES:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.HIGH,
                    tool_name=tool.name,
                    field="name",
                    evidence=tool.name,
                    message=f"Tool '{tool.name}' shadows known system tool '{name}'.",
                    suggested_fix=self._SUGGESTED_FIX,
                )
            )
            return findings

        for known in DANGEROUS_NAMES:
            distance = _levenshtein(name, known)
            if 0 < distance <= 2:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        tool_name=tool.name,
                        field="name",
                        evidence=f"{tool.name} ~ {known} (distance {distance})",
                        message=(
                            f"Tool '{tool.name}' is suspiciously similar to "
                            f"known system tool '{known}' (Levenshtein "
                            f"distance {distance})."
                        ),
                        suggested_fix=self._SUGGESTED_FIX,
                    )
                )

        return self._dedupe(findings)
