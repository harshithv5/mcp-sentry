"""Abstract base classes for static, server-level, and dynamic detectors.

Three concrete shapes share a small set of helpers (`_make_finding`, `_dedupe`)
and metadata fields (rule_id, severity, description):

- `Detector`        — sync, per-tool inspection of static metadata.
- `DynamicDetector` — async, per-tool, calls the tool via an MCP session.

Server-level static detectors (e.g. S10 Lethal Trifecta) still inherit from
`Detector`, set `is_server_level = True`, and implement `check_server(tools)`
instead of `check(tool)`. The orchestrator dispatches on `is_server_level`.
"""
from abc import ABC, abstractmethod

from mcp import ClientSession

from ..models import Finding, Severity, ToolInfo


class _BaseDetector(ABC):
    rule_id: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    is_server_level: bool = False

    def _make_finding(
        self,
        tool: ToolInfo,
        field: str,
        evidence: str,
        message: str,
        suggested_fix: str,
        confirmed: bool = False,
        severity: Severity | None = None,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=severity if severity is not None else self.severity,
            tool_name=tool.name,
            field=field,
            evidence=evidence,
            message=message,
            suggested_fix=suggested_fix,
            confirmed=confirmed,
        )

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.tool_name, f.field, f.evidence)
            if key in seen:
                continue
            seen.add(key)
            unique.append(f)
        return unique


class Detector(_BaseDetector):
    """Sync detector: inspects a single tool's static metadata."""

    @abstractmethod
    def check(self, tool: ToolInfo) -> list[Finding]:
        """Inspect *tool* and return any findings (empty list if clean)."""


class DynamicDetector(_BaseDetector):
    """Async detector: actually invokes the tool on the live MCP session."""

    @abstractmethod
    async def check(self, tool: ToolInfo, session: ClientSession) -> list[Finding]:
        """Probe *tool* on *session* and return any findings (empty list if clean)."""
