"""Abstract base class for all static and dynamic detectors.

Subclasses set the three class-level attributes (rule_id, severity, description)
and override check(). The orchestrator drives every detector through this
uniform interface, so adding a new rule is a matter of dropping a new subclass
into detectors/static or detectors/dynamic.
"""
from abc import ABC, abstractmethod

from ..models import Finding, Severity, ToolInfo


class Detector(ABC):
    rule_id: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    is_server_level: bool = False  # True => orchestrator calls check_server(tools) instead of check(tool)

    @abstractmethod
    def check(self, tool: ToolInfo) -> list[Finding]:
        """Inspect a single tool and return any findings (empty list if clean)."""

    def _make_finding(
        self,
        tool: ToolInfo,
        field: str,
        evidence: str,
        message: str,
        suggested_fix: str,
    ) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            tool_name=tool.name,
            field=field,
            evidence=evidence,
            message=message,
            suggested_fix=suggested_fix,
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