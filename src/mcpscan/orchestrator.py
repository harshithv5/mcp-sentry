"""Scan orchestrator.

Connects to an MCP server, runs every static detector against every tool,
runs every server-level detector against the full tool list, scores the
result, and returns a fully populated ScanReport.
"""
import asyncio
from datetime import datetime

from .client import create_mcp_client, list_tools
from .detectors.base import Detector
from .detectors.static.hidden_unicode import HiddenUnicodeDetector
from .detectors.static.injection_phrases import InjectionPhrasesDetector
from .detectors.static.lethal_trifecta import LethalTrifectaDetector
from .detectors.static.schema_validator import SchemaValidatorDetector
from .detectors.static.secrecy_instructions import SecrecyInstructionsDetector
from .detectors.static.sensitive_paths import SensitivePathsDetector
from .detectors.static.suspicious_tags import SuspiciousTagsDetector
from .detectors.static.tool_shadowing import ToolShadowingDetector
from .models import Finding, ScanReport, Severity, ToolInfo


DETECTORS: list[Detector] = [
    SensitivePathsDetector(),
    InjectionPhrasesDetector(),
    SuspiciousTagsDetector(),
    SecrecyInstructionsDetector(),
    HiddenUnicodeDetector(),
    ToolShadowingDetector(),
    SchemaValidatorDetector(),
    LethalTrifectaDetector(),
]

# Score deducted per finding, by severity. Score floors at 0.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


def _grade_for(score: int) -> str:
    if score >= 95:
        return "A+"
    if score >= 85:
        return "A"
    if score >= 75:
        return "B"
    if score >= 65:
        return "C"
    if score >= 55:
        return "D"
    return "F"


def _score(findings: list[Finding]) -> tuple[int, str]:
    deduction = sum(SEVERITY_WEIGHTS[f.severity] for f in findings)
    score = max(0, 100 - deduction)
    return score, _grade_for(score)


def _run_detectors(tools: list[ToolInfo]) -> list[Finding]:
    findings: list[Finding] = []
    for detector in DETECTORS:
        if detector.is_server_level:
            findings.extend(detector.check_server(tools))  # type: ignore[attr-defined]
        else:
            for tool in tools:
                findings.extend(detector.check(tool))
    return findings


async def build_report(target_url: str) -> ScanReport:
    started = datetime.now()
    async with create_mcp_client(url=target_url) as session:
        tools = await list_tools(session)

    findings = _run_detectors(tools)
    score, grade = _score(findings)
    elapsed_ms = int((datetime.now() - started).total_seconds() * 1000)

    return ScanReport(
        target_url=target_url,
        tool_count=len(tools),
        findings=findings,
        score=score,
        grade=grade,
        scan_duration_ms=elapsed_ms,
    )


if __name__ == "__main__":
    import sys

    from .reporter.markdown import render_markdown

    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000/mcp"
    report = asyncio.run(build_report(url))
    print(render_markdown(report))
