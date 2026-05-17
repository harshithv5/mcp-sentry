"""Scan orchestrator.

Two phases against one MCP session:

1. Static phase  — every static detector runs against every tool's metadata.
                   Server-level static detectors run once over the full list.
2. Dynamic phase — every dynamic detector runs against every *safe* tool by
                   actually invoking it. Tools classified as destructive are
                   skipped. Pass `skip_dynamic=True` to bypass this phase.

The final ScanReport carries the merged findings, a 0–100 score, and a grade.
"""
import asyncio
from datetime import datetime

from mcp import ClientSession

from .client import create_mcp_client, list_tools
from .detectors.base import Detector, DynamicDetector
from .detectors.dynamic.echo_test import EchoTestDetector
from .detectors.dynamic.response_injection import ResponseInjectionDetector
from .detectors.static.hidden_unicode import HiddenUnicodeDetector
from .detectors.static.injection_phrases import InjectionPhrasesDetector
from .detectors.static.lethal_trifecta import LethalTrifectaDetector
from .detectors.static.schema_validator import SchemaValidatorDetector
from .detectors.static.secrecy_instructions import SecrecyInstructionsDetector
from .detectors.static.sensitive_paths import SensitivePathsDetector
from .detectors.static.suspicious_tags import SuspiciousTagsDetector
from .detectors.static.tool_shadowing import ToolShadowingDetector
from .models import Finding, ScanReport, Severity, ToolInfo
from .safety import classify_tool


STATIC_DETECTORS: list[Detector] = [
    SensitivePathsDetector(),
    InjectionPhrasesDetector(),
    SuspiciousTagsDetector(),
    SecrecyInstructionsDetector(),
    HiddenUnicodeDetector(),
    ToolShadowingDetector(),
    SchemaValidatorDetector(),
    LethalTrifectaDetector(),
]

DYNAMIC_DETECTORS: list[DynamicDetector] = [
    EchoTestDetector(),
    ResponseInjectionDetector(),
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


def _run_static(tools: list[ToolInfo]) -> list[Finding]:
    findings: list[Finding] = []
    for detector in STATIC_DETECTORS:
        if detector.is_server_level:
            findings.extend(detector.check_server(tools))  # type: ignore[attr-defined]
        else:
            for tool in tools:
                findings.extend(detector.check(tool))
    return findings


async def _run_dynamic(tools: list[ToolInfo], session: ClientSession) -> list[Finding]:
    findings: list[Finding] = []
    for tool in tools:
        if classify_tool(tool) == "destructive":
            continue
        for detector in DYNAMIC_DETECTORS:
            findings.extend(await detector.check(tool, session))
    return findings


async def build_report(target_url: str, *, skip_dynamic: bool = False) -> ScanReport:
    started = datetime.now()
    async with create_mcp_client(url=target_url) as session:
        tools = await list_tools(session)
        findings = _run_static(tools)
        if not skip_dynamic:
            findings.extend(await _run_dynamic(tools, session))

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

    args = sys.argv[1:]
    skip_dynamic = "--skip-dynamic" in args
    args = [a for a in args if a != "--skip-dynamic"]
    url = args[0] if args else "https://mcp.deepwiki.com/mcp"

    report = asyncio.run(build_report(url, skip_dynamic=skip_dynamic))
    print(render_markdown(report))