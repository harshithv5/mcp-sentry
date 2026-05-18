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
from .detectors.dynamic.credential_probe import CredentialProbeDetector
from .detectors.dynamic.echo_test import EchoTestDetector
from .detectors.dynamic.path_traversal import PathTraversalDetector
from .detectors.dynamic.response_injection import ResponseInjectionDetector
from .detectors.dynamic.ssrf_probe import SsrfProbeDetector
from .detectors.semantic.llm_judge import LLMJudgeDetector
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
    PathTraversalDetector(),
    CredentialProbeDetector(),
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


async def _run_dynamic(
    tools: list[ToolInfo],
    session: ClientSession,
    *,
    enable_ssrf: bool = False,
) -> list[Finding]:
    findings: list[Finding] = []
    ssrf_detector = SsrfProbeDetector() if enable_ssrf else None
    for tool in tools:
        if classify_tool(tool) == "destructive":
            continue
        for detector in DYNAMIC_DETECTORS:
            findings.extend(await detector.check(tool, session))
        if ssrf_detector is not None:
            findings.extend(await ssrf_detector.check(tool, session))
    return findings


async def _run_semantic(
    tools: list[ToolInfo],
    *,
    groq_api_key: str,
    threshold: float = 0.7,
) -> list[Finding]:
    """Phase 2 — semantic LLM judge. Off unless an API key is supplied."""
    judge = LLMJudgeDetector(groq_api_key, threshold=threshold)
    findings: list[Finding] = []
    for tool in tools:
        findings.extend(await judge.check(tool))
    return findings


async def build_report(
    target_url: str,
    *,
    skip_dynamic: bool = False,
    enable_ssrf: bool = False,
    enable_llm_judge: bool = False,
    groq_api_key: str | None = None,
    judge_threshold: float = 0.7,
) -> ScanReport:
    started = datetime.now()
    async with create_mcp_client(url=target_url) as session:
        tools = await list_tools(session)
        findings = _run_static(tools)
        if enable_llm_judge and groq_api_key:
            findings.extend(
                await _run_semantic(
                    tools,
                    groq_api_key=groq_api_key,
                    threshold=judge_threshold,
                )
            )
        if not skip_dynamic:
            findings.extend(await _run_dynamic(tools, session, enable_ssrf=enable_ssrf))

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


# if __name__ == "__main__":
#     import sys
#
#     from .reporter.markdown import render_markdown
#
#     args = sys.argv[1:]
#     skip_dynamic = "--skip-dynamic" in args
#     enable_ssrf = "--enable-ssrf" in args
#     args = [a for a in args if a not in ("--skip-dynamic", "--enable-ssrf")]
#     url = args[0] if args else "https://mcp.deepwiki.com/mcp"
#
#     report = asyncio.run(
#         build_report(url, skip_dynamic=skip_dynamic, enable_ssrf=enable_ssrf)
#     )
#     print(render_markdown(report))