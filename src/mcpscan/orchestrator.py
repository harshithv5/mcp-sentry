"""Scan orchestrator.

Two phases against one MCP session:

1. Static phase  — every static detector runs against every tool's metadata.
                   Server-level static detectors run once over the full list.
2. Dynamic phase — every dynamic detector runs against every *safe* tool by
                   actually invoking it. Tools classified as destructive are
                   skipped. Pass `skip_dynamic=True` to bypass this phase.

The final ScanReport carries the merged findings, a 0–100 score, and a grade.
"""
import logging
from datetime import datetime

from mcp import ClientSession

from .client import (
    _is_auth_error,
    create_mcp_client,
    describe_transport_error,
    list_tools,
)
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


logger = logging.getLogger(__name__)


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
) -> tuple[list[Finding], str | None]:
    """Run dynamic detectors. Stops early on session-level auth failure.

    Returns (findings, abort_reason). abort_reason is non-None when an auth
    error tripped a tool invocation and the remainder of the phase was skipped.
    """
    findings: list[Finding] = []
    ssrf_detector = SsrfProbeDetector() if enable_ssrf else None
    for tool in tools:
        if classify_tool(tool) == "destructive":
            continue
        try:
            for detector in DYNAMIC_DETECTORS:
                findings.extend(await detector.check(tool, session))
            if ssrf_detector is not None:
                findings.extend(await ssrf_detector.check(tool, session))
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning(
                    "Dynamic phase aborted at tool %r: server returned 401/403.",
                    tool.name,
                )
                return findings, (
                    f"dynamic phase aborted at tool {tool.name!r}: "
                    f"server requires authentication"
                )
            # Non-auth failure on a single tool (bad-arg rejection, a tool that
            # errors, etc.): log it and keep probing the rest. If the transport
            # itself died, the next call or session teardown resurfaces it and
            # build_report records it as a note.
            logger.warning(
                "Dynamic probe error on tool %r: %s",
                tool.name,
                describe_transport_error(exc),
            )
            continue
    return findings, None


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
    notes: list[str] = []

    # Phase 0 — enumerate tools. If this fails with auth, propagate so the API
    # layer returns 401. Without a tool list there is nothing to scan.
    async with create_mcp_client(url=target_url) as session:
        tools = await list_tools(session)

    # Phase 1 — static + semantic detectors run on tool metadata only, no
    # session required. These always run even if the server later refuses
    # dynamic probes.
    findings = _run_static(tools)
    if enable_llm_judge and groq_api_key:
        findings.extend(
            await _run_semantic(
                tools,
                groq_api_key=groq_api_key,
                threshold=judge_threshold,
            )
        )

    # Phase 2 — dynamic probes need a live session. This phase is best-effort:
    # any failure (auth gate, a 4xx/5xx from the transport, a dropped session)
    # is isolated so the static + semantic findings are still returned with a
    # note explaining what happened, rather than failing the whole scan.
    if not skip_dynamic:
        try:
            async with create_mcp_client(url=target_url) as session:
                dynamic_findings, abort_reason = await _run_dynamic(
                    tools, session, enable_ssrf=enable_ssrf
                )
            findings.extend(dynamic_findings)
            if abort_reason:
                notes.append(abort_reason)
        except Exception as exc:
            if _is_auth_error(exc):
                logger.warning(
                    "Dynamic phase skipped for %s: server requires authentication.",
                    target_url,
                )
                notes.append(
                    "dynamic phase skipped: server requires authentication for "
                    "tool invocation (static and semantic findings still reported)"
                )
            else:
                summary = describe_transport_error(exc)
                logger.warning(
                    "Dynamic phase skipped for %s: %s",
                    target_url,
                    summary,
                    exc_info=True,
                )
                notes.append(
                    f"dynamic phase skipped: server rejected tool invocation "
                    f"({summary}); static and semantic findings still reported"
                )

    score, grade = _score(findings)
    elapsed_ms = int((datetime.now() - started).total_seconds() * 1000)

    return ScanReport(
        target_url=target_url,
        tool_count=len(tools),
        findings=findings,
        score=score,
        grade=grade,
        scan_duration_ms=elapsed_ms,
        notes=notes,
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