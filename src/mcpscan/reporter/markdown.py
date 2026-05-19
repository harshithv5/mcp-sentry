"""Render a ScanReport as a human-readable Markdown document."""
from ..models import Finding, ScanReport, Severity


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_GRADE_BADGE: dict[str, str] = {
    "A+": "[A+] excellent",
    "A": "[A] good",
    "B": "[B] acceptable",
    "C": "[C] concerning",
    "D": "[D] poor",
    "F": "[F] do not connect",
}

_EVIDENCE_TRUNCATE = 200


def _truncate(text: str, limit: int = _EVIDENCE_TRUNCATE) -> str:
    text = text.replace("\n", " ").replace("`", "'")
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def render_markdown(report: ScanReport) -> str:
    lines: list[str] = []
    lines.append("# MCP Security Scan Report")
    lines.append("")
    lines.append(f"- **Target**: `{report.target_url}`")
    lines.append(f"- **Tools scanned**: {report.tool_count}")
    lines.append(f"- **Findings**: {len(report.findings)}")
    lines.append(f"- **Score**: {report.score} / 100")
    lines.append(f"- **Grade**: {_GRADE_BADGE.get(report.grade, report.grade)}")
    lines.append(f"- **Duration**: {report.scan_duration_ms} ms")
    lines.append("")

    if report.notes:
        lines.append("## Notes")
        lines.append("")
        for note in report.notes:
            lines.append(f"- {note}")
        lines.append("")

    if not report.findings:
        lines.append("## Result")
        lines.append("")
        lines.append("No issues detected. The server is clean against all static rules.")
        return "\n".join(lines)

    # Severity counts table
    counts: dict[Severity, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    for f in report.findings:
        counts[f.severity] += 1

    lines.append("## Severity breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|------:|")
    for sev in _SEVERITY_ORDER:
        lines.append(f"| {sev.value.upper()} | {counts[sev]} |")
    lines.append("")

    # Findings grouped by severity
    by_sev: dict[Severity, list[Finding]] = {sev: [] for sev in _SEVERITY_ORDER}
    for f in report.findings:
        by_sev[f.severity].append(f)

    lines.append("## Findings")
    lines.append("")
    for sev in _SEVERITY_ORDER:
        bucket = by_sev[sev]
        if not bucket:
            continue
        lines.append(f"### {sev.value.upper()} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            tag = " [CONFIRMED]" if f.confirmed else ""
            if f.rule_id.startswith("L"):
                tag += " [SEMANTIC]"
            lines.append(f"- **[{f.rule_id}]**{tag} `{f.tool_name}` · field `{f.field}`")
            lines.append(f"  - {f.message}")
            lines.append(f"  - Evidence: `{_truncate(f.evidence)}`")
            lines.append(f"  - Fix: {f.suggested_fix}")
        lines.append("")

    return "\n".join(lines)
