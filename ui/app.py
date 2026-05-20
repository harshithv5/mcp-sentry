"""mcp-sentry Streamlit UI.

A minimal front-end that calls the deployed mcp-sentry /scan endpoint for a
single MCP server URL and renders the resulting report. One server per scan
keeps load on the scanner low. The /scan endpoint is synchronous (returns the
final JSON once the scan is done), so we surface liveness with a status panel
while the request is in flight.

Run:
    streamlit run ui/app.py
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import requests
import streamlit as st
from dotenv import load_dotenv

# Load ui/.env (sitting next to this file) so MCPSCAN_API_URL is available
# regardless of the directory streamlit is launched from.
load_dotenv(Path(__file__).resolve().parent / ".env")

DEFAULT_API = os.environ.get("MCPSCAN_API_URL", "https://mcp-sentry-nqli.onrender.com")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_EMOJI = {
    "critical": "🟥",
    "high": "🟧",
    "medium": "🟨",
    "low": "🟦",
    "info": "⬜",
}

# Friendly one-line headlines per status the API (or the client) can return.
# status_code 0 means the request never reached the server (network error).
ERROR_HEADLINES = {
    0: "Couldn't reach the scan API",
    401: "Server requires authentication",
    422: "Not a scannable MCP endpoint",
    502: "Scan failed",
}


def _humanize_error(res: dict) -> tuple[str, str, str]:
    """Turn an error response into readable ``(headline, message, hint)`` text.

    The API returns ``detail`` as a string, a dict (``{reason, hint, ...}``), or
    a list (FastAPI/pydantic validation errors). Network failures arrive as
    ``status_code`` 0 with ``{"detail": str(exc)}``. Everything is reduced to
    plain strings so the UI never has to dump raw JSON at the user.
    """
    status = res.get("status_code", 0)
    data = res.get("data", {}) or {}
    detail = data.get("detail", data) if isinstance(data, dict) else data

    headline = ERROR_HEADLINES.get(status, f"Request failed (HTTP {status})")
    message = ""
    hint = ""

    if isinstance(detail, dict):
        message = str(detail.get("reason") or detail.get("msg") or "").strip()
        hint = str(detail.get("hint") or "").strip()
        if not message:
            message = "; ".join(f"{k}: {v}" for k, v in detail.items())
    elif isinstance(detail, list):
        # pydantic validation errors: [{"loc": [...], "msg": "...", ...}, ...]
        parts: list[str] = []
        for item in detail:
            if isinstance(item, dict):
                loc = ".".join(
                    str(p) for p in item.get("loc", []) if p != "body"
                )
                msg = item.get("msg", "")
                parts.append(f"{loc}: {msg}" if loc else str(msg))
            else:
                parts.append(str(item))
        message = "; ".join(p for p in parts if p)
    else:
        message = str(detail).strip()

    if not message:
        message = "No further detail was provided by the server."
    return headline, message, hint


def _post_scan(api_url: str, target_url: str, payload: dict, timeout: int) -> dict:
    body = {"target_url": target_url, **payload}
    resp = requests.post(f"{api_url.rstrip('/')}/scan", json=body, timeout=timeout)
    try:
        data = resp.json()
    except ValueError:
        data = {"detail": resp.text}
    return {"status_code": resp.status_code, "ok": resp.ok, "data": data}


def _grade_color(grade: str) -> str:
    g = (grade or "").upper()
    if g.startswith("A"):
        return "#16a34a"
    if g.startswith("B"):
        return "#65a30d"
    if g.startswith("C"):
        return "#ca8a04"
    if g.startswith("D"):
        return "#ea580c"
    return "#dc2626"


def _render_report(report: dict) -> None:
    target = report.get("target_url", "?")
    grade = report.get("grade", "?")
    score = report.get("score", "?")
    tool_count = report.get("tool_count", 0)
    duration = report.get("scan_duration_ms", 0)
    findings = report.get("findings", []) or []
    notes = report.get("notes", []) or []

    st.markdown(f"### {target}")
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(
        f"<div style='font-size:42px;font-weight:700;color:{_grade_color(grade)}'>"
        f"{grade}</div><div style='color:#666'>Grade</div>",
        unsafe_allow_html=True,
    )
    c2.metric("Score", f"{score}/100")
    c3.metric("Tools scanned", tool_count)
    c4.metric("Duration", f"{duration} ms")

    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    chip_cols = st.columns(len(SEVERITY_ORDER))
    for i, sev in enumerate(SEVERITY_ORDER):
        chip_cols[i].markdown(
            f"{SEVERITY_EMOJI[sev]} **{counts[sev]}** {sev}"
        )

    if notes:
        with st.expander("Operational notes", expanded=False):
            for n in notes:
                st.write(f"- {n}")

    if not findings:
        st.success("No findings — clean report.")
        return

    findings_sorted = sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.index(f.get("severity", "info"))
            if f.get("severity", "info") in SEVERITY_ORDER
            else len(SEVERITY_ORDER),
            f.get("rule_id", ""),
        ),
    )
    st.markdown("#### Findings")
    for f in findings_sorted:
        sev = f.get("severity", "info")
        title = (
            f"{SEVERITY_EMOJI.get(sev, '')} "
            f"[{f.get('rule_id','?')}] {f.get('tool_name','?')} · "
            f"{f.get('field','?')}"
            + ("  · confirmed" if f.get("confirmed") else "")
        )
        with st.expander(title, expanded=(sev in ("critical", "high"))):
            st.markdown(f"**Message** — {f.get('message','')}")
            st.markdown("**Evidence**")
            st.code(f.get("evidence", ""), language="text")
            if f.get("suggested_fix"):
                st.markdown(f"**Suggested fix** — {f['suggested_fix']}")


def main() -> None:
    st.set_page_config(page_title="mcp-sentry", page_icon="🛡️", layout="wide")
    st.title("🛡️ mcp-sentry")
    st.caption("Security scanner for Model Context Protocol servers.")

    with st.sidebar:
        st.subheader("API")
        api_url = st.text_input(
            "Scan endpoint",
            value=DEFAULT_API,
            disabled=True,
            help="Fixed from MCPSCAN_API_URL in ui/.env.",
        )
        timeout = st.number_input(
            "Request timeout (seconds)", min_value=30, max_value=900, value=300, step=30
        )

        st.subheader("Scan options")
        enable_llm_judge = st.toggle(
            "Enable LLM-as-a-Judge",
            value=False,
            help=(
                "Runs the semantic L1 detector that asks an LLM to classify "
                "tool text for prompt-injection and policy violations. Requires "
                "GROQ_API_KEY to be set on the server. Slower, but catches "
                "attacks keyword rules miss."
            ),
        )
        judge_threshold = st.slider(
            "Judge threshold",
            min_value=0.0,
            max_value=1.0,
            value=0.7,
            step=0.05,
            disabled=not enable_llm_judge,
            help="Confidence above which the LLM judge raises a finding.",
        )
        enable_ssrf = st.toggle(
            "Enable SSRF probe",
            value=True,
            help=(
                "Active D5 probe that fires test URLs through the target's "
                "tools to detect server-side request forgery. Disable for "
                "passive-only scans."
            ),
        )
        skip_dynamic = st.toggle(
            "Skip dynamic phase",
            value=False,
            help=(
                "Static analysis only — no live probes. Faster and safer for "
                "servers you don't fully trust, but misses confirmed findings."
            ),
        )

    st.markdown("#### MCP server URL")
    url_input = st.text_input(
        "MCP server URL",
        placeholder="https://example.com/mcp",
        label_visibility="collapsed",
        help="One MCP server per scan — keeps load on the scanner low.",
    )

    # Per-session flags: `scanning` gates the button; `result` holds the last
    # completed scan so it survives the rerun that re-enables the button.
    if "scanning" not in st.session_state:
        st.session_state.scanning = False
    if "result" not in st.session_state:
        st.session_state.result = None

    scan_clicked = st.button(
        "⏳ Scanning…" if st.session_state.scanning else "🔎 Scan",
        type="primary",
        use_container_width=True,
        disabled=st.session_state.scanning,
    )

    # Click: validate, snapshot inputs, flip into the scanning state, and rerun
    # so the button re-renders disabled before any network work starts.
    if scan_clicked:
        url = url_input.strip()
        if not url:
            st.error("Enter an MCP server URL to scan.")
        elif not url.lower().startswith(("http://", "https://")):
            st.error("URL must start with http:// or https://")
        else:
            st.session_state.result = None
            st.session_state.scan_job = {
                "api_url": api_url,
                "timeout": int(timeout),
                "url": url,
                "payload": {
                    "skip_dynamic": skip_dynamic,
                    "enable_ssrf": enable_ssrf,
                    "enable_llm_judge": enable_llm_judge,
                    "judge_threshold": judge_threshold,
                },
            }
            st.session_state.scanning = True
            st.rerun()

    # Scanning run: button is already disabled. Fire the single request, store
    # the result, then rerun to re-enable the button and render the report.
    if st.session_state.scanning:
        job = st.session_state.scan_job
        url = job["url"]
        status = st.status(f"Scanning {url}", expanded=True)
        with status:
            st.write(f"Connecting to `{url}`…")
        started = time.time()
        try:
            res = _post_scan(job["api_url"], url, job["payload"], timeout=job["timeout"])
        except requests.RequestException as exc:
            res = {"status_code": 0, "ok": False, "data": {"detail": str(exc)}}
        elapsed = time.time() - started
        with status:
            if res["ok"]:
                grade = res["data"].get("grade", "?")
                findings = len(res["data"].get("findings", []) or [])
                st.write(
                    f"✅ Done — grade **{grade}**, {findings} findings "
                    f"({elapsed:.1f}s)"
                )
            else:
                headline, _, _ = _humanize_error(res)
                code = res["status_code"]
                prefix = f"HTTP {code}, " if code else ""
                st.write(f"❌ {headline} ({prefix}{elapsed:.1f}s)")
        status.update(
            label=f"Scan complete ({elapsed:.1f}s)",
            state="complete" if res["ok"] else "error",
            expanded=False,
        )
        st.session_state.result = (url, res)
        st.session_state.scanning = False
        st.rerun()

    # Render the last completed scan (persists across the re-enable rerun).
    if st.session_state.result:
        url, res = st.session_state.result
        st.markdown("---")
        st.markdown("## Result")
        if res["ok"]:
            _render_report(res["data"])
        else:
            headline, message, hint = _humanize_error(res)
            st.markdown(f"### {url}")
            st.error(f"**{headline}**\n\n{message}")
            if hint:
                st.info(f"💡 {hint}")
            with st.expander("Technical details", expanded=False):
                st.json(res["data"])


if __name__ == "__main__":
    main()
