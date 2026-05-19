"""mcp-sentry Streamlit UI.

A minimal front-end that calls the deployed mcp-sentry /scan endpoint for one
or more MCP server URLs and renders the resulting report. The /scan endpoint
is synchronous (returns the final JSON once the scan is done), so we surface
liveness by scanning URLs sequentially and pushing status messages between
each call.

Run:
    streamlit run ui/app.py
"""
from __future__ import annotations

import os
import time
from typing import Any

import requests
import streamlit as st

DEFAULT_API = os.environ.get("MCPSCAN_API_URL", "http://127.0.0.1:8000")
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_EMOJI = {
    "critical": "🟥",
    "high": "🟧",
    "medium": "🟨",
    "low": "🟦",
    "info": "⬜",
}


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
        api_url = st.text_input("Scan endpoint", value=DEFAULT_API)
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

    st.markdown("#### MCP server URLs")
    urls_text = st.text_area(
        "One URL per line",
        height=140,
        placeholder="https://example.com/mcp\nhttps://another.example.com/mcp",
    )
    scan_clicked = st.button("🔎 Scan", type="primary", use_container_width=True)

    if not scan_clicked:
        return

    urls = [u.strip() for u in urls_text.splitlines() if u.strip()]
    if not urls:
        st.error("Add at least one MCP URL to scan.")
        return

    payload = {
        "skip_dynamic": skip_dynamic,
        "enable_ssrf": enable_ssrf,
        "enable_llm_judge": enable_llm_judge,
        "judge_threshold": judge_threshold,
    }

    progress = st.progress(0.0, text="Starting scan…")
    status = st.status("Scanning MCP servers", expanded=True)
    results: list[tuple[str, dict]] = []

    for i, url in enumerate(urls, start=1):
        with status:
            st.write(f"**[{i}/{len(urls)}]** Connecting to `{url}`…")
        progress.progress((i - 1) / len(urls), text=f"Scanning {url}")
        started = time.time()
        try:
            res = _post_scan(api_url, url, payload, timeout=timeout)
        except requests.RequestException as exc:
            res = {"status_code": 0, "ok": False, "data": {"detail": str(exc)}}
        elapsed = time.time() - started
        results.append((url, res))
        with status:
            if res["ok"]:
                grade = res["data"].get("grade", "?")
                findings = len(res["data"].get("findings", []) or [])
                st.write(
                    f"✅ `{url}` — grade **{grade}**, {findings} findings "
                    f"({elapsed:.1f}s)"
                )
            else:
                st.write(
                    f"❌ `{url}` — HTTP {res['status_code']} ({elapsed:.1f}s)"
                )
        progress.progress(i / len(urls), text=f"Done {url}")

    status.update(label="Scan complete", state="complete", expanded=False)
    progress.empty()

    st.markdown("---")
    st.markdown("## Results")
    for url, res in results:
        if res["ok"]:
            _render_report(res["data"])
        else:
            st.error(
                f"**{url}** — request failed (HTTP {res['status_code']})"
            )
            st.json(res["data"])
        st.markdown("---")


if __name__ == "__main__":
    main()
