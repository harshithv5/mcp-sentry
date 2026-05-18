"""FastAPI server exposing the mcp-sentry scanner.

Endpoints:
- GET  /              — service info / quick links
- GET  /scan          — run a scan, return the ScanReport as JSON
- POST /scan          — same, but parameters come in a JSON body
- GET  /scan/download — run a scan, return the Markdown report as a download

Run with (from project root, with `src/` on PYTHONPATH, or `pip install -e .`):
    python -m mcpscan.api

In Docker the entrypoint is `uvicorn mcpscan.api:app --host 0.0.0.0 --port 8000`.
"""
import logging
import os

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field, HttpUrl

from .client import InvalidMcpEndpoint, validate_mcp_endpoint
from .orchestrator import build_report
from .reporter.markdown import render_markdown



logger = logging.getLogger(__name__)

DEFAULT_TARGET = "https://mcp.deepwiki.com/mcp"

app = FastAPI(
    title="mcp-sentry",
    description="Security scanner for Model Context Protocol servers.",
    version="0.1.0",
)


class ScanRequest(BaseModel):
    target_url: HttpUrl = Field(
        ...,
        description="MCP server URL to scan (http or https). Required.",
    )
    skip_dynamic: bool = Field(
        default=False,
        description="Skip the dynamic probe phase. Default false — run everything.",
    )
    enable_ssrf: bool = Field(
        default=True,
        description="Enable the SSRF probe (D5). Default true — run everything.",
    )
    enable_llm_judge: bool = Field(
        default=False,
        description="Run the semantic LLM-judge detector (L1). Requires GROQ_API_KEY "
                    "to be set in the server environment; off by default.",
    )
    judge_threshold: float = Field(
        default=0.7, ge=0.0, le=1.0,
        description="Classifier score above which L1 raises a finding (0.0–1.0).",
    )


class ValidateRequest(BaseModel):
    target_url: HttpUrl = Field(..., description="MCP server URL to validate.")
    timeout: float = Field(
        default=5.0, gt=0.0, le=30.0,
        description="Seconds to wait for the MCP handshake before giving up.",
    )


def _filename_for(target_url: str) -> str:
    slug = (
        target_url.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )[:80] or "report"
    return f"mcp-sentry-{slug}.md"


async def _ensure_mcp(target_url: str, timeout: float = 5.0) -> None:
    """Run the cheap MCP handshake. Raise 422 with the validator's reason."""
    try:
        await validate_mcp_endpoint(target_url, timeout=timeout)
    except InvalidMcpEndpoint as exc:
        raise HTTPException(
            status_code=422,
            detail={"target_url": target_url, "reason": str(exc)},
        ) from exc


async def _run_scan(
    target_url: str,
    skip_dynamic: bool,
    enable_ssrf: bool,
    *,
    enable_llm_judge: bool = False,
    judge_threshold: float = 0.7,
):
    groq_key = os.environ.get("GROQ_API_KEY") if enable_llm_judge else None
    if enable_llm_judge and not groq_key:
        logger.warning("enable_llm_judge=true but GROQ_API_KEY is not set; skipping L1.")
    try:
        return await build_report(
            target_url,
            skip_dynamic=skip_dynamic,
            enable_ssrf=enable_ssrf,
            enable_llm_judge=enable_llm_judge and bool(groq_key),
            groq_api_key=groq_key,
            judge_threshold=judge_threshold,
        )
    except Exception as exc:
        logger.exception("Scan failed for %s", target_url)
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}") from exc


@app.get("/")
def root() -> dict:
    return {
        "name": "mcp-sentry",
        "version": app.version,
        "endpoints": {
            "GET /scan": "Run a scan, return JSON. Query: target_url, skip_dynamic, enable_ssrf, validate_endpoint",
            "POST /scan": "Run a scan, JSON body. target_url is required; skip_dynamic=false, enable_ssrf=true by default",
            "GET /scan/download": "Run a scan, download a Markdown report",
            "POST /validate": "Cheap MCP-handshake probe; returns 200 + server info or 422 + reason",
        },
        "default_target": DEFAULT_TARGET,
    }


@app.post("/validate")
async def validate_endpoint(req: ValidateRequest) -> dict:
    """Probe *target_url* with a fast MCP handshake.

    Returns 200 with `{ok, url, tool_count, tools}` on success.
    Returns 422 with `{target_url, reason}` when the URL is not an MCP server.
    """
    try:
        return await validate_mcp_endpoint(str(req.target_url), timeout=req.timeout)
    except InvalidMcpEndpoint as exc:
        raise HTTPException(
            status_code=422,
            detail={"target_url": str(req.target_url), "reason": str(exc)},
        ) from exc


@app.get("/scan")
async def scan_get(
    target_url: str = Query(DEFAULT_TARGET, description="MCP server URL to scan"),
    skip_dynamic: bool = Query(False, description="Skip the dynamic probe phase"),
    enable_ssrf: bool = Query(False, description="Enable the SSRF probe (D5)"),
    validate_endpoint: bool = Query(True, description="Run MCP handshake first"),
):
    if validate_endpoint:
        await _ensure_mcp(target_url)
    return await _run_scan(target_url, skip_dynamic, enable_ssrf)


@app.post("/scan")
async def scan_post(req: ScanRequest):
    target_url = str(req.target_url)
    await _ensure_mcp(target_url)
    return await _run_scan(
        target_url,
        req.skip_dynamic,
        req.enable_ssrf,
        enable_llm_judge=req.enable_llm_judge,
        judge_threshold=req.judge_threshold,
    )


@app.get("/scan/download")
async def scan_download(
    target_url: str = Query(DEFAULT_TARGET, description="MCP server URL to scan"),
    skip_dynamic: bool = Query(False, description="Skip the dynamic probe phase"),
    enable_ssrf: bool = Query(False, description="Enable the SSRF probe (D5)"),
    validate_endpoint: bool = Query(True, description="Run MCP handshake first"),
):
    if validate_endpoint:
        await _ensure_mcp(target_url)
    report = await _run_scan(target_url, skip_dynamic, enable_ssrf)
    markdown = render_markdown(report)
    return Response(
        content=markdown,
        media_type="text/markdown; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{_filename_for(target_url)}"',
        },
    )


def _serve() -> None:
    """Entrypoint for the `mcpscan-api` console script (see pyproject.toml).

    Reads HOST/PORT from env vars so the same binary works in dev and in a
    container. Pass the `app` object (not an import string) so this works
    whether launched as a module or via the installed entrypoint.
    """
    import os

    logging.basicConfig(level=logging.INFO)
    host = os.environ.get("MCPSCAN_HOST", "127.0.0.1")
    port = int(os.environ.get("MCPSCAN_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    _serve()
