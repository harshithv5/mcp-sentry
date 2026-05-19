"""FastAPI server exposing the mcp-sentry scanner.

Endpoints:
- GET  /health  — liveness probe.
- POST /scan    — run a scan; JSON body, JSON response.

Run with (from project root, with `src/` on PYTHONPATH, or `pip install -e .`):
    python -m mcpscan.api

In Docker the entrypoint is `uvicorn mcpscan.api:app --host 0.0.0.0 --port 8000`.
"""
import logging
import os

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, HttpUrl

from .client import (
    InvalidMcpEndpoint,
    UnauthorizedMcpEndpoint,
    _is_auth_error,
    validate_mcp_endpoint,
)
from .orchestrator import build_report
from dotenv import load_dotenv

# Load environment variables BEFORE importing any module that depends on them
load_dotenv()

logger = logging.getLogger(__name__)

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


async def _ensure_mcp(target_url: str, timeout: float = 5.0) -> None:
    """Run the cheap MCP handshake.

    - 401 if the server is auth-gated (mcp-sentry only scans public servers).
    - 422 for any other validation failure (bad URL, no MCP handshake, etc.).
    """
    try:
        await validate_mcp_endpoint(target_url, timeout=timeout)
    except UnauthorizedMcpEndpoint as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "target_url": target_url,
                "reason": str(exc),
                "hint": "mcp-sentry only works with publicly-deployed MCP servers. "
                        "Authentication-gated servers are not supported.",
            },
        ) from exc
    except InvalidMcpEndpoint as exc:
        raise HTTPException(
            status_code=422,
            detail={"target_url": target_url, "reason": str(exc)},
        ) from exc


@app.get("/health")
def health() -> dict:
    """Liveness probe — no I/O, just confirms the process is up."""
    return {"status": "ok", "service": "mcp-sentry", "version": app.version}


@app.post("/scan")
async def scan(req: ScanRequest):
    target_url = str(req.target_url)
    await _ensure_mcp(target_url)

    groq_key = os.environ.get("GROQ_API_KEY") if req.enable_llm_judge else None
    if req.enable_llm_judge and not groq_key:
        logger.warning("enable_llm_judge=true but GROQ_API_KEY is not set; skipping L1.")

    try:
        return await build_report(
            target_url,
            skip_dynamic=req.skip_dynamic,
            enable_ssrf=req.enable_ssrf,
            enable_llm_judge=req.enable_llm_judge and bool(groq_key),
            groq_api_key=groq_key,
            judge_threshold=req.judge_threshold,
        )
    except Exception as exc:
        logger.exception("Scan failed for %s", target_url)
        if _is_auth_error(exc):
            raise HTTPException(
                status_code=401,
                detail={
                    "target_url": target_url,
                    "reason": "MCP server requires authentication mid-session.",
                    "hint": "mcp-sentry only works with publicly-deployed MCP servers. "
                            "Authentication-gated servers are not supported.",
                },
            ) from exc
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}") from exc


def _serve() -> None:
    """Entrypoint for the `mcpscan-api` console script (see pyproject.toml).

    Reads HOST/PORT from env vars so the same binary works in dev and in a
    container. Pass the `app` object (not an import string) so this works
    whether launched as a module or via the installed entrypoint.
    """
    logging.basicConfig(level=logging.INFO)
    host = os.environ.get("MCPSCAN_HOST", "127.0.0.1")
    port = int(os.environ.get("MCPSCAN_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    _serve()
