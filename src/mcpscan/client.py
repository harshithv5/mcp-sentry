import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .models import ToolInfo


class InvalidMcpEndpoint(ValueError):
    """Raised when a URL is not a usable MCP endpoint."""


class UnauthorizedMcpEndpoint(InvalidMcpEndpoint):
    """Raised when the MCP server returns 401/403 — auth-gated, not public."""


_AUTH_GATE_MARKERS: tuple[str, ...] = (
    "401", "unauthorized",
    "402", "payment required",
    "403", "forbidden",
)


def _is_auth_error(exc: BaseException) -> bool:
    """Best-effort detection of an auth/paywall gate inside an exception chain.

    Catches 401 (Unauthorized), 402 (Payment Required) and 403 (Forbidden) —
    all three mean "we cannot proceed without credentials/payment", which from
    a scanner's perspective behaves identically: the endpoint is gated.

    `streamable_http_client` wraps httpx errors in an anyio TaskGroup
    `ExceptionGroup`, so we walk both `__cause__`/`__context__` and any nested
    `.exceptions` (BaseExceptionGroup) and match on the string representation.
    """
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        text = f"{type(cur).__name__}: {cur}".lower()
        if any(marker in text for marker in _AUTH_GATE_MARKERS):
            return True
        if isinstance(cur, BaseExceptionGroup):
            stack.extend(cur.exceptions)
        if cur.__cause__ is not None:
            stack.append(cur.__cause__)
        if cur.__context__ is not None:
            stack.append(cur.__context__)
    return False


def describe_transport_error(exc: BaseException) -> str:
    """Reduce a (possibly nested) transport exception to one readable line.

    `streamable_http_client` wraps httpx errors in an anyio `ExceptionGroup`,
    so the top-level `str(exc)` is uselessly generic ("unhandled errors in a
    TaskGroup"). We walk the same chain `_is_auth_error` does and prefer an
    HTTP status line (e.g. "HTTP 400 Bad Request") when an httpx-style error is
    present, falling back to the first concrete leaf exception otherwise.
    """
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    http_summary: str | None = None
    leaf_summary: str | None = None
    while stack:
        cur = stack.pop()
        if cur is None or id(cur) in seen:
            continue
        seen.add(id(cur))
        # httpx.HTTPStatusError (duck-typed) exposes .response.status_code.
        response = getattr(cur, "response", None)
        status = getattr(response, "status_code", None)
        if status is not None and http_summary is None:
            reason = (getattr(response, "reason_phrase", "") or "").strip()
            http_summary = f"HTTP {status} {reason}".strip()
        if not isinstance(cur, BaseExceptionGroup) and leaf_summary is None:
            leaf_summary = f"{type(cur).__name__}: {cur}"
        if isinstance(cur, BaseExceptionGroup):
            stack.extend(cur.exceptions)
        if cur.__cause__ is not None:
            stack.append(cur.__cause__)
        if cur.__context__ is not None:
            stack.append(cur.__context__)
    return http_summary or leaf_summary or f"{type(exc).__name__}: {exc}"


@asynccontextmanager
async def create_mcp_client(url: str):
    """Connect to an MCP server at *url* and yield an initialised ClientSession."""
    async with streamable_http_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


async def list_tools(session: ClientSession) -> list[ToolInfo]:
    """Return all tools advertised by the server in the given session."""
    result = await session.list_tools()
    return [
        ToolInfo(
            name=tool.name,
            description=tool.description,
            input_schema=tool.inputSchema,
        )
        for tool in result.tools
    ]


async def validate_mcp_endpoint(url: str, *, timeout: float = 5.0) -> dict:
    """Verify that *url* speaks MCP. Returns server info on success.

    The check is intentionally cheap: open a streamable-HTTP transport, run
    `initialize()` (handled inside `create_mcp_client`), then `list_tools()`.
    A working MCP server replies in well under a second; anything else is
    rejected with a human-readable error.

    Raises `InvalidMcpEndpoint` for bad URL syntax, transport failures,
    handshake timeouts, or a response that doesn't parse as MCP.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise InvalidMcpEndpoint(
            f"URL scheme must be http or https, got '{parsed.scheme or '(none)'}'"
        )
    if not parsed.netloc:
        raise InvalidMcpEndpoint("URL is missing a host")

    try:
        async with asyncio.timeout(timeout):
            async with create_mcp_client(url=url) as session:
                tools = await session.list_tools()
                return {
                    "ok": True,
                    "url": url,
                    "tool_count": len(tools.tools),
                    "tools": [t.name for t in tools.tools],
                }
    except asyncio.TimeoutError as exc:
        raise InvalidMcpEndpoint(
            f"MCP handshake timed out after {timeout}s — server is unreachable "
            f"or not speaking MCP over streamable-HTTP"
        ) from exc
    except (ConnectionError, OSError) as exc:
        if _is_auth_error(exc):
            raise UnauthorizedMcpEndpoint(
                "MCP server is gated (401/402/403). mcp-sentry only scans "
                "publicly-deployed MCP servers."
            ) from exc
        raise InvalidMcpEndpoint(f"Could not reach endpoint: {exc}") from exc
    except InvalidMcpEndpoint:
        raise
    except Exception as exc:
        if _is_auth_error(exc):
            raise UnauthorizedMcpEndpoint(
                "MCP server is gated (401/402/403). mcp-sentry only scans "
                "publicly-deployed MCP servers."
            ) from exc
        raise InvalidMcpEndpoint(
            f"Endpoint did not respond as an MCP server: {type(exc).__name__}: {exc}"
        ) from exc
