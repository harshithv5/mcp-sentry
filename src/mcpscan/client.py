import asyncio
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .models import ToolInfo


class InvalidMcpEndpoint(ValueError):
    """Raised when a URL is not a usable MCP endpoint."""


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
        raise InvalidMcpEndpoint(f"Could not reach endpoint: {exc}") from exc
    except InvalidMcpEndpoint:
        raise
    except Exception as exc:
        raise InvalidMcpEndpoint(
            f"Endpoint did not respond as an MCP server: {type(exc).__name__}: {exc}"
        ) from exc
