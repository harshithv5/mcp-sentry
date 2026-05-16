from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from .models import ToolInfo


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
            description=tool.description ,
            input_schema=tool.inputSchema
        )
        for tool in result.tools
    ]


# if __name__ == "__main__":
#     import asyncio

#     async def _test() -> None:
#         url = "http://127.0.0.1:8000/mcp"
#         print(f"Connecting to {url} ...")
#         async with create_mcp_client(url) as session:
#             print("Connection OK. Listing tools...\n")
#             tools = await list_tools(session)

#         if not tools:
#             print("Server returned no tools.")
#             return

#         print(f"{len(tools)} tool(s) found:\n")
#         for t in tools:
#             print(t.all_text_fields)
#             print(f"  {t.name}")
#             if t.description:
#                 print(f"    {t.description.strip()}")
#             if t.input_schema:
#                 print(f"    schema: {t.input_schema}")

#     asyncio.run(_test())
