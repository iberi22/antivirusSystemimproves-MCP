import asyncio
import json
import os
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    # Ensure free-only mode and light mode by default
    env = dict(os.environ)
    env.setdefault("MCP_FREE_ONLY_SOURCES", "true")
    env.setdefault("MCP_LIGHT_MODE", "true")
    env.setdefault("MCP_DEFAULT_REP_TTL", "86400")

    params = StdioServerParameters(
        command=sys.executable,
        args=["-u", "-m", "mcp_win_admin.server"],
        env=env,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize handshake
            await session.initialize()

            # List tools
            tools = await session.list_tools()
            names = sorted([t.name for t in tools.tools]) if hasattr(tools, "tools") else sorted([t.name for t in tools])
            print("Tools:", names)

            # Call a simple tool
            call = await session.call_tool("system_scan_performance", {"persist": False})
            # call.content is a list of blocks; try json first
            data: Any = None
            try:
                for block in getattr(call, "content", []) or []:
                    text = getattr(block, "text", None)
                    if text:
                        data = json.loads(text)
                        break
            except Exception:
                pass
            if data is None and hasattr(call, "data"):
                data = call.data
            print("system_scan_performance -> keys:", list(data.keys()) if isinstance(data, dict) else type(data))

            # List resources and read snapshot://last
            res = await session.list_resources()
            uris = [str(r.uri) for r in getattr(res, "resources", []) or getattr(res, "items", [])]
            print("Resources:", uris)
            if "snapshot://last" in uris:
                rr = await session.read_resource("snapshot://last")
                try:
                    blocks = getattr(rr, "content", None) or rr
                    if isinstance(blocks, list) and blocks:
                        first = blocks[0]
                        text = getattr(first, "text", None)
                        if isinstance(text, str):
                            print("snapshot://last size:", len(text))
                        elif isinstance(first, str):
                            print("snapshot://last size:", len(first))
                except Exception as e:
                    print("snapshot://last read error:", e)


if __name__ == "__main__":
    asyncio.run(main())
