import asyncio
import json
import os
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main() -> None:
    # Resolve Rust MCP server binary
    here = os.path.dirname(__file__)
    exe = os.path.abspath(
        os.path.join(here, "..", "native", "overwatch-mcp-rs", "target-rs-mcp", "release", "overwatch-mcp.exe")
    )
    if not os.path.exists(exe):
        raise SystemExit(f"Rust MCP binary not found: {exe}. Build first with cargo build --release.")

    env = dict(os.environ)
    env["OVERWATCH_MCP_STDIO"] = "1"

    print("Launching:", exe)
    params = StdioServerParameters(
        command=exe,
        args=["--stdio"],
        env=env,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            # Initialize handshake
            await session.initialize()

            # List tools
            tools = await session.list_tools()
            names = sorted([t.name for t in getattr(tools, "tools", getattr(tools, "items", []))])
            print("Tools:", names)

            # Call metrics.get
            call = await session.call_tool("metrics.get", {})
            data: Any = None
            for block in getattr(call, "content", []) or []:
                text = getattr(block, "text", None)
                if isinstance(text, str):
                    try:
                        data = json.loads(text)
                        break
                    except Exception:
                        pass
            print("metrics.get ->", (list(data.keys()) if isinstance(data, dict) else type(data)))

            # Call process.list
            call2 = await session.call_tool("process.list", {})
            data2: Any = None
            for block in getattr(call2, "content", []) or []:
                text = getattr(block, "text", None)
                if isinstance(text, str):
                    try:
                        data2 = json.loads(text)
                        break
                    except Exception:
                        pass
            count = len(data2.get("processes", [])) if isinstance(data2, dict) else 0
            print("process.list -> count:", count)


if __name__ == "__main__":
    asyncio.run(main())
