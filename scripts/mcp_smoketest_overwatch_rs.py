import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def find_overwatch_exe() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    native = repo_root / "native" / "overwatch-mcp-rs"
    candidates = [
        native / "target-rs-mcp" / "release" / "overwatch-mcp.exe",
        native / "target" / "release" / "overwatch-mcp.exe",
        native / "target-rs-mcp" / "debug" / "overwatch-mcp.exe",
        native / "target" / "debug" / "overwatch-mcp.exe",
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    # Fallback: assume in PATH
    return "overwatch-mcp.exe"


async def main() -> None:
    exe = find_overwatch_exe()
    print("Using server:", exe)

    env = dict(os.environ)
    env.setdefault("RUST_LOG", "info")

    params = StdioServerParameters(
        command=exe,
        args=["--stdio"],
        env=env,
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            names = [t.name for t in getattr(tools, "tools", tools)]
            print("Tools:", names)

            for tool_name in ("metrics.get", "process.list", "sensors.get"):
                try:
                    call = await session.call_tool(tool_name, {})
                    data: Any = None
                    for block in getattr(call, "content", []) or []:
                        text = getattr(block, "text", None)
                        if text:
                            try:
                                data = json.loads(text)
                            except Exception:
                                data = text
                            break
                    print(f"{tool_name} -> type:", type(data), "keys:" if isinstance(data, dict) else "", list(data.keys()) if isinstance(data, dict) else "")
                except Exception as e:
                    print(f"Error calling {tool_name}:", e)


if __name__ == "__main__":
    asyncio.run(main())
