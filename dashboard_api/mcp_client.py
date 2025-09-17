import asyncio
import json
import os
from typing import Any, Dict, Optional, Tuple

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


class MCPClient:
    """
    Persistent stdio MCP client for the Rust server.
    - Spawns the Rust binary once and maintains a single ClientSession.
    - Reconnects on demand if the session drops.
    - Parses text content blocks as JSON when convenient.

    Env/config:
      OVERWATCH_MCP_BIN: override path to overwatch-mcp.exe
      OVERWATCH_MCP_STDIO: when set to "1", also passed to child env
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._call_lock = asyncio.Lock()
        self._cm = None  # stdio_client(...) context manager
        self._read = None
        self._write = None
        self._session: Optional[ClientSession] = None
        self._started = False
        self._exe = self._resolve_exe()
        self._env = dict(os.environ)
        self._env.setdefault("OVERWATCH_MCP_STDIO", "1")

    def _resolve_exe(self) -> str:
        # Project structure: native/overwatch-mcp-rs/target-*/release/overwatch-mcp.exe
        # Allow override via env var
        override = os.environ.get("OVERWATCH_MCP_BIN")
        if override and os.path.exists(override):
            return override
        here = os.path.dirname(__file__)
        root = os.path.abspath(os.path.join(here, ".."))
        native = os.path.join(root, "native", "overwatch-mcp-rs")
        candidates = [
            os.path.join(native, "target-rs-mcp", "release", "overwatch-mcp.exe"),
            os.path.join(native, "target", "release", "overwatch-mcp.exe"),
            os.path.join(native, "target-rs-mcp", "debug", "overwatch-mcp.exe"),
            os.path.join(native, "target", "debug", "overwatch-mcp.exe"),
        ]
        for p in candidates:
            if os.path.exists(p):
                return p
        return candidates[0]

    async def ensure_started(self) -> None:
        if self._session is not None:
            return
        async with self._lock:
            if self._session is not None:
                return
            if not os.path.exists(self._exe):
                raise RuntimeError(f"Rust MCP binary not found: {self._exe}. Build with cargo build --release.")
            params = StdioServerParameters(command=self._exe, args=["--stdio"], env=self._env)
            # Manually enter async context managers to keep them open for app lifetime
            self._cm = stdio_client(params)
            self._read, self._write = await self._cm.__aenter__()
            self._session = ClientSession(self._read, self._write)
            await self._session.__aenter__()
            await self._session.initialize()
            self._started = True

    async def stop(self) -> None:
        async with self._lock:
            # Serializa contra llamadas activas para evitar "cancel scope" cross-task
            async with self._call_lock:
                try:
                    if self._session is not None:
                        await self._session.__aexit__(None, None, None)
                finally:
                    self._session = None
                try:
                    if self._cm is not None:
                        await self._cm.__aexit__(None, None, None)
                finally:
                    self._cm = None
                    self._read = None
                    self._write = None
                    self._started = False

    async def restart(self) -> None:
        # Garantiza que no haya llamadas en curso durante el ciclo stop/start
        async with self._call_lock:
            await self.stop()
            await self.ensure_started()

    async def list_tools(self) -> Dict[str, Any]:
        await self.ensure_started()
        try:
            async with self._call_lock:
                res = await self._session.list_tools()  # type: ignore[union-attr]
        except Exception:
            # Attempt a single restart and retry once
            await self.restart()
            async with self._call_lock:
                res = await self._session.list_tools()  # type: ignore[union-attr]
        # Convert to simple list-of-dicts form when possible
        tools = []
        items = getattr(res, "tools", getattr(res, "items", [])) or []
        for t in items:
            try:
                tools.append({
                    "name": getattr(t, "name", None),
                    "description": getattr(t, "description", None),
                })
            except Exception:
                continue
        return {"tools": tools}

    @staticmethod
    def _parse_call_result(call_obj: Any) -> Tuple[Optional[Dict[str, Any]], Any]:
        data: Optional[Dict[str, Any]] = None
        raw = getattr(call_obj, "content", []) or []
        for block in raw:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                try:
                    data = json.loads(text)
                    break
                except Exception:
                    continue
        return data, raw

    async def call_tool_json(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        await self.ensure_started()
        try:
            async with self._call_lock:
                call = await self._session.call_tool(name, args)  # type: ignore[union-attr]
        except Exception:
            await self.restart()
            async with self._call_lock:
                call = await self._session.call_tool(name, args)  # type: ignore[union-attr]
        data, raw = self._parse_call_result(call)
        if isinstance(data, dict):
            return data
        return {"raw": raw}

    async def health(self) -> Dict[str, Any]:
        try:
            tools = await self.list_tools()
            names = [t.get("name") for t in tools.get("tools", []) if isinstance(t, dict)]
            return {"ok": True, "tools_count": len(names), "tools": names[:16], "bin": self._exe}
        except Exception as e:
            return {"ok": False, "error": str(e), "bin": self._exe}


# Singleton instance used by FastAPI
mcp_singleton = MCPClient()
