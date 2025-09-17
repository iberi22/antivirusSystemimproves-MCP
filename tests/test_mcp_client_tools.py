import pytest

# Skip these tests if the optional dev dependency is not installed
pytest.importorskip("fastmcp", reason="fastmcp not installed; install with 'pip install .[dev]' to run these tests")

pytestmark = pytest.mark.asyncio


def _result_json(res):
    data = getattr(res, "data", None)
    if data is None:
        try:
            import json as _json
            if getattr(res, "content", None) and getattr(res.content[0], "text", None):
                return _json.loads(res.content[0].text)
        except Exception:
            return None
    return data


async def test_mcp_client_lists_and_calls_tools():
    # Importar el servidor y crear cliente en memoria
    from fastmcp import Client
    from mcp_win_admin.server import mcp as server_mcp

    client = Client(server_mcp)
    async with client:
        # Ping/health
        await client.ping()

        # Listar tools
        tools = await client.list_tools()
        names = {t.name for t in tools}
        # Algunas tools clave deben existir
        assert {
            "system_scan_performance",
            "processes_list",
            "profiles_list",
            "profiles_preview",
            "db_optimize",
            "db_purge_old",
            "av_check_hash",
            "av_scan_path",
        }.issubset(names)

        # Ejecutar una tool simple sin efectos en disco/red
        res = await client.call_tool("system_scan_performance", {"persist": False})
        data = res.data
        if data is None:
            # Fallback: algunos transports devuelven contenido textual JSON
            try:
                import json as _json
                data = _json.loads(res.content[0].text) if res.content and getattr(res.content[0], "text", None) else None
            except Exception:
                data = None
        assert isinstance(data, dict)
        assert "snapshot" in data

        # Ejecutar mantenimiento DB (debe devolver ok)
        opt = await client.call_tool("db_optimize", {})
        optj = _result_json(opt)
        assert isinstance(optj, dict) and optj.get("ok") is True

        # Purgas desactivadas por defecto (TTL -1) pero la llamada debe responder con ok
        pur = await client.call_tool(
            "db_purge_old", {"events_ttl_seconds": -1, "reputation_ttl_seconds": -1, "hash_ttl_seconds": -1}
        )
        purj = _result_json(pur)
        assert isinstance(purj, dict) and purj.get("ok") is True


async def test_mcp_client_resources_snapshot():
    from fastmcp import Client
    from mcp_win_admin.server import mcp as server_mcp

    client = Client(server_mcp)
    async with client:
        resources = await client.list_resources()
        uris = {str(r.uri) for r in resources}
        assert "snapshot://last" in uris

        content = await client.read_resource("snapshot://last")
        # read_resource devuelve una lista de partes; al menos una con .text
        assert content and hasattr(content[0], "text")
        assert isinstance(content[0].text, str)
