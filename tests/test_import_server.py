import importlib


def test_import_server():
    mod = importlib.import_module("mcp_win_admin.server")
    assert hasattr(mod, "mcp"), "El módulo server debe exponer 'mcp'"
