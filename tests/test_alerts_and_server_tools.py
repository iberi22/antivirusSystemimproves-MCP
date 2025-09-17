import importlib
import sys


class _FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code


class _FakeClient:
    def __init__(self, *a, **k):
        self.posts = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, url, json=None):
        self.posts.append((url, json))
        return _FakeResponse(200)


def test_alert_notify_webhook_direct(monkeypatch):
    alerts = importlib.import_module("mcp_win_admin.alerts")
    httpx = importlib.import_module("httpx")

    monkeypatch.setattr(httpx, "Client", _FakeClient, raising=True)
    out = alerts.notify_webhook("http://example.local/hook", event="evt", level="INFO", data={"a": 1})
    assert out.get("ok") is True


def test_server_alert_notify_webhook_uses_env(monkeypatch):
    server = importlib.import_module("mcp_win_admin.server")
    httpx = importlib.import_module("httpx")

    fc = _FakeClient()
    def _Client(*a, **k):
        return fc

    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://example.local/envhook")
    monkeypatch.setattr(httpx, "Client", _Client, raising=True)

    out = server.alert_notify_webhook(event="evt", level="WARN", data_json='{"x":2}', url="")
    assert out.get("ok") is True and out.get("used_env") is True
    assert fc.posts and fc.posts[0][0] == "http://example.local/envhook"


def test_notify_toast_via_win10toast(monkeypatch):
    alerts = importlib.import_module("mcp_win_admin.alerts")

    class FakeToast:
        def show_toast(self, *a, **k):
            return True

    mod = type("_M", (), {"ToastNotifier": lambda: FakeToast()})
    monkeypatch.setitem(sys.modules, "win10toast", mod)

    out = alerts.notify_toast("Title", "Message")
    assert out.get("ok") is True and out.get("method") == "win10toast"
