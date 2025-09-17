import os
import sys
import types
import pytest


def test_notify_log_success(monkeypatch):
    from mcp_win_admin import alerts

    calls = {}
    def fake_log_event(level, message, code=None):
        calls['args'] = (level, message, code)

    monkeypatch.setattr(alerts.db, 'log_event', fake_log_event, raising=True)
    out = alerts.notify_log('info', 'hello', code='X1')
    assert out == {"ok": True}
    assert calls['args'] == ('info', 'hello', 'X1')


def test_notify_log_failure(monkeypatch):
    from mcp_win_admin import alerts

    def fake_log_event(level, message, code=None):
        raise RuntimeError('db error')

    monkeypatch.setattr(alerts.db, 'log_event', fake_log_event, raising=True)
    out = alerts.notify_log('error', 'oops')
    assert out['ok'] is False
    assert 'error' in out


def test_notify_webhook_ok(monkeypatch):
    from mcp_win_admin import alerts
    import httpx

    class Resp:
        def __init__(self, code=200):
            self.status_code = code
        def raise_for_status(self):
            return None

    class Client:
        def __init__(self, *a, **k):
            pass
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def post(self, url, json=None):
            return Resp(200)

    monkeypatch.setattr(httpx, 'Client', Client, raising=True)
    out = alerts.notify_webhook('http://example', 'evt', 'info', {"a":1}, timeout=0.1)
    assert out['ok'] is True and out['status'] == 200


def test_notify_webhook_exception(monkeypatch):
    from mcp_win_admin import alerts
    import httpx

    class Client:
        def __init__(self, *a, **k):
            pass
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def post(self, url, json=None):
            raise RuntimeError('network')

    monkeypatch.setattr(httpx, 'Client', Client, raising=True)
    out = alerts.notify_webhook('http://example', 'evt', 'info')
    assert out['ok'] is False
    assert 'error' in out


def test_notify_webhook_if_configured_disabled(monkeypatch):
    from mcp_win_admin import alerts
    # desactivar
    monkeypatch.setattr(alerts.cfg, 'ENABLE_ALERTS', False, raising=False)
    monkeypatch.setenv(alerts.DEFAULT_WEBHOOK_ENV, 'http://should-not-be-used')

    called = {'n': 0}
    def boom(*a, **k):
        called['n'] += 1
        raise AssertionError('should not call')

    monkeypatch.setattr(alerts, 'notify_webhook', boom, raising=True)
    # no debe lanzar
    alerts.notify_webhook_if_configured('evt', 'info', {"x":1})
    assert called['n'] == 0


def test_notify_webhook_if_configured_env_empty(monkeypatch):
    from mcp_win_admin import alerts
    monkeypatch.setattr(alerts.cfg, 'ENABLE_ALERTS', True, raising=False)
    monkeypatch.delenv(alerts.DEFAULT_WEBHOOK_ENV, raising=False)

    called = {'n': 0}
    def boom(*a, **k):
        called['n'] += 1
        raise AssertionError('should not call')

    monkeypatch.setattr(alerts, 'notify_webhook', boom, raising=True)
    alerts.notify_webhook_if_configured('evt', 'warn')
    assert called['n'] == 0


def test_notify_webhook_if_configured_calls_and_swallows(monkeypatch):
    from mcp_win_admin import alerts
    monkeypatch.setattr(alerts.cfg, 'ENABLE_ALERTS', True, raising=False)
    monkeypatch.setenv(alerts.DEFAULT_WEBHOOK_ENV, 'http://example')

    def boom(*a, **k):
        raise RuntimeError('fail')

    monkeypatch.setattr(alerts, 'notify_webhook', boom, raising=True)
    # swallow exceptions
    alerts.notify_webhook_if_configured('evt', 'info', {"a":1})


def test_notify_toast_win10toast(monkeypatch):
    from mcp_win_admin import alerts

    fake_mod = types.ModuleType('win10toast')
    class Notifier:
        def show_toast(self, title, message, duration=5, threaded=True):
            return None
    fake_mod.ToastNotifier = Notifier
    monkeypatch.setitem(sys.modules, 'win10toast', fake_mod)

    out = alerts.notify_toast('Hello', 'World')
    assert out['ok'] is True and out['method'] == 'win10toast'


def test_notify_toast_winrt(monkeypatch):
    from mcp_win_admin import alerts

    # asegurar que win10toast falle
    monkeypatch.setitem(sys.modules, 'win10toast', None)

    # inyectar winrt.* módulos mínimos
    pkg_winrt = types.ModuleType('winrt')
    pkg_windows = types.ModuleType('winrt.windows')
    pkg_ui = types.ModuleType('winrt.windows.ui')
    pkg_notif = types.ModuleType('winrt.windows.ui.notifications')
    pkg_data = types.ModuleType('winrt.windows.data')
    pkg_dom = types.ModuleType('winrt.windows.data.xml')
    pkg_dom2 = types.ModuleType('winrt.windows.data.xml.dom')

    class XmlDocument:
        def load_xml(self, t):
            self.t = t
    pkg_dom2.XmlDocument = XmlDocument

    class Notifier:
        def show(self, notification):
            pass
    class ToastNotification:
        def __init__(self, xml):
            self.xml = xml
    class ToastNotificationManager:
        @staticmethod
        def create_toast_notifier(app):
            return Notifier()

    pkg_notif.ToastNotification = ToastNotification
    pkg_notif.ToastNotificationManager = ToastNotificationManager

    # Link hierarchy attributes (best-effort)
    pkg_winrt.windows = pkg_windows
    pkg_windows.ui = pkg_ui
    pkg_windows.data = pkg_data
    pkg_data.xml = pkg_dom
    pkg_dom.dom = pkg_dom2

    # Register modules in sys.modules for import system
    monkeypatch.setitem(sys.modules, 'winrt', pkg_winrt)
    monkeypatch.setitem(sys.modules, 'winrt.windows', pkg_windows)
    monkeypatch.setitem(sys.modules, 'winrt.windows.ui', pkg_ui)
    monkeypatch.setitem(sys.modules, 'winrt.windows.ui.notifications', pkg_notif)
    monkeypatch.setitem(sys.modules, 'winrt.windows.data', pkg_data)
    monkeypatch.setitem(sys.modules, 'winrt.windows.data.xml', pkg_dom)
    monkeypatch.setitem(sys.modules, 'winrt.windows.data.xml.dom', pkg_dom2)

    out = alerts.notify_toast('Title', 'Msg')
    assert out['ok'] is True and out['method'] == 'winrt'


def test_notify_toast_no_backend(monkeypatch):
    from mcp_win_admin import alerts
    # forzar fallos en ambas importaciones
    monkeypatch.setitem(sys.modules, 'win10toast', None)
    monkeypatch.setitem(sys.modules, 'winrt.windows.ui.notifications', None)
    monkeypatch.setitem(sys.modules, 'winrt.windows.data.xml.dom', None)
    out = alerts.notify_toast('T', 'M')
    assert out['ok'] is False and 'no_toast_backend' in out['error']
