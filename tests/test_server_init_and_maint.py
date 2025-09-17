import importlib
import sys
import time
import types

import pytest


def test_server_init_db_log_event_failure_caught(monkeypatch):
    # Import modules
    import mcp_win_admin.db as dbmod
    import mcp_win_admin.config as cfg
    import mcp_win_admin.server as server

    # Ensure maintenance thread won't start
    monkeypatch.setattr(cfg, 'DB_MAINT_ENABLED', False, raising=False)

    # Force init_db to raise, and log_event to also raise to hit inner except: pass (lines 36-37)
    monkeypatch.setattr(dbmod, 'init_db', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('init fail')))
    monkeypatch.setattr(dbmod, 'log_event', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('log fail')))

    # Reload server to execute top-level init try/except
    importlib.reload(server)

    # If we reach here without exception, inner except: pass was executed
    assert hasattr(server, 'mcp')


def test_server_maint_on_start_purge_called(monkeypatch):
    # Import modules
    import mcp_win_admin.db as dbmod
    import mcp_win_admin.config as cfg
    import mcp_win_admin.server as server

    # Activate maintenance thread with on-start actions
    monkeypatch.setattr(cfg, 'DB_MAINT_ENABLED', True, raising=False)
    monkeypatch.setattr(cfg, 'DB_MAINT_ON_START', True, raising=False)
    monkeypatch.setattr(cfg, 'DB_PURGE_EVENTS_TTL_SECONDS', 1, raising=False)
    monkeypatch.setattr(cfg, 'DB_PURGE_REP_TTL_SECONDS', 1, raising=False)
    monkeypatch.setattr(cfg, 'DB_PURGE_HASH_TTL_SECONDS', 1, raising=False)

    # Make optimize_db safe and fast
    monkeypatch.setattr(dbmod, 'optimize_db', lambda *a, **k: {'ok': True})

    called = {'purge': 0}

    def fake_purge(*, events_ttl_seconds=None, reputation_ttl_seconds=None, hash_ttl_seconds=None, db_path=None):
        called['purge'] += 1
        return {'events_deleted': 0, 'reputation_deleted': {}, 'av_hash_deleted': 0}

    monkeypatch.setattr(dbmod, 'purge_old_data', fake_purge)

    # Reload server to start thread and execute on-start purge
    importlib.reload(server)

    # Give a short time for the background thread to execute the on-start block
    time.sleep(0.1)

    assert called['purge'] >= 1


def test_server_maint_on_start_optimize_error_logged(monkeypatch):
    import mcp_win_admin.db as dbmod
    import mcp_win_admin.config as cfg
    import mcp_win_admin.server as server

    # Enable maintenance and on-start
    monkeypatch.setattr(cfg, 'DB_MAINT_ENABLED', True, raising=False)
    monkeypatch.setattr(cfg, 'DB_MAINT_ON_START', True, raising=False)

    # Force optimize_db to fail; purge returns
    monkeypatch.setattr(dbmod, 'optimize_db', lambda *a, **k: (_ for _ in ()).throw(RuntimeError('opt fail')))
    monkeypatch.setattr(dbmod, 'purge_old_data', lambda **k: {'ok': True}, raising=True)

    logs = []
    def fake_log_event(level, message, code=None, db_path=None):
        logs.append((level, message))
        return {'ok': True}

    monkeypatch.setattr(dbmod, 'log_event', fake_log_event, raising=True)

    # Reload to execute on-start block
    import importlib
    importlib.reload(server)

    assert any('optimize_db on start failed' in msg for _, msg in logs)


def test_server_maint_on_start_purge_error_logged(monkeypatch):
    import mcp_win_admin.db as dbmod
    import mcp_win_admin.config as cfg
    import mcp_win_admin.server as server

    # Enable maintenance and on-start
    monkeypatch.setattr(cfg, 'DB_MAINT_ENABLED', True, raising=False)
    monkeypatch.setattr(cfg, 'DB_MAINT_ON_START', True, raising=False)

    # optimize ok; purge fails
    monkeypatch.setattr(dbmod, 'optimize_db', lambda *a, **k: {'ok': True})
    monkeypatch.setattr(dbmod, 'purge_old_data', lambda **k: (_ for _ in ()).throw(RuntimeError('purge fail')), raising=True)

    logs = []
    def fake_log_event(level, message, code=None, db_path=None):
        logs.append((level, message))
        return {'ok': True}

    monkeypatch.setattr(dbmod, 'log_event', fake_log_event, raising=True)

    # Reload to execute on-start block
    import importlib
    importlib.reload(server)

    assert any('purge_old_data on start failed' in msg for _, msg in logs)
