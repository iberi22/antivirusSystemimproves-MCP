import json
import types

import pytest

import mcp_win_admin.server as server


class DummySnap:
    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return self._data


def test_system_scan_performance_persist(monkeypatch):
    snap = DummySnap({"ok": True})
    monkeypatch.setattr(server.sysmod, "get_performance_snapshot", lambda: snap)

    # persist = True
    ins = {"called": False}
    def insert_snapshot(d):
        ins["called"] = True
        assert d == {"ok": True}
        return 123
    monkeypatch.setattr(server.db, "insert_snapshot", insert_snapshot)
    res = server.system_scan_performance(persist=True)
    assert res["snapshot"] == {"ok": True}
    assert res["persisted_id"] == 123

    # persist = False
    res2 = server.system_scan_performance(persist=False)
    assert res2["snapshot"] == {"ok": True}
    assert res2["persisted_id"] is None


def test_processes_and_profiles_and_last_snapshot(monkeypatch):
    # processes_list clamps
    monkeypatch.setattr(server.cfg, "clamp_limit", lambda n, _: 5)
    called = {}
    def fake_list_processes(**kwargs):
        called.update(kwargs)
        return [{"pid": 1}]
    monkeypatch.setattr(server.procmod, "list_processes", fake_list_processes)
    out = server.processes_list(limit=100, sort_by="cpu", fast=False, include_cpu=True)
    assert out == [{"pid": 1}]
    assert called == {"limit": 5, "sort_by": "cpu", "fast": False, "include_cpu": True}

    # profiles
    monkeypatch.setattr(server.profmod, "list_profiles", lambda: [{"name": "GameBooster"}])
    assert server.profiles_list() == [{"name": "GameBooster"}]

    monkeypatch.setattr(server.profmod, "preview_profile", lambda name: {"name": name, "actions": []})
    assert server.profiles_preview("GameBooster") == {"name": "GameBooster", "actions": []}

    # last_snapshot
    monkeypatch.setattr(server.db, "get_last_snapshot", lambda: {"k": "v"})
    s = server.last_snapshot()
    assert json.loads(s) == {"k": "v"}
    # none -> message
    monkeypatch.setattr(server.db, "get_last_snapshot", lambda: None)
    s2 = server.last_snapshot()
    assert json.loads(s2)["message"].startswith("No hay snapshots")


def test_db_tools(monkeypatch):
    monkeypatch.setattr(server.db, "optimize_db", lambda: {"ok": True})
    assert server.db_optimize() == {"ok": True}

    def boom(**_k):
        raise RuntimeError("fail")
    monkeypatch.setattr(server.db, "optimize_db", boom)
    r = server.db_optimize()
    assert r["ok"] is False and "fail" in r["error"]

    monkeypatch.setattr(server.db, "purge_old_data", lambda **k: {"ok": True, "args": k})
    r2 = server.db_purge_old(1, 2, 3)
    assert r2["ok"] is True and r2["args"]["events_ttl_seconds"] == 1

    monkeypatch.setattr(server.db, "purge_old_data", boom)
    r3 = server.db_purge_old()
    assert r3["ok"] is False and "fail" in r3["error"]


def test_av_tools(monkeypatch):
    monkeypatch.setattr(server.cfg, "effective_rep_ttl", lambda x: 42)

    seen = {}
    def fake_check_hash(h, **k):
        seen["check_hash"] = (h, k)
        return {"hash": h, "args": k}
    monkeypatch.setattr(server.avmod, "check_hash", fake_check_hash)

    out = server.av_check_hash("aa", algo="md5", use_cloud=False, ttl_seconds=-1, sources_csv="vt, teamcymru")
    assert out["hash"] == "aa"
    assert seen["check_hash"][1]["ttl_seconds"] == 42
    assert seen["check_hash"][1]["sources"] == ("vt", "teamcymru")

    def fake_scan_path(target, **k):
        seen["scan_path"] = (target, k)
        return [{"p": target}]
    monkeypatch.setattr(server.avmod, "scan_path", fake_scan_path)

    out2 = server.av_scan_path("/tmp", recursive=False, limit=10, algo="sha1", use_cloud=True, ttl_seconds=7, sources_csv="mb,tc")
    assert out2 == [{"p": "/tmp"}]
    assert seen["scan_path"][1]["sources"] == ("mb", "tc")
    assert seen["scan_path"][1]["ttl_seconds"] == 42


def test_services_connections_events_startup_tasks(monkeypatch):
    monkeypatch.setattr(server.cfg, "clamp_limit", lambda n, _: 10)

    # services
    seen = {}
    def _list_services_mock(**k):
        seen.setdefault("svc", k)
        return [{"s": 1}]
    monkeypatch.setattr(server.svcmod, "list_services", _list_services_mock)
    assert server.services_list(status="running", limit=200) == [{"s": 1}]
    assert seen["svc"]["status"] == "running" and seen["svc"]["limit"] == 10

    # connections
    def _list_connections_mock(**k):
        seen.setdefault("conn", k)
        return [{"c": 1}]
    monkeypatch.setattr(server.conmod, "list_connections", _list_connections_mock)
    assert server.connections_list(limit=100, kind="inet6", listening_only=True, include_process=True) == [{"c": 1}]
    assert seen["conn"]["limit"] == 10 and seen["conn"]["kind"] == "inet6"

    # events
    monkeypatch.setattr(server.evtmod, "list_events", lambda **k: [{"e": 1, **k}])
    assert server.events_list(channel="App", limit=5) == [{"e": 1, "channel": "App", "limit": 5}]

    # startup
    monkeypatch.setattr(server.stmod, "list_startup", lambda **k: [{"st": 1, **k}])
    assert server.startup_list(limit=3) == [{"st": 1, "limit": 3}]

    # tasks
    monkeypatch.setattr(server.tmod, "list_scheduled_tasks", lambda **k: [{"t": 1, **k}])
    assert server.tasks_list(limit=9, state="Ready") == [{"t": 1, "limit": 9, "state": "Ready"}]


def test_integrity_tools(monkeypatch):
    monkeypatch.setattr(server.intmod, "build_baseline", lambda **k: {"ok": True, **k})
    assert server.integrity_build_baseline("base", "C:/", algo="md5", recursive=False, limit=2)["name"] == "base"

    monkeypatch.setattr(server.intmod, "verify_baseline", lambda **k: {"diff": [], **k})
    out = server.integrity_verify_baseline("base", recursive=False, limit=3, algo="")
    assert out["name"] == "base" and out["recursive"] is False and out["algo"] == ""

    monkeypatch.setattr(server.intmod, "list_baselines", lambda: [{"name": "a"}])
    assert server.integrity_list_baselines() == [{"name": "a"}]

    monkeypatch.setattr(server.intmod, "diff_baselines", lambda a, b: {"a": a, "b": b, "changes": []})
    assert server.integrity_diff_baselines("a", "b")["a"] == "a"


def test_reputation_tools_and_connections_enriched(monkeypatch):
    # rep_check_ip/domain: ttl_by_source parsing
    monkeypatch.setattr(server.cfg, "effective_rep_ttl", lambda x: 99)

    seen = {"ip": None, "domain": None}
    def fake_check_ip(ip, **k):
        seen["ip"] = (ip, k)
        return {"ip": ip, "k": k}
    monkeypatch.setattr(server.repmod, "check_ip", fake_check_ip)

    def fake_check_domain(domain, **k):
        seen["domain"] = (domain, k)
        return {"domain": domain, "k": k}
    monkeypatch.setattr(server.repmod, "check_domain", fake_check_domain)

    # invalid json -> None
    out = server.rep_check_ip("1.1.1.1", ttl_by_source_json="not-json")
    assert out["ip"] == "1.1.1.1"
    assert seen["ip"][1]["ttl_by_source"] is None

    out2 = server.rep_check_domain("example.com", ttl_by_source_json='{"otx": 3600}')
    assert out2["domain"] == "example.com"
    assert seen["domain"][1]["ttl_by_source"]["otx"] == 3600

    # connections_list_enriched
    monkeypatch.setattr(server.cfg, "clamp_limit", lambda n, _: 10)
    base_items = [
        {"raddr": "1.2.3.4:443", "i": 0},
        {"raddr": "1.2.3.4:80", "i": 1},  # duplicate ip
        {"raddr": "", "i": 2},
        {"i": 3},  # no raddr
        {"raddr": "5.6.7.8:53", "i": 4},
    ]
    monkeypatch.setattr(server.conmod, "list_connections", lambda **k: base_items)

    def rep_ip(ip, **k):
        if ip == "1.2.3.4":
            return {"ip": ip, "verdict": "malicious"}
        raise RuntimeError("boom")
    monkeypatch.setattr(server.repmod, "check_ip", rep_ip)

    enr = server.connections_list_enriched(limit=5)
    # First two have same IP and should get reputation
    assert enr[0]["reputation"]["verdict"] == "malicious"
    assert enr[1]["reputation"]["verdict"] == "malicious"
    # Error path -> unknown
    assert enr[4]["reputation"]["verdict"] == "unknown"


def test_yara_drivers_rootkit_firewall_updates(monkeypatch):
    # YARA
    monkeypatch.setattr(server.yaramod, "scan_path", lambda target, **k: [{"ok": True, "target": target, **k}])
    assert server.yara_scan_path("/tmp", rule_text="rule X", recursive=False, limit=1)[0]["ok"] is True
    monkeypatch.setattr(server.yaramod, "test_rule", lambda rule_text, sample_path: {"ok": True, "rule_text": rule_text, "sample_path": sample_path})
    assert server.yara_test_rule("rule X", "sample.bin")["ok"] is True

    # drivers
    monkeypatch.setattr(server.drvmod, "list_drivers", lambda **k: [{"d": 1}])
    assert server.drivers_list(limit=2) == [{"d": 1}]

    # rootkit
    monkeypatch.setattr(server.rkmod, "detect_hidden_processes", lambda **k: [{"x": 1}])
    assert server.rootkit_detect_hidden_processes(limit=1) == [{"x": 1}]
    monkeypatch.setattr(server.rkmod, "check_port_owners", lambda **k: [{"y": 1}])
    assert server.rootkit_check_port_owners(limit=2) == [{"y": 1}]

    # firewall
    monkeypatch.setattr(server.fwmod, "list_rules", lambda **k: [{"r": 1}])
    assert server.firewall_list_rules(limit=3) == [{"r": 1}]
    monkeypatch.setattr(server.fwmod, "export_rules", lambda file_path: {"ok": True, "file_path": file_path})
    assert server.firewall_export_rules("out.wfw")["file_path"] == "out.wfw"
    monkeypatch.setattr(server.fwmod, "block_ip_dryrun", lambda ip: {"cmd": f"netsh deny {ip}"})
    assert server.firewall_block_ip_dryrun("8.8.8.8")["cmd"].startswith("netsh")

    # updates
    monkeypatch.setattr(server.upmod, "list_installed", lambda **k: [{"u": 1, **k}])
    assert server.updates_list_installed(limit=4) == [{"u": 1, "limit": 4}]
    monkeypatch.setattr(server.upmod, "trigger_scan_dryrun", lambda: {"cmd": "UsoClient.exe StartScan"})
    assert server.updates_trigger_scan_dryrun()["cmd"].endswith("StartScan")


def test_telemetry_defense_alerts_usn(monkeypatch):
    # telemetry
    monkeypatch.setattr(server.db, "list_events", lambda **k: [{"e": 1, **k}])
    assert server.telemetry_list_events(limit=2) == [{"e": 1, "limit": 2}]

    # defense dryrun/exec
    monkeypatch.setattr(server.defmod, "quarantine_dryrun", lambda p: {"p": p})
    assert server.defense_quarantine_dryrun("a")["p"] == "a"
    monkeypatch.setattr(server.defmod, "kill_process_dryrun", lambda pid: {"pid": pid})
    assert server.defense_kill_process_dryrun(11)["pid"] == 11
    monkeypatch.setattr(server.defmod, "quarantine_bulk_dryrun", lambda paths: [{"p": p} for p in paths])
    assert len(server.defense_quarantine_bulk_dryrun("a,b")) == 2

    monkeypatch.setattr(server.defmod, "quarantine_execute", lambda p, **k: {"p": p, **k})
    assert server.defense_quarantine_execute("f", confirm=True, policy_name="Balanced")["confirm"] is True
    monkeypatch.setattr(server.defmod, "kill_process_execute", lambda pid, **k: {"pid": pid, **k})
    assert server.defense_kill_process_execute(22, confirm=False, policy_name="Strict")["policy_name"] == "Strict"

    monkeypatch.setattr(server.defmod, "process_isolate_dryrun", lambda pid: {"pid": pid})
    assert server.defense_process_isolate_dryrun(33)["pid"] == 33
    monkeypatch.setattr(server.defmod, "process_isolate_execute", lambda pid, **k: {"pid": pid, **k})
    assert server.defense_process_isolate_execute(44, confirm=True)["confirm"] is True
    monkeypatch.setattr(server.defmod, "process_unsandbox_execute", lambda pid, **k: {"pid": pid, **k})
    assert server.defense_process_unsandbox_execute(55, confirm=False)["confirm"] is False

    # alerts
    seen = {}
    monkeypatch.setattr(server.alertmod, "notify_webhook_if_configured", lambda *a, **k: seen.setdefault("env", True))
    r = server.alert_notify_webhook("evt", data_json="{\"x\":1}")
    assert r["ok"] is True and r["used_env"] is True and seen.get("env") is True

    called = {}
    def fake_notify_webhook(url, event, level, data):
        called["args"] = (url, event, level, data)
        return {"ok": True}
    monkeypatch.setattr(server.alertmod, "notify_webhook", fake_notify_webhook)
    r2 = server.alert_notify_webhook("evt2", level="WARN", data_json="not-json", url="http://u")
    assert called["args"][0] == "http://u" and called["args"][1] == "evt2" and called["args"][3] == {}

    monkeypatch.setattr(server.alertmod, "notify_toast", lambda title, message: {"title": title, "message": message})
    assert server.alert_notify_toast("t", "m")["title"] == "t"

    # usn
    monkeypatch.setattr(server.usnmod, "query_usn_info", lambda drive: {"drive": drive})
    assert server.usn_query_info("D")["drive"] == "D"
