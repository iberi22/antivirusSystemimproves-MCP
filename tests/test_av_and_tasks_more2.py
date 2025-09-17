from pathlib import Path
import types
import pytest

from mcp_win_admin import av
from mcp_win_admin import tasks


def test_hash_files_with_invalid_path():
    out = av.hash_files([Path('this_file_should_not_exist_123456.tmp')])
    assert isinstance(out, list) and out and 'error' in out[0]


def test_scan_path_handles_hash_error(tmp_path, monkeypatch):
    f = tmp_path / 'file.bin'
    f.write_bytes(b'abc')

    def boom(path, algo):
        raise IOError('cannot read')

    monkeypatch.setattr(av, '_hash_file', boom, raising=True)
    res = av.scan_path(str(tmp_path), recursive=False, use_cloud=False)
    # One file with error
    assert any('error' in r for r in res)


def test_walk_files_non_recursive_limit(tmp_path):
    base = tmp_path / 'root'
    base.mkdir()
    (base / 'a.txt').write_text('a')
    (base / 'b.txt').write_text('b')
    (base / 'sub').mkdir()
    (base / 'sub' / 'c.txt').write_text('c')

    items = list(av._walk_files(base, recursive=False, limit=1))
    assert len(items) == 1
    assert items[0].parent == base


def test_tasks_dictreader_raises(monkeypatch):
    # Force csv.DictReader creation to raise and hit outer except branch
    import csv

    def bad_reader(*a, **k):
        raise RuntimeError('csv broken')

    class Proc:
        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run(*a, **k):
        return Proc('header\nrow')

    monkeypatch.setattr(tasks.subprocess, 'run', fake_run, raising=True)
    monkeypatch.setattr(csv, 'DictReader', bad_reader, raising=True)
    out = tasks.list_scheduled_tasks()
    assert isinstance(out, list) and out and 'error' in out[0]


def test_teamcymru_socket_fallback(monkeypatch):
    # Disable dnspython so socket path is used
    monkeypatch.setenv('MHR_USE_DNSPYTHON', '0')
    import socket as pysocket

    def gethostbyname(name):
        return '127.0.0.1'

    monkeypatch.setattr(pysocket, 'gethostbyname', gethostbyname, raising=True)
    out = av.teamcymru_mhr_lookup_hash('a'*64)
    assert out['verdict'] == 'unknown' and out.get('ip') == '127.0.0.1'


def test_teamcymru_socket_error(monkeypatch):
    monkeypatch.setenv('MHR_USE_DNSPYTHON', '0')
    import socket as pysocket
    def boom(name):
        raise OSError('dns fail')
    monkeypatch.setattr(pysocket, 'gethostbyname', boom, raising=True)
    out = av.teamcymru_mhr_lookup_hash('b'*64)
    assert out['verdict'] == 'unknown'
