from app_triage.models import Finding, Risk
from app_triage.scanners import base
from app_triage.scanners.base import run_scan
from app_triage.sysapi.base import AccessDenied
from app_triage.sysapi.fake import FakeSystem


def test_failing_scanner_does_not_abort_scan(monkeypatch):
    def boom(sys): raise AccessDenied(r"HKLM\X")
    def ok(sys): return [Finding("a", "x", "t", {}, Risk.LOW, [])]
    monkeypatch.setattr(base, "SCANNERS", {"boom": ("坏", boom), "ok": ("好", ok)})
    r = run_scan(FakeSystem())
    assert [f.id for f in r.findings] == ["a"]
    assert "boom" in r.errors and "权限" in r.errors["boom"]


def test_generic_exception_is_reported_with_type(monkeypatch):
    def boom(sys): raise ValueError("bad value")
    monkeypatch.setattr(base, "SCANNERS", {"boom": ("坏", boom)})
    r = run_scan(FakeSystem())
    assert r.findings == []
    assert r.errors["boom"] == "扫描出错：ValueError: bad value"


def test_run_scan_subset_and_progress():
    seen = []; run_scan(FakeSystem(), ["installed"], progress=seen.append)
    assert seen == ["正在扫描：已安装程序"]


def test_run_scan_all_in_registration_order(monkeypatch):
    seen = []
    monkeypatch.setattr(base, "SCANNERS", {"a": ("甲", lambda s: []), "b": ("乙", lambda s: [])})
    run_scan(FakeSystem(), progress=seen.append)
    assert seen == ["正在扫描：甲", "正在扫描：乙"]
