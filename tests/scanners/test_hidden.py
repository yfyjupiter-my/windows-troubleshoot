from app_triage.models import ActionSpec, Risk
from app_triage.scanners.base import SCANNERS
from app_triage.scanners.hidden import scan_hidden
from app_triage.sysapi.base import SignatureInfo
from app_triage.sysapi.fake import FakeSystem

ROAMING = r"C:\Users\tester\AppData\Roaming"
LOCAL = r"C:\Users\tester\AppData\Local"
PROFILE = r"C:\Users\tester"


def test_registered_under_hidden_label():
    assert SCANNERS["hidden"][0] == "隐藏的可执行文件"


def test_hidden_unsigned_exe_in_appdata_reported():
    s = FakeSystem()
    path = ROAMING + r"\Foo\svc.exe"
    s.add_file(path, size=42, hidden=True)
    s.set_signature(path, SignatureInfo("unsigned", ""))
    findings = scan_hidden(s)
    assert len(findings) == 1  # AppData sits under UserProfile: reported once
    f = findings[0]
    assert f.category == "hidden"
    assert f.risk is Risk.MEDIUM
    assert f.evidence["path"] == path
    assert f.actions == [ActionSpec("quarantine_path", path)]
    assert f.vendor is None


def test_vendor_match_is_medium_and_signed_other_is_low():
    s = FakeSystem()
    v = LOCAL + r"\Kingsoft\ksolaunch.exe"
    other = LOCAL + r"\Acme\tool.dll"
    s.add_file(v, system=True)
    s.add_file(other, hidden=True)
    s.set_signature(other, SignatureInfo("valid", "Acme Corp"))
    by = {f.evidence["path"]: f for f in scan_hidden(s)}
    assert by[v].risk is Risk.MEDIUM and by[v].vendor == "WPS (金山办公)"
    assert by[other].risk is Risk.LOW


def test_hidden_microsoft_signed_skipped():
    s = FakeSystem()
    path = LOCAL + r"\Microsoft\OneDrive\OneDrive.exe"
    s.add_file(path, hidden=True)
    s.set_signature(path, SignatureInfo("valid", "Microsoft Corporation"))
    assert scan_hidden(s) == []


def test_non_hidden_or_non_exe_ignored():
    s = FakeSystem()
    s.add_file(ROAMING + r"\Foo\visible.exe")
    s.add_file(ROAMING + r"\Foo\hidden.txt", hidden=True)
    s.add_file(ROAMING + r"\Foo\hidden.dat", system=True)
    assert scan_hidden(s) == []


def test_depth_limits():
    s = FakeSystem()
    ok = ROAMING + r"\a\b\c.exe"  # depth 3 under AppData
    too_deep = ROAMING + r"\a\b\c\d.exe"
    profile_deep = PROFILE + r"\Docs\x.exe"  # UserProfile only scans depth 1
    profile_top = PROFILE + r"\top.exe"
    for p in (ok, too_deep, profile_deep, profile_top):
        s.add_file(p, hidden=True)
    paths = {f.evidence["path"] for f in scan_hidden(s)}
    assert paths == {ok, profile_top}


def test_access_denied_subdir_skipped():
    s = FakeSystem()
    s.add_file(ROAMING + r"\Locked\secret.exe", hidden=True)
    s.add_file(ROAMING + r"\Open\bad.exe", hidden=True)
    s.deny(ROAMING + r"\Locked")
    paths = {f.evidence["path"] for f in scan_hidden(s)}
    assert paths == {ROAMING + r"\Open\bad.exe"}
