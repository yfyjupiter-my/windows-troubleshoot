"""Read-only checks of the real Windows backend (run by CI on windows-latest; skipped elsewhere).

Nothing here changes the system: only reads, plus one reg export into pytest's tmp dir.
"""
import os
import sys

import pytest

from app_triage.sysapi.base import SignatureInfo, TaskInfo

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="needs real Windows")

UNINSTALL = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
MISSING_KEY = r"HKLM\SOFTWARE\AppTriage-smoke-test-does-not-exist"


@pytest.fixture(scope="module")
def win():
    from app_triage.sysapi.windows import WindowsSystem
    return WindowsSystem()


def test_known_folders_complete_and_existing(win):
    from app_triage.sysapi.fake import FakeSystem
    folders = win.known_folders()
    assert set(folders) == set(FakeSystem().known_folders())
    for name, path in folders.items():
        assert "%" not in path and os.path.isdir(path), (name, path)
    assert win.username()


def test_registry_reads(win):
    assert win.reg_exists(UNINSTALL)
    assert isinstance(win.reg_subkeys(UNINSTALL), list)
    values = win.reg_values(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    assert isinstance(values["CurrentBuild"], str)
    assert not win.reg_exists(MISSING_KEY)
    with pytest.raises(KeyError):
        win.reg_values(MISSING_KEY)


def test_reg_export_writes_file(win, tmp_path):
    dest = tmp_path / "explorer.reg"
    win.reg_export(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer", str(dest))
    assert dest.stat().st_size > 0
    with pytest.raises(KeyError):
        win.reg_export(MISSING_KEY, str(tmp_path / "missing.reg"))


def test_list_services_normalized(win):
    services = win.list_services()
    assert services
    for s in services:
        assert not s.binary_path.startswith("\\") and not s.binary_path.lower().startswith("system32\\"), s
        assert s.start_type in {"auto", "manual", "disabled", "boot", "system"}, s
    assert any(s.name.lower() == "eventlog" for s in services)


def test_list_tasks(win):
    tasks = win.list_tasks()
    assert tasks and all(isinstance(t, TaskInfo) for t in tasks)
    assert any(t.path.lower().startswith("\\microsoft\\windows\\") for t in tasks)


def test_signatures(win):
    sig = win.get_signature(os.path.join(os.environ["SystemRoot"], "explorer.exe"))
    assert sig.status == "valid" and "Microsoft" in sig.publisher, sig
    assert win.get_signature(r"C:\AppTriage-smoke\missing.exe") == SignatureInfo("unknown", "")


def test_filesystem_reads(win):
    root = os.environ["SystemRoot"]
    names = {e.name.lower(): e for e in win.list_dir(root)}
    assert "explorer.exe" in names and not names["explorer.exe"].is_dir and names["explorer.exe"].size > 0
    assert names["system32"].is_dir
    assert win.path_exists(os.path.join(root, "explorer.exe"))
    with pytest.raises(KeyError):
        win.list_dir(r"C:\AppTriage-smoke\missing")
