"""WindowsSystem decision logic, run on any OS by stubbing processes, winreg and os calls."""
import os
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from app_triage.sysapi import windows
from app_triage.sysapi.base import AccessDenied, SignatureInfo
from app_triage.sysapi.windows import WindowsSystem


def _proc(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def _winerror(code: int) -> OSError:
    e = OSError(f"WinError {code}")
    e.winerror = code
    return e


# ---- _check: exit code / text -> exception ---------------------------------------------------

def test_check_maps_exit_codes_and_text():
    assert windows._check(_proc(0, "out"), "x") == "out"
    with pytest.raises(KeyError):
        windows._check(_proc(3), "x")
    with pytest.raises(AccessDenied):
        windows._check(_proc(5), "x")
    with pytest.raises(AccessDenied):
        windows._check(_proc(1, "", "错误: 拒绝访问。"), "x")
    with pytest.raises(KeyError):
        windows._check(_proc(1060), "svc", missing=(1060,))
    with pytest.raises(OSError, match="boom"):
        windows._check(_proc(1, "", "boom"), "x")


# ---- listings survive one corrupt entry -------------------------------------------------------

def test_listings_ask_powershell_to_continue_past_bad_entries():
    assert "-ErrorAction SilentlyContinue" in windows._SERVICES_PS
    assert "-ErrorAction SilentlyContinue" in windows._TASKS_PS


def test_list_services_uses_stdout_despite_nonzero_exit(monkeypatch):
    out = ('{"Name": "drv", "DisplayName": "d", "PathName": "\\\\SystemRoot\\\\System32\\\\drivers\\\\d.sys", '
           '"StartMode": "Boot", "State": "Running"}')
    monkeypatch.setattr(windows, "_powershell", lambda script, timeout=180: _proc(1, out, "one service failed"))
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    [svc] = WindowsSystem().list_services()
    assert svc.binary_path == r"C:\Windows\System32\drivers\d.sys" and svc.start_type == "boot"


def test_list_tasks_uses_stdout_despite_nonzero_exit_but_fails_when_empty(monkeypatch):
    out = '{"TaskPath": "\\\\", "TaskName": "坏任务旁边的好任务", "State": 3, "Author": "", "Command": "a.exe"}'
    monkeypatch.setattr(windows, "_powershell", lambda script, timeout=180: _proc(1, out, "err"))
    assert [t.path for t in WindowsSystem().list_tasks()] == ["\\坏任务旁边的好任务"]
    monkeypatch.setattr(windows, "_powershell", lambda script, timeout=180: _proc(1, "", "broken"))
    with pytest.raises(OSError):
        WindowsSystem().list_tasks()


# ---- scheduled task names are literal, not wildcards -----------------------------------------

def test_set_task_enabled_escapes_wildcards(monkeypatch):
    scripts = []
    monkeypatch.setattr(windows, "_powershell", lambda script, timeout=180: scripts.append(script) or _proc(0))
    WindowsSystem().set_task_enabled("\\2345Soft\\更新[每日]", False)
    assert "-TaskPath ([WildcardPattern]::Escape('\\2345Soft\\'))" in scripts[0]
    assert "-TaskName ([WildcardPattern]::Escape('更新[每日]'))" in scripts[0]
    assert "Disable-ScheduledTask" in scripts[0]


# ---- signatures: failures are "unknown" and not cached ---------------------------------------

def test_get_signature_failures_return_unknown_and_are_not_cached(monkeypatch):
    monkeypatch.setattr(windows.os.path, "isfile", lambda p: True)
    results = [subprocess.TimeoutExpired("powershell", 180), FileNotFoundError("powershell"),
               _proc(1, "", "err"), _proc(0, "not json"),
               _proc(0, '{"Status": "Valid", "Publisher": "CN=Microsoft Windows, O=Microsoft"}')]

    def fake_ps(script, timeout=180):
        r = results.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r

    monkeypatch.setattr(windows, "_powershell", fake_ps)
    win = WindowsSystem()
    for _ in range(4):
        assert win.get_signature(r"C:\x\a.exe") == SignatureInfo("unknown", "")
    assert win.get_signature(r"C:\x\a.exe") == SignatureInfo("valid", "Microsoft Windows")
    assert win.get_signature(r"c:\X\A.exe") == SignatureInfo("valid", "Microsoft Windows")  # cached
    assert results == []


# ---- take ownership enables the privileges and reports step-1 failures ------------------------

def test_take_ownership_script_enables_privileges_and_reports_failures(monkeypatch):
    scripts = []
    monkeypatch.setattr(windows, "_powershell", lambda script, timeout=180: scripts.append(script) or _proc(0))
    WindowsSystem().reg_take_ownership(r"HKCU\Software\X\.jpg\UserChoice")
    s = scripts[0]
    assert "AdjustTokenPrivileges" in s
    assert "'SeTakeOwnershipPrivilege'" in s and "'SeRestorePrivilege'" in s
    assert s.index("SeTakeOwnershipPrivilege'") < s.index("TakeOwnership)")
    assert r"'Software\X\.jpg\UserChoice'" in s and "CurrentUser" in s
    assert "catch { }" not in s and "catch {}" not in s


# ---- reg_delete_key checks the whole subtree before deleting anything -------------------------

class _Handle:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeWinreg:
    HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT = "HKLM", "HKCU", "HKCR"
    KEY_READ, KEY_WOW64_64KEY = 0x20019, 0x100

    def __init__(self, keys, delete_denied=()):
        self.keys = set(keys)
        self.delete_denied = set(delete_denied)
        self.deleted = []

    def OpenKeyEx(self, root, sub, reserved, access):
        path = f"{root}\\{sub}"
        if path not in self.keys:
            raise FileNotFoundError(path)
        if path in self.delete_denied and access & windows._DELETE:
            raise PermissionError(path)
        return _Handle(path)

    def EnumKey(self, handle, i):
        children = sorted(k.rsplit("\\", 1)[1] for k in self.keys if k.rsplit("\\", 1)[0] == handle.path)
        if i >= len(children):
            raise _winerror(259)
        return children[i]

    def DeleteKeyEx(self, root, sub, access, reserved):
        self.deleted.append(f"{root}\\{sub}")
        self.keys.discard(f"{root}\\{sub}")


def _fake_winreg(monkeypatch, keys, delete_denied=()):
    fake = _FakeWinreg(keys, delete_denied)
    monkeypatch.setattr(windows, "winreg", fake, raising=False)
    return fake


TREE = [r"HKCU\Software", r"HKCU\Software\V", r"HKCU\Software\V\a", r"HKCU\Software\V\a\deep",
        r"HKCU\Software\V\b"]


def test_reg_delete_key_denied_child_deletes_nothing(monkeypatch):
    fake = _fake_winreg(monkeypatch, TREE, delete_denied=[r"HKCU\Software\V\b"])
    with pytest.raises(AccessDenied):
        WindowsSystem().reg_delete_key(r"HKCU\Software\V")
    assert fake.deleted == [] and set(TREE) == fake.keys


def test_reg_delete_key_deletes_children_first(monkeypatch):
    fake = _fake_winreg(monkeypatch, TREE)
    WindowsSystem().reg_delete_key(r"HKCU\Software\V")
    assert fake.deleted == [r"HKCU\Software\V\a\deep", r"HKCU\Software\V\a", r"HKCU\Software\V\b",
                            r"HKCU\Software\V"]
    with pytest.raises(KeyError):
        WindowsSystem().reg_delete_key(r"HKCU\Software\V")


# ---- list_dir: reparse points are never reported as directories -------------------------------

class _Entry:
    def __init__(self, name, is_dir, attrs, size=0):
        self.name, self.path, self._dir = name, rf"C:\Users\t\{name}", is_dir
        self._st = SimpleNamespace(st_file_attributes=attrs, st_size=size)

    def is_dir(self, follow_symlinks=True):
        return self._dir

    def stat(self, follow_symlinks=True):
        return self._st


class _Scan(list):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_list_dir_reparse_points_are_not_directories(monkeypatch):
    entries = [_Entry("Application Data", True, 0x10 | 0x400 | 0x2 | 0x4),
               _Entry("AppData", True, 0x10 | 0x2), _Entry("a.exe", False, 0x20, size=42)]
    monkeypatch.setattr(windows.os, "scandir", lambda path: _Scan(entries))
    got = {e.name: e for e in WindowsSystem().list_dir(r"C:\Users\t")}
    junction = got["Application Data"]
    assert not junction.is_dir and junction.hidden and junction.system and junction.size == 0
    assert got["AppData"].is_dir and got["AppData"].hidden and not got["AppData"].system
    assert not got["a.exe"].is_dir and got["a.exe"].size == 42


def test_list_dir_other_os_errors_become_access_denied(monkeypatch):
    def unreadable(path):
        raise _winerror(1920)  # ERROR_CANT_ACCESS_FILE (e.g. a broken cloud placeholder)
    monkeypatch.setattr(windows.os, "scandir", unreadable)
    with pytest.raises(AccessDenied):
        WindowsSystem().list_dir(r"C:\Users\t\OneDrive")

    class _Failing(_Scan):
        def __iter__(self):
            yield _Entry("a.exe", False, 0x20)
            raise OSError(5, "I/O error mid-listing")
    monkeypatch.setattr(windows.os, "scandir", lambda path: _Failing())
    with pytest.raises(AccessDenied):
        WindowsSystem().list_dir(r"C:\Users\t")


# ---- move: rename only; cross-volume via a staged rename ------------------------------------

@pytest.fixture
def app(tmp_path):
    src = tmp_path / "vol1" / "Vendor"
    (src / "sub").mkdir(parents=True)
    (src / "a.exe").write_text("A")
    (src / "sub" / "b.dll").write_text("B")
    dst = tmp_path / "vol2" / "q" / "0_Vendor"
    (tmp_path / "vol2").mkdir()
    return src, dst


def _tree(path):
    return sorted(p.relative_to(path).as_posix() for p in path.rglob("*"))  # same on every OS


def test_move_permission_error_is_access_denied_and_never_copies(monkeypatch, app):
    src, dst = app
    def locked(a, b):
        raise PermissionError(13, "in use")
    monkeypatch.setattr(windows.os, "rename", locked)
    monkeypatch.setattr(windows.shutil, "copytree", lambda *a, **k: pytest.fail("must not copy"))
    with pytest.raises(AccessDenied):
        WindowsSystem().move(str(src), str(dst))
    assert _tree(src) == ["a.exe", "sub", "sub/b.dll"]


def _cross_device(monkeypatch, dst, staged_error=None):
    real = os.rename

    def rename(a, b):
        if str(b) == str(dst):
            raise _winerror(17)  # ERROR_NOT_SAME_DEVICE
        if staged_error is not None and ".apptriage-" in str(b):
            raise staged_error
        return real(a, b)
    monkeypatch.setattr(windows.os, "rename", rename)


def test_move_across_volumes_copies_then_removes_staged_original(monkeypatch, app):
    src, dst = app
    _cross_device(monkeypatch, dst)
    WindowsSystem().move(str(src), str(dst))
    assert _tree(dst) == ["a.exe", "sub", "sub/b.dll"] and (dst / "sub" / "b.dll").read_text() == "B"
    assert not src.exists() and os.listdir(src.parent) == []


def test_move_across_volumes_failed_copy_restores_original(monkeypatch, app):
    src, dst = app
    _cross_device(monkeypatch, dst)

    def partial_copy(s, d, **kw):
        os.makedirs(d)
        shutil.copy2(os.path.join(s, "a.exe"), d)
        raise OSError(28, "disk full")
    monkeypatch.setattr(windows.shutil, "copytree", partial_copy)
    with pytest.raises(OSError, match="disk full"):
        WindowsSystem().move(str(src), str(dst))
    assert _tree(src) == ["a.exe", "sub", "sub/b.dll"]
    assert not dst.exists() and os.listdir(src.parent) == ["Vendor"]


def test_move_across_volumes_locked_staging_is_access_denied(monkeypatch, app):
    src, dst = app
    _cross_device(monkeypatch, dst, staged_error=PermissionError(13, "in use"))
    with pytest.raises(AccessDenied):
        WindowsSystem().move(str(src), str(dst))
    assert _tree(src) == ["a.exe", "sub", "sub/b.dll"] and not dst.exists()


def test_move_single_file_across_volumes(monkeypatch, app):
    src, dst = app
    f, target = src / "a.exe", dst.parent / "1_a.exe"
    _cross_device(monkeypatch, target)
    WindowsSystem().move(str(f), str(target))
    assert target.read_text() == "A" and not f.exists() and sorted(os.listdir(src)) == ["sub"]


def test_move_missing_src_and_existing_dst(app):
    src, dst = app
    with pytest.raises(KeyError):
        WindowsSystem().move(str(src / "nope"), str(dst))
    dst.parent.mkdir(parents=True)
    dst.write_text("x")
    with pytest.raises(FileExistsError):
        WindowsSystem().move(str(src), str(dst))


def test_powershell_drops_inherited_psmodulepath(monkeypatch):
    # Started from PowerShell 7, PSModulePath points at PS7 modules that Windows PowerShell 5.1
    # can't load (Get-AuthenticodeSignature -> CouldNotAutoloadMatchingModule).
    seen = {}
    monkeypatch.setenv("PSModulePath", r"C:\Program Files\PowerShell\7\Modules")
    monkeypatch.setenv("APPTRIAGE_KEEP", "1")
    monkeypatch.setattr(windows.subprocess, "run", lambda args, **kw: seen.update(kw) or _proc(0))
    windows._powershell("Write-Output ok")
    env = seen["env"]
    assert not any(k.lower() == "psmodulepath" for k in env)
    assert env["APPTRIAGE_KEEP"] == "1"
