"""The real Windows SystemAPI.

Importable on any OS (the test suite imports packages broadly); ``winreg`` is only bound on Windows
and pywin32 modules are imported inside the methods that need them. Parsing lives in ``parsing.py``.
Errors follow the protocol: missing key/path -> KeyError, refused access -> AccessDenied.
"""
from __future__ import annotations

import getpass
import ntpath
import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import replace

from .base import AccessDenied, DirEntry, ServiceInfo, ShortcutInfo, SignatureInfo, TaskInfo
from .parsing import (
    HIVES, expand_env_vars, looks_access_denied, normalize_image_path, parse_service_json,
    parse_signature_json, parse_tasks_json, ps_quote, split_reg_path, split_task_path,
)

if sys.platform == "win32":
    import winreg

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_PS_PREFIX = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
_HIDDEN, _SYSTEM = 0x2, 0x4  # FILE_ATTRIBUTE_HIDDEN / FILE_ATTRIBUTE_SYSTEM
_SC_START = {"auto": "auto", "manual": "demand", "disabled": "disabled", "boot": "boot", "system": "system"}
_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
_E_ACCESSDENIED = -2147024891  # HRESULT 0x80070005
_SERVICES_PS = ("Get-CimInstance Win32_Service | Select Name,DisplayName,PathName,StartMode,State"
                " | ConvertTo-Json")
_TASKS_PS = ("Get-ScheduledTask | Select TaskPath,TaskName,State,Author,@{n='Command';e={($_.Actions | "
             "% { \"$($_.Execute) $($_.Arguments)\".Trim() }) -join ' ; '}} | ConvertTo-Json")
_SIGNATURE_PS = ("Get-AuthenticodeSignature -LiteralPath {path} | Select Status,"
                 "@{{n='Publisher';e={{$_.SignerCertificate.Subject}}}} | ConvertTo-Json")
# Ownership step is best effort: when we already own the key (HKCU UserChoice) it may be refused
# and the ACL step still succeeds. Keys owned by TrustedInstaller (HKLM) need an elevated process.
_TAKE_OWNERSHIP_PS = (
    "try {{ $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::{hive},"
    "[Microsoft.Win32.RegistryView]::Registry64); "
    "$me=[Security.Principal.WindowsIdentity]::GetCurrent().User; "
    "$R=[Security.AccessControl.RegistryRights]; $T=[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree; "
    "try {{ $k=$base.OpenSubKey({sub},$T,$R::TakeOwnership); if (-not $k) {{ exit 3 }}; "
    "$acl=$k.GetAccessControl([Security.AccessControl.AccessControlSections]::None); "
    "$acl.SetOwner($me); $k.SetAccessControl($acl); $k.Close() }} catch {{ }}; "
    "$k=$base.OpenSubKey({sub},$T,$R::ChangePermissions -bor $R::ReadPermissions); if (-not $k) {{ exit 3 }}; "
    "$acl=$k.GetAccessControl(); "
    "foreach ($r in @($acl.GetAccessRules($true,$false,[Security.Principal.SecurityIdentifier]))) "
    "{{ if ($r.AccessControlType -eq 'Deny') {{ [void]$acl.RemoveAccessRuleSpecific($r) }} }}; "
    "$acl.AddAccessRule((New-Object Security.AccessControl.RegistryAccessRule($me,'FullControl',"
    "'ContainerInherit','None','Allow'))); $k.SetAccessControl($acl); $k.Close() }} "
    "catch [System.UnauthorizedAccessException],[System.Security.SecurityException] {{ exit 5 }} "
    "catch {{ Write-Output $_.Exception.ToString(); exit 1 }}")
_NET_HIVES = {"HKLM": "LocalMachine", "HKCU": "CurrentUser", "HKCR": "ClassesRoot"}


# ---- subprocesses (the only place processes are started, except launch) ---------------------

def _system32(rel: str) -> str:
    """Absolute path of a system tool, so a planted reg.exe/powershell.exe on PATH is never used."""
    path = ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", rel)
    return path if os.path.exists(path) else ntpath.basename(rel)


def _run(args: list[str], encoding: str = "utf-8", timeout: float = 180) -> subprocess.CompletedProcess:
    # stdin=DEVNULL: a --windowed exe has no valid console handles to inherit
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, encoding=encoding,
                          errors="replace", creationflags=_NO_WINDOW, timeout=timeout)


def _native(args: list[str]) -> subprocess.CompletedProcess:
    """reg.exe / sc.exe write the console (OEM) code page, e.g. cp936 on Chinese Windows."""
    return _run([_system32(args[0]), *args[1:]], encoding="oem")


def _powershell(script: str, timeout: float = 180) -> subprocess.CompletedProcess:
    return _run([_system32(r"WindowsPowerShell\v1.0\powershell.exe"), "-NoProfile", "-NonInteractive",
                 "-Command", _PS_PREFIX + script], timeout=timeout)


def _check(proc: subprocess.CompletedProcess, what: str, missing: tuple[int, ...] = (3,)) -> str:
    """Our PowerShell snippets exit 3 for "not found" and 5 for "access denied"."""
    if proc.returncode == 0:
        return proc.stdout
    output = f"{proc.stdout}\n{proc.stderr}".strip()
    if proc.returncode in missing:
        raise KeyError(what)
    if proc.returncode == 5 or looks_access_denied(output):
        raise AccessDenied(what)
    raise OSError(f"{what}: {output or f'exit code {proc.returncode}'}")


@contextmanager
def _translate(path: str):
    try:
        yield
    except FileNotFoundError:
        raise KeyError(path) from None
    except PermissionError:  # includes WinError 5
        raise AccessDenied(path) from None


# ---- registry helpers ------------------------------------------------------------------------

def _hive_handle(hive: str):
    return {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT}[hive]


def _open(path: str, access: int):
    hive, sub = split_reg_path(path)
    return winreg.OpenKeyEx(_hive_handle(hive), sub, 0, access | winreg.KEY_WOW64_64KEY)


def _enum(fn, key) -> list:
    items, i = [], 0
    while True:
        try:
            items.append(fn(key, i))
        except OSError as e:
            if getattr(e, "winerror", None) == 259:  # ERROR_NO_MORE_ITEMS
                return items
            raise
        i += 1


def _value_type(key, name: str, value: object) -> int:
    if isinstance(value, str):
        try:  # keep REG_EXPAND_SZ when overwriting one, so %vars% keep expanding
            if winreg.QueryValueEx(key, name)[1] == winreg.REG_EXPAND_SZ:
                return winreg.REG_EXPAND_SZ
        except OSError:
            pass
        return winreg.REG_SZ
    if isinstance(value, int):
        return winreg.REG_DWORD if 0 <= value <= 0xFFFFFFFF else winreg.REG_QWORD
    if isinstance(value, (bytes, bytearray)):
        return winreg.REG_BINARY
    if isinstance(value, list):
        return winreg.REG_MULTI_SZ
    raise TypeError(f"unsupported registry value type: {type(value).__name__}")


def _delete_tree(root, sub: str) -> None:
    with winreg.OpenKeyEx(root, sub, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
        children = _enum(winreg.EnumKey, key)
    for child in children:
        _delete_tree(root, f"{sub}\\{child}")
    winreg.DeleteKeyEx(root, sub, winreg.KEY_WOW64_64KEY, 0)


def _long_name(path: str) -> str:
    """%TEMP% is often an 8.3 name (C:\\Users\\ADMINI~1\\...), which hides the profile name."""
    if "~" not in path:
        return path
    try:
        import win32api
        return win32api.GetLongPathName(path)
    except Exception:  # noqa: BLE001 - best effort; the short name still works as a path
        return path


def _com_denied(e: Exception) -> bool:
    codes = [getattr(e, "hresult", None)]
    excepinfo = getattr(e, "excepinfo", None)
    if excepinfo and len(excepinfo) > 5:
        codes.append(excepinfo[5])
    return _E_ACCESSDENIED in codes


class WindowsSystem:
    def __init__(self) -> None:
        self._signatures: dict[str, SignatureInfo] = {}

    # ---- registry -------------------------------------------------------
    def reg_subkeys(self, path: str) -> list[str]:
        with _translate(path), _open(path, winreg.KEY_READ) as key:
            return sorted(_enum(winreg.EnumKey, key), key=str.lower)

    def reg_values(self, path: str) -> dict[str, object]:
        with _translate(path), _open(path, winreg.KEY_READ) as key:
            # EnumValue leaves REG_EXPAND_SZ unexpanded; the default value is named ""
            return {name: (b"" if data is None else data) for name, data, _ in _enum(winreg.EnumValue, key)}

    def reg_exists(self, path: str) -> bool:
        try:
            with _open(path, winreg.KEY_READ):
                return True
        except PermissionError:
            return True  # it is there, we just may not read it
        except (FileNotFoundError, KeyError):
            return False

    def reg_set_value(self, path: str, name: str, value: object) -> None:
        hive, sub = split_reg_path(path)
        access = winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY
        with _translate(path), winreg.CreateKeyEx(_hive_handle(hive), sub, 0, access) as key:
            winreg.SetValueEx(key, name, 0, _value_type(key, name, value), value)

    def reg_delete_value(self, path: str, name: str) -> None:
        with _translate(path), _open(path, winreg.KEY_SET_VALUE) as key:
            try:
                winreg.DeleteValue(key, name)
            except FileNotFoundError:
                raise KeyError(name) from None

    def reg_delete_key(self, path: str) -> None:
        hive, sub = split_reg_path(path)
        if not sub:
            raise ValueError(f"refusing to delete a registry hive: {path}")
        with _translate(path):
            _delete_tree(_hive_handle(hive), sub)

    def reg_export(self, path: str, dest_file: str) -> None:
        with _translate(path), _open(path, winreg.KEY_READ):
            pass  # missing -> KeyError, unreadable -> AccessDenied, independent of reg.exe's language
        hive, sub = split_reg_path(path)
        full = HIVES[hive] + (f"\\{sub}" if sub else "")
        _check(_native(["reg.exe", "export", full, dest_file, "/y", "/reg:64"]), path, missing=())

    def reg_import(self, src_file: str) -> None:
        _check(_native(["reg.exe", "import", src_file, "/reg:64"]), src_file, missing=())

    def reg_take_ownership(self, path: str) -> None:
        """Own the key and grant ourselves FullControl, dropping Deny ACEs. HKLM keys need admin."""
        hive, sub = split_reg_path(path)
        _check(_powershell(_TAKE_OWNERSHIP_PS.format(hive=_NET_HIVES[hive], sub=ps_quote(sub))), path)

    # ---- environment ----------------------------------------------------
    def _shell_folders(self, hive: str) -> dict[str, str]:
        try:
            values = self.reg_values(f"{hive}\\{_EXPLORER}")
        except (KeyError, AccessDenied):
            return {}
        return {k: self.expand_env(v) for k, v in values.items() if isinstance(v, str) and v}

    def known_folders(self) -> dict[str, str]:
        env = os.environ
        home = env.get("USERPROFILE", ntpath.join(r"C:\Users", self.username()))
        appdata = env.get("APPDATA", ntpath.join(home, r"AppData\Roaming"))
        local = env.get("LOCALAPPDATA", ntpath.join(home, r"AppData\Local"))
        data = env.get("ProgramData", r"C:\ProgramData")
        program_files = env.get("ProgramW6432") or env.get("ProgramFiles", r"C:\Program Files")
        user, common = self._shell_folders("HKCU"), self._shell_folders("HKLM")
        start = user.get("Start Menu", ntpath.join(appdata, r"Microsoft\Windows\Start Menu"))
        common_start = common.get("Common Start Menu", ntpath.join(data, r"Microsoft\Windows\Start Menu"))
        return {
            "ProgramFiles": program_files,
            "ProgramFilesX86": env.get("ProgramFiles(x86)", program_files),
            "ProgramData": data, "AppData": appdata, "LocalAppData": local,
            "Temp": _long_name(env.get("TEMP", ntpath.join(local, "Temp"))),
            "UserProfile": home,
            "Desktop": user.get("Desktop", ntpath.join(home, "Desktop")),
            "StartMenu": start, "CommonStartMenu": common_start,
            "Startup": user.get("Startup", ntpath.join(start, r"Programs\Startup")),
            "CommonStartup": common.get("Common Startup", ntpath.join(common_start, r"Programs\Startup")),
            "SystemRoot": env.get("SystemRoot", r"C:\Windows"),
        }

    def username(self) -> str:
        return os.environ.get("USERNAME") or getpass.getuser()

    def expand_env(self, s: str) -> str:
        return expand_env_vars(s, os.environ)

    # ---- filesystem -----------------------------------------------------
    def list_dir(self, path: str) -> list[DirEntry]:
        entries = []
        try:
            with os.scandir(path) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                        is_dir, attrs, size = e.is_dir(), getattr(st, "st_file_attributes", 0), st.st_size
                    except OSError:
                        is_dir, attrs, size = False, 0, 0
                    entries.append(DirEntry(e.name, e.path, is_dir, bool(attrs & _HIDDEN),
                                            bool(attrs & _SYSTEM), 0 if is_dir else size))
        except (FileNotFoundError, NotADirectoryError):
            raise KeyError(path) from None
        except PermissionError:
            raise AccessDenied(path) from None
        return sorted(entries, key=lambda d: d.name.lower())

    def path_exists(self, path: str) -> bool:
        return os.path.lexists(path)

    def move(self, src: str, dst: str) -> None:
        if not os.path.lexists(src):
            raise KeyError(src)
        if os.path.lexists(dst):
            raise FileExistsError(dst)
        with _translate(src):
            os.makedirs(ntpath.dirname(ntpath.normpath(dst)), exist_ok=True)
            shutil.move(src, dst)

    def read_text(self, path: str) -> str:
        if os.path.isdir(path):
            raise KeyError(path)
        with _translate(path), open(path, encoding="utf-8-sig", errors="replace") as f:
            return f.read()

    # ---- services and scheduled tasks ----------------------------------
    def list_services(self) -> list[ServiceInfo]:
        services = parse_service_json(_check(_powershell(_SERVICES_PS), "Win32_Service"))
        return [replace(s, binary_path=self.expand_env(normalize_image_path(s.binary_path)))
                for s in services]

    def set_service_start(self, name: str, start_type: str) -> None:
        if start_type not in _SC_START:
            raise ValueError(f"unknown start type: {start_type}")
        # sc.exe exits with the Win32 error: 1060 = no such service, 5 = access denied
        _check(_native(["sc.exe", "config", name, "start=", _SC_START[start_type]]), name, missing=(1060,))

    def list_tasks(self) -> list[TaskInfo]:
        return parse_tasks_json(_check(_powershell(_TASKS_PS), "ScheduledTasks"))

    def set_task_enabled(self, path: str, enabled: bool) -> None:
        folder, name = split_task_path(path)
        verb = "Enable" if enabled else "Disable"
        script = (f"$t=Get-ScheduledTask -TaskPath {ps_quote(folder)} -TaskName {ps_quote(name)} "
                  "-ErrorAction SilentlyContinue; if (-not $t) { exit 3 }; "
                  f"try {{ $t | {verb}-ScheduledTask -ErrorAction Stop | Out-Null }} "
                  "catch { if ($_.CategoryInfo.Category -eq 'PermissionDenied') { exit 5 }; "
                  "Write-Output $_.ToString(); exit 1 }")
        _check(_powershell(script), path)

    # ---- signatures, shortcuts, misc -----------------------------------
    def get_signature(self, file_path: str) -> SignatureInfo:
        key = ntpath.normcase(ntpath.normpath(file_path))
        if key in self._signatures:
            return self._signatures[key]
        if not os.path.isfile(file_path):
            return SignatureInfo("unknown", "")
        proc = _powershell(_SIGNATURE_PS.format(path=ps_quote(file_path)))
        try:
            info = parse_signature_json(proc.stdout) if proc.returncode == 0 else SignatureInfo("unknown", "")
        except ValueError:
            info = SignatureInfo("unknown", "")
        self._signatures[key] = info
        return info

    @staticmethod
    def _shortcut(lnk: str):
        if not os.path.isfile(lnk):
            raise KeyError(lnk)
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()  # per thread; scans may run off the GUI thread; repeat calls are harmless
        return win32com.client.Dispatch("WScript.Shell").CreateShortcut(lnk)

    def read_shortcut(self, lnk: str) -> ShortcutInfo:
        link = self._shortcut(lnk)
        return ShortcutInfo(target=link.TargetPath or "", arguments=getattr(link, "Arguments", "") or "")

    def set_shortcut_arguments(self, lnk: str, args: str) -> None:
        link = self._shortcut(lnk)
        link.Arguments = args
        try:
            link.Save()
        except Exception as e:  # pywintypes.com_error
            if _com_denied(e):
                raise AccessDenied(lnk) from None
            raise

    def create_restore_point(self, description: str) -> bool:
        # The once-per-24h limit is only a warning; -WarningAction Stop turns it into False.
        script = (f"try {{ Checkpoint-Computer -Description {ps_quote(description)} "
                  "-RestorePointType MODIFY_SETTINGS -ErrorAction Stop -WarningAction Stop } "
                  "catch { exit 1 }")
        try:
            return _powershell(script, timeout=600).returncode == 0
        except subprocess.TimeoutExpired:
            return False

    def open_uri(self, uri: str) -> None:
        os.startfile(uri)  # type: ignore[attr-defined]  # Windows-only

    def launch(self, command_line: str) -> None:
        # Not CREATE_NO_WINDOW: uninstallers are user-facing and some are console programs.
        with _translate(command_line):
            subprocess.Popen(self.expand_env(command_line))
