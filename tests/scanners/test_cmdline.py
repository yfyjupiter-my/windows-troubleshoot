import pytest

from app_triage.scanners.cmdline import extract_exe_path, is_microsoft
from app_triage.sysapi.base import SignatureInfo


@pytest.mark.parametrize("cmd,expected", [
    (r'"C:\Program Files\Kingsoft\wps.exe" /tray', r"C:\Program Files\Kingsoft\wps.exe"),
    (r"C:\Program Files\Kingsoft\wpscloudsvr.exe -s", r"C:\Program Files\Kingsoft\wpscloudsvr.exe"),
    (r"%ProgramFiles%\2345Soft\a.exe", r"C:\Program Files\2345Soft\a.exe"),
    (r"rundll32.exe C:\x\evil.dll,Start", r"C:\x\evil.dll"),
    (r"C:\Windows\system32\svchost.exe -k netsvcs", r"C:\Windows\system32\svchost.exe"),
    ("", ""),
])
def test_extract_exe_path_cases(cmd, expected):
    def expand(s: str) -> str:
        return s.replace("%ProgramFiles%", r"C:\Program Files")

    def exists(p: str) -> bool:
        return p == expected

    assert extract_exe_path(cmd, expand=expand, exists=exists) == expected


def test_extract_exe_path_defaults_need_no_environment():
    assert extract_exe_path(r"C:\a\b.exe /x") == r"C:\a\b.exe"
    assert extract_exe_path("   ") == ""


def test_extract_exe_path_missing_binary_still_returned():
    assert extract_exe_path(r"C:\Gone Away\app.exe --silent", exists=lambda p: False) \
        == r"C:\Gone Away\app.exe"


def test_extract_exe_path_unquoted_first_prefix_that_exists_wins():
    cmd = r"C:\Program Files\App\run.exe extra.exe"
    assert extract_exe_path(cmd, exists=lambda p: p.endswith("run.exe")) == r"C:\Program Files\App\run.exe"


def test_extract_exe_path_rundll32_full_path_quoted_dll_with_spaces():
    cmd = r'C:\Windows\System32\rundll32.exe "C:\Program Files\X\x.dll",Entry arg'
    assert extract_exe_path(cmd) == r"C:\Program Files\X\x.dll"


def test_extract_exe_path_regsvr32_skips_switches():
    assert extract_exe_path(r"regsvr32.exe /s C:\x\evil.dll") == r"C:\x\evil.dll"


def test_extract_exe_path_no_binary_returns_empty():
    assert extract_exe_path("cmd /c echo hi", exists=lambda p: False) == ""


def test_is_microsoft():
    assert is_microsoft(SignatureInfo("valid", "Microsoft Corporation"))
    assert not is_microsoft(SignatureInfo("invalid", "Microsoft Corporation"))
    assert not is_microsoft(SignatureInfo("valid", "Kingsoft Corp"))
    assert not is_microsoft(SignatureInfo("unknown", ""))
