from app_triage.models import Risk
from app_triage.scanners.installed import list_installed, scan_installed
from app_triage.sysapi.fake import FakeSystem

HKLM_U = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
WOW_U = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
HKCU_U = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall"
WPS_UNINST = r'"C:\Users\tester\AppData\Local\Kingsoft\WPS Office\uninst.exe" /S'


def make_system() -> FakeSystem:
    s = FakeSystem()
    s.add_key(HKCU_U + r"\WPS Office", {
        "DisplayName": "WPS Office", "Publisher": "Kingsoft Corp", "DisplayVersion": "12.1",
        "InstallLocation": r"C:\Users\tester\AppData\Local\Kingsoft\WPS Office",
        "UninstallString": WPS_UNINST,
    })
    s.add_key(HKLM_U + "\\7-Zip", {
        "DisplayName": "7-Zip", "Publisher": "Igor Pavlov", "DisplayVersion": "23.01",
        "UninstallString": r"C:\Program Files\7-Zip\Uninstall.exe",
    })
    s.add_key(HKLM_U + r"\SysComp", {"DisplayName": "Hidden Component", "SystemComponent": 1})
    s.add_key(HKLM_U + r"\SysCompStr", {"DisplayName": "Hidden Str", "SystemComponent": "1"})
    s.add_key(HKLM_U + r"\NoName", {"Publisher": "Nobody"})
    return s


def test_list_installed_reads_all_hives_and_skips_system_components():
    apps = list_installed(make_system())
    assert {a.name for a in apps} == {"WPS Office", "7-Zip"}
    wps = next(a for a in apps if a.name == "WPS Office")
    assert wps.publisher == "Kingsoft Corp" and wps.version == "12.1"
    assert wps.uninstall_string == WPS_UNINST
    assert wps.key_path == HKCU_U + r"\WPS Office"
    seven = next(a for a in apps if a.name == "7-Zip")
    assert seven.install_location == ""


def test_list_installed_reads_wow6432_and_tolerates_missing_hives_and_odd_types():
    s = FakeSystem()
    s.add_key(WOW_U + r"\Old", {"DisplayName": "Old App", "DisplayVersion": 5, "Publisher": None})
    apps = list_installed(s)
    assert [a.name for a in apps] == ["Old App"]
    assert apps[0].version == "" and apps[0].publisher == ""
    assert list_installed(FakeSystem()) == []


def test_list_installed_skips_denied_hive():
    s = make_system()
    s.deny(HKLM_U)
    assert {a.name for a in list_installed(s)} == {"WPS Office"}


def test_installed_scanner_flags_only_vendor_apps():
    findings = scan_installed(make_system())
    assert len(findings) == 1
    f = findings[0]
    assert f.vendor == "WPS (金山办公)"
    assert f.category == "installed" and f.risk == Risk.LOW
    assert f.title == "已安装：WPS Office"
    assert f.actions[0].kind == "run_uninstaller"
    assert f.actions[0].target == HKCU_U + r"\WPS Office"
    assert f.actions[0].param("command") == WPS_UNINST
    assert f.evidence["name"] == "WPS Office"
    assert f.evidence["uninstall_string"] == WPS_UNINST
