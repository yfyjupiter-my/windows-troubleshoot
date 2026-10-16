from app_triage.models import ActionSpec, Risk
from app_triage.scanners.base import SCANNERS, run_scan
from app_triage.scanners.leftovers import scan_leftovers
from app_triage.sysapi.fake import FakeSystem

HKLM_U = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
HKCU_U = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall"
ROAMING = r"C:\Users\tester\AppData\Roaming"
LOCAL = r"C:\Users\tester\AppData\Local"


def by_path(findings):
    return {f.evidence["path"]: f for f in findings}


def test_registered_under_leftovers_label():
    assert SCANNERS["leftovers"][0] == "卸载残留"


def test_wps_folder_left_after_uninstall_reported():
    s = FakeSystem()
    s.add_file(ROAMING + r"\Kingsoft\WPS Office\cfg.ini", size=100)
    s.add_file(ROAMING + r"\Kingsoft\WPS Office\data\cache.bin", size=2000)
    s.add_file(ROAMING + r"\Kingsoft\readme.txt", size=5)
    findings = scan_leftovers(s)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "leftovers"
    assert f.risk is Risk.MEDIUM
    assert f.evidence["path"] == ROAMING + r"\Kingsoft"
    assert f.evidence["size"] == "2105"
    assert f.actions == [ActionSpec("quarantine_path", ROAMING + r"\Kingsoft")]
    assert f.vendor == "WPS (金山办公)"


def test_installed_app_folder_not_reported():
    s = FakeSystem()
    s.add_key(HKLM_U + "\\7-Zip", {"DisplayName": "7-Zip", "Publisher": "Igor Pavlov",
                                   "InstallLocation": "C:\\Program Files\\7-Zip\\"})
    s.add_file(r"C:\Program Files\7-Zip\7z.exe", size=10)
    assert scan_leftovers(s) == []


def test_unowned_program_files_folder_without_vendor_is_low():
    s = FakeSystem()
    s.add_file(r"C:\Program Files\OldTool\a.dll", size=7)
    s.add_file(ROAMING + r"\OldTool\a.dll", size=7)  # not under Program Files, no vendor: ignored
    findings = scan_leftovers(s)
    assert [(f.evidence["path"], f.risk) for f in findings] == [(r"C:\Program Files\OldTool", Risk.LOW)]


def test_token_match_counts_as_owned():
    s = FakeSystem()
    s.add_key(HKLM_U + r"\Notepad++", {"DisplayName": "Notepad++ (64-bit x64)", "Publisher": "Notepad++ Team"})
    s.add_file(r"C:\Program Files\Notepad++\notepad++.exe", size=1)
    s.add_file(ROAMING + r"\Notepad++\config.xml", size=1)
    assert scan_leftovers(s) == []


def test_microsoft_and_skip_dirs_ignored():
    s = FakeSystem()
    for d in ("Microsoft", "Microsoft Office", "Windows Defender", "WindowsApps", "Common Files",
              "Windows Kits", "Temp", "Packages", "Internet Explorer", "Uninstall Information"):
        s.add_file(rf"C:\Program Files\{d}\x.bin", size=1)
    s.add_file(ROAMING + r"\Microsoft\Kingsoft\x.bin", size=1)
    # skip names apply one level down too: Kingsoft is owned, its only unowned child is skipped
    s.add_key(HKCU_U + r"\WPS Office", {"DisplayName": "WPS Office", "Publisher": "Kingsoft Corp",
                                        "InstallLocation": ROAMING + r"\Kingsoft\WPS Office"})
    s.add_file(ROAMING + r"\Kingsoft\Windows Helper\x.bin", size=1)
    s.add_file(ROAMING + r"\Kingsoft\WPS Office\x.bin", size=1)
    assert scan_leftovers(s) == []


def test_orphan_vendor_registry_key_reported():
    s = FakeSystem()
    s.add_key(r"HKCU\Software\Kingsoft\Office\6.0", {"x": 1})
    s.add_key(r"HKLM\SOFTWARE\WOW6432Node\2345Soft")
    s.add_key(r"HKLM\SOFTWARE\Igor Pavlov")
    findings = scan_leftovers(s)
    assert {f.evidence["key"] for f in findings} == {
        r"HKCU\Software\Kingsoft", r"HKLM\SOFTWARE\WOW6432Node\2345Soft"}
    for f in findings:
        assert f.risk is Risk.LOW and f.category == "leftovers"
        assert f.actions == [ActionSpec("delete_reg_key", f.evidence["key"])]


def test_registry_key_of_installed_vendor_app_not_reported():
    s = FakeSystem()
    s.add_key(HKCU_U + r"\WPS Office", {"DisplayName": "WPS Office", "Publisher": "Kingsoft Corp"})
    s.add_key(r"HKCU\Software\Kingsoft")
    assert scan_leftovers(s) == []


def test_unicode_dir_names():
    s = FakeSystem()
    s.add_key(HKCU_U + r"\WPS Office", {
        "DisplayName": "WPS Office", "Publisher": "Kingsoft Corp",
        "InstallLocation": ROAMING + r"\Kingsoft\WPS Office"})
    s.add_file(ROAMING + r"\Kingsoft\WPS Office\a.dat", size=3)
    s.add_file(ROAMING + r"\Kingsoft\金山文档\缓存.dat", size=40)
    findings = scan_leftovers(s)
    assert len(findings) == 1
    f = findings[0]
    assert f.risk is Risk.MEDIUM
    assert "金山文档" in f.title
    assert f.evidence["path"] == ROAMING + r"\Kingsoft\金山文档"
    assert f.evidence["size"] == "40"
    assert f.actions == [ActionSpec("quarantine_path", ROAMING + r"\Kingsoft\金山文档")]


def test_chinese_dir_token_owned_by_chinese_app_name():
    s = FakeSystem()
    s.add_key(HKCU_U + r"\2345", {"DisplayName": "2345看图王", "Publisher": "2345"})
    s.add_file(LOCAL + r"\2345看图王\x.bin", size=1)
    assert scan_leftovers(s) == []


def test_denied_root_and_owned_vendor_dir_are_skipped():
    s = FakeSystem()
    s.add_file(ROAMING + r"\Kingsoft\x.bin", size=1)
    s.add_key(HKCU_U + r"\WPS Office", {"DisplayName": "WPS Office", "Publisher": "Kingsoft Corp",
                                        "InstallLocation": LOCAL + r"\Kingsoft\WPS Office"})
    s.add_file(LOCAL + r"\Kingsoft\WPS Office\x.bin", size=1)
    s.add_file(r"C:\ProgramData\2345Soft\x.bin", size=1)
    s.add_key(r"HKCU\Software\Kingsoft")  # same publisher as the installed app: owned
    s.deny(ROAMING)
    s.deny(LOCAL + r"\Kingsoft")
    assert [f.evidence["path"] for f in scan_leftovers(s)] == [r"C:\ProgramData\2345Soft"]
    assert run_scan(s, ["leftovers"]).errors == {}


def test_size_counts_readable_part_when_subdir_denied():
    s = FakeSystem()
    s.add_file(ROAMING + r"\Kingsoft\a.bin", size=10)
    s.add_file(ROAMING + r"\Kingsoft\locked\b.bin", size=999)
    s.deny(ROAMING + r"\Kingsoft\locked")
    (f,) = scan_leftovers(s)
    assert f.evidence["size"] == "10"


def test_missing_folders_and_empty_system_ok():
    assert scan_leftovers(FakeSystem()) == []


def test_unowned_vendor_dir_under_owned_vendor_dir_not_duplicated():
    s = FakeSystem()
    s.add_key(HKCU_U + r"\WPS Office", {"DisplayName": "WPS Office", "Publisher": "Kingsoft Corp",
                                        "InstallLocation": LOCAL + r"\Kingsoft\WPS Office"})
    s.add_file(LOCAL + r"\Kingsoft\WPS Office\a", size=1)
    s.add_file(LOCAL + r"\Kingsoft\Old Thing\a", size=1)
    s.add_file(LOCAL + r"\Kingsoft\Old Thing\deep\b", size=1)
    assert [f.evidence["path"] for f in scan_leftovers(s)] == [LOCAL + r"\Kingsoft\Old Thing"]
