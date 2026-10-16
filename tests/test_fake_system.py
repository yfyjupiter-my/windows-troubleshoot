import pytest

from app_triage.sysapi.base import (
    AccessDenied, DirEntry, ServiceInfo, ShortcutInfo, SignatureInfo, TaskInfo,
)
from app_triage.sysapi.fake import FakeSystem


def test_registry_roundtrip_and_case_insensitive(tmp_path):
    s = FakeSystem(); s.add_key(r"HKCU\Software\Kingsoft\Office", {"ver": "12"})
    assert s.reg_subkeys(r"hkcu\software\kingsoft") == ["Office"]
    assert s.reg_values(r"HKCU\Software\Kingsoft\Office") == {"ver": "12"}
    s.reg_export(r"HKCU\Software\Kingsoft", str(tmp_path / "b.json"))
    s.reg_delete_key(r"HKCU\Software\Kingsoft")
    assert not s.reg_exists(r"HKCU\Software\Kingsoft\Office")
    s.reg_import(str(tmp_path / "b.json"))
    assert s.reg_values(r"HKCU\Software\Kingsoft\Office") == {"ver": "12"}


def test_missing_key_raises_keyerror():
    with pytest.raises(KeyError): FakeSystem().reg_values(r"HKLM\Nope")


def test_deny_then_take_ownership():
    s = FakeSystem(); s.add_key(r"HKCU\K\UserChoice", {"ProgId": "WPS.PIC.jpg"}); s.deny(r"HKCU\K\UserChoice")
    with pytest.raises(AccessDenied): s.reg_delete_key(r"HKCU\K\UserChoice")
    s.reg_take_ownership(r"HKCU\K\UserChoice"); s.reg_delete_key(r"HKCU\K\UserChoice")
    assert not s.reg_exists(r"HKCU\K\UserChoice")


def test_filesystem_list_and_move():
    s = FakeSystem(); s.add_file(r"C:\Users\tester\AppData\Roaming\x\a.exe", hidden=True)
    [e] = s.list_dir(r"C:\Users\tester\AppData\Roaming\x")
    assert e.name == "a.exe" and e.hidden and not e.is_dir
    s.move(r"C:\Users\tester\AppData\Roaming\x", r"D:\q\x")
    assert s.path_exists(r"D:\q\x\a.exe") and not s.path_exists(r"C:\Users\tester\AppData\Roaming\x")


def test_registry_value_ops_and_default_value():
    s = FakeSystem()
    s.reg_set_value(r"HKCU\A\B", "", "default")  # creates key
    s.reg_set_value(r"hkcu\a\b", "Name", 5)
    assert s.reg_values(r"HKCU\A\B") == {"": "default", "Name": 5}
    assert s.reg_exists(r"HKCU\A") and s.reg_subkeys(r"HKCU\A") == ["B"]
    s.reg_delete_value(r"HKCU\A\B", "NAME")
    assert s.reg_values(r"HKCU\A\B") == {"": "default"}
    with pytest.raises(KeyError): s.reg_delete_value(r"HKCU\A\B", "Name")
    with pytest.raises(KeyError): s.reg_delete_value(r"HKCU\Nope", "x")
    with pytest.raises(KeyError): s.reg_delete_key(r"HKCU\Nope")


def test_reg_subkeys_only_direct_children_and_implicit_parents():
    s = FakeSystem(); s.add_key(r"HKLM\S\a\b\c"); s.add_key(r"HKLM\S\d")
    assert sorted(s.reg_subkeys(r"HKLM\S")) == ["a", "d"]
    assert s.reg_exists(r"HKLM\S\a\b") and s.reg_values(r"HKLM\S\a") == {}
    # prefix siblings must not leak into subtree operations
    s.add_key(r"HKLM\SX\z")
    s.reg_delete_key(r"HKLM\S")
    assert not s.reg_exists(r"HKLM\S\a\b\c") and s.reg_exists(r"HKLM\SX\z")


def test_deny_covers_subtree_and_reads_and_writes():
    s = FakeSystem(); s.add_key(r"HKCU\K\Sub\Deep", {"v": 1}); s.deny(r"HKCU\K")
    for call in (lambda: s.reg_values(r"HKCU\K\Sub\Deep"), lambda: s.reg_subkeys(r"HKCU\K"),
                 lambda: s.reg_set_value(r"hkcu\k\sub", "x", 1),
                 lambda: s.reg_delete_value(r"HKCU\K\Sub\Deep", "v")):
        with pytest.raises(AccessDenied): call()
    s.reg_take_ownership(r"HKCU\K")
    assert s.reg_values(r"HKCU\K\Sub\Deep") == {"v": 1}


def test_reg_export_import_preserves_value_types_and_denied_export(tmp_path):
    s = FakeSystem(); s.add_key(r"HKLM\X\Y", {"n": 7, "s": "t", "": "d"})
    f = str(tmp_path / "e.json")
    s.reg_export(r"HKLM\X", f)
    s.reg_delete_key(r"HKLM\X")
    s.reg_import(f)
    assert s.reg_values(r"HKLM\X\Y") == {"n": 7, "s": "t", "": "d"}
    with pytest.raises(KeyError): s.reg_export(r"HKLM\Nope", f)
    s.deny(r"HKLM\X")
    with pytest.raises(AccessDenied): s.reg_export(r"HKLM\X", f)


def test_files_dirs_case_insensitive_and_autocreated_parents():
    s = FakeSystem(); s.add_file(r"C:\Prog\App\Bin\run.exe", size=42, system=True, content="hi")
    assert s.path_exists(r"c:\prog\app") and s.path_exists(r"C:\PROG\APP\BIN\RUN.EXE")
    [d] = s.list_dir(r"C:\Prog")
    assert d == DirEntry("App", r"C:\Prog\App", True, False, False, 0)
    [f] = s.list_dir(r"c:\prog\app\bin")
    assert (f.name, f.path, f.size, f.system, f.is_dir) == ("run.exe", r"C:\Prog\App\Bin\run.exe", 42, True, False)
    assert s.read_text(r"c:\prog\app\bin\RUN.exe") == "hi"
    with pytest.raises(KeyError): s.read_text(r"C:\nope.txt")
    with pytest.raises(KeyError): s.list_dir(r"C:\nope")
    s.add_dir(r"C:\Empty")
    assert s.list_dir(r"C:\Empty") == [] and s.path_exists(r"C:\Empty")


def test_list_dir_does_not_leak_prefix_siblings():
    s = FakeSystem(); s.add_file(r"C:\A\f.txt"); s.add_file(r"C:\AB\g.txt")
    assert [e.name for e in s.list_dir(r"C:\A")] == ["f.txt"]


def test_move_file_conflict_and_missing():
    s = FakeSystem(); s.add_file(r"C:\a.txt"); s.add_file(r"C:\b.txt")
    with pytest.raises(FileExistsError): s.move(r"C:\a.txt", r"c:\B.TXT")
    with pytest.raises(KeyError): s.move(r"C:\none", r"C:\x")
    s.move(r"C:\a.txt", r"C:\q\a.txt")
    assert s.path_exists(r"C:\q\a.txt") and not s.path_exists(r"C:\a.txt")
    assert s.path_exists(r"C:\q")  # parent auto-created


def test_move_dir_carries_content_and_deny_on_files():
    s = FakeSystem(); s.add_file(r"C:\d\sub\f.txt", content="z"); s.add_file(r"C:\d2\keep.txt")
    s.move(r"C:\d", r"E:\new")
    assert s.read_text(r"E:\new\sub\f.txt") == "z" and s.path_exists(r"C:\d2\keep.txt")
    s.deny(r"E:\new")
    with pytest.raises(AccessDenied): s.list_dir(r"E:\new")
    with pytest.raises(AccessDenied): s.move(r"E:\new", r"E:\other")
    s.reg_take_ownership(r"E:\new")
    s.move(r"E:\new", r"E:\other")
    assert s.path_exists(r"E:\other\sub\f.txt")


def test_known_folders_username_and_expand_env():
    s = FakeSystem()
    kf = s.known_folders()
    assert set(kf) == {"ProgramFiles", "ProgramFilesX86", "ProgramData", "AppData", "LocalAppData", "Temp",
                       "UserProfile", "Desktop", "StartMenu", "CommonStartMenu", "Startup", "CommonStartup",
                       "SystemRoot"}
    assert s.username() == "tester" and kf["UserProfile"] == r"C:\Users\tester"
    assert s.expand_env(r"%ProgramFiles%\X\a.exe") == kf["ProgramFiles"] + r"\X\a.exe"
    assert s.expand_env("%programfiles(x86)%;%APPDATA%;%localappdata%;%TEMP%;%windir%;%SystemRoot%") == ";".join(
        [kf["ProgramFilesX86"], kf["AppData"], kf["LocalAppData"], kf["Temp"], kf["SystemRoot"], kf["SystemRoot"]])
    assert s.expand_env(r"%ProgramData%|%USERPROFILE%|%NOPE%") == f"{kf['ProgramData']}|{kf['UserProfile']}|%NOPE%"


def test_services_and_tasks():
    s = FakeSystem()
    s.add_service(ServiceInfo("svc", "Svc", r"C:\s.exe", "auto", "running"))
    s.add_task(TaskInfo(r"\Vendor\Updater", "u.exe", True, "Vendor"))
    s.set_service_start("svc", "disabled"); s.set_task_enabled(r"\Vendor\Updater", False)
    assert s.list_services()[0].start_type == "disabled" and s.list_services()[0].name == "svc"
    assert s.list_tasks()[0].enabled is False
    with pytest.raises(KeyError): s.set_service_start("nope", "auto")
    with pytest.raises(KeyError): s.set_task_enabled(r"\nope", True)


def test_signature_shortcut_and_recorders():
    s = FakeSystem()
    assert s.get_signature(r"C:\x.exe") == SignatureInfo("unknown", "")
    s.set_signature(r"C:\x.exe", SignatureInfo("valid", "Acme"))
    assert s.get_signature(r"c:\X.EXE").publisher == "Acme"
    with pytest.raises(KeyError): s.read_shortcut(r"C:\a.lnk")
    s.add_shortcut(r"C:\a.lnk", ShortcutInfo(r"C:\t.exe", "-x"))
    s.set_shortcut_arguments(r"c:\A.lnk", "-y")
    assert s.read_shortcut(r"C:\a.lnk") == ShortcutInfo(r"C:\t.exe", "-y")
    with pytest.raises(KeyError): s.set_shortcut_arguments(r"C:\none.lnk", "")
    assert s.create_restore_point("before") is True
    s.open_uri("ms-settings:defaultapps"); s.launch("notepad.exe")
    assert (s.restore_points, s.opened_uris, s.launched) == (["before"], ["ms-settings:defaultapps"], ["notepad.exe"])


def test_move_carries_shortcuts_and_signatures_and_reads_require_existing_file():
    s = FakeSystem()
    s.add_shortcut(r"C:\Desk\a.lnk", ShortcutInfo(r"C:\t.exe", "-x"))
    s.set_signature(r"C:\Prog\App\run.exe", SignatureInfo("valid", "Acme"))
    s.move(r"C:\Desk\a.lnk", r"D:\Q\a.lnk")
    s.move(r"C:\Prog", r"D:\Q\Prog")
    assert s.read_shortcut(r"D:\q\A.lnk") == ShortcutInfo(r"C:\t.exe", "-x")
    s.set_shortcut_arguments(r"D:\Q\a.lnk", "-z")
    assert s.read_shortcut(r"D:\Q\a.lnk").arguments == "-z"
    assert s.get_signature(r"D:\Q\Prog\App\run.exe") == SignatureInfo("valid", "Acme")
    with pytest.raises(KeyError): s.read_shortcut(r"C:\Desk\a.lnk")
    with pytest.raises(KeyError): s.set_shortcut_arguments(r"C:\Desk\a.lnk", "")
    assert s.get_signature(r"C:\Prog\App\run.exe") == SignatureInfo("unknown", "")


def test_reg_export_import_roundtrips_bytes_values(tmp_path):
    s = FakeSystem(); s.add_key(r"HKCU\B\Progids", {"WPS.PIC.jpg": b"", "bin": b"\x00\xff\x10", "s": "t"})
    f = str(tmp_path / "bytes.json")
    s.reg_export(r"HKCU\B", f)
    s.reg_delete_key(r"HKCU\B")
    s.reg_import(f)
    vals = s.reg_values(r"HKCU\B\Progids")
    assert vals == {"WPS.PIC.jpg": b"", "bin": b"\x00\xff\x10", "s": "t"}
    assert isinstance(vals["WPS.PIC.jpg"], bytes)


def test_reg_export_failure_leaves_no_partial_file(tmp_path):
    s = FakeSystem(); s.add_key(r"HKCU\B", {"bad": object()})
    f = tmp_path / "partial.json"
    with pytest.raises(TypeError): s.reg_export(r"HKCU\B", str(f))
    assert not f.exists()
