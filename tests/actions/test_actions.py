import copy
import ntpath

import pytest

from app_triage.actions import ACTIONS
from app_triage.actions.base import ActionError
from app_triage.models import ActionSpec
from app_triage.safety.journal import Journal, JournalEntry
from app_triage.sysapi.base import ServiceInfo, ShortcutInfo, TaskInfo
from app_triage.sysapi.fake import FakeSystem

FILEEXTS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
WINLOGON = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
PHOTOS = "AppX43hnxtbyyps62jhe9sqpdzxn1790zetc"


def state(s: FakeSystem):
    """Snapshot of the fake's user-visible state; the quarantine folder (not on C:) is excluded."""
    fs = {k: v for k, v in s._fs.items() if k.startswith("c:")}
    return copy.deepcopy((s._reg, fs, s._content, s._services, s._tasks, s._shortcuts))


@pytest.fixture
def session(tmp_path):
    return Journal(tmp_path).begin("测试")


def apply(spec, s, session, index=0) -> JournalEntry:
    backup = ACTIONS[spec.kind].apply(spec, s, session, index)
    return JournalEntry(index, spec.kind, spec.target, dict(spec.params), "applied", backup)


def undo(entry, s, session):
    ACTIONS[entry.kind].undo(entry, s, session)


def test_every_kind_registered_with_chinese_description():
    kinds = {"delete_reg_value", "delete_reg_key", "set_reg_value", "reset_file_assoc",
             "set_service_start", "disable_task", "quarantine_path", "fix_shortcut_args",
             "run_uninstaller"}
    assert set(ACTIONS) == kinds
    for kind, action in ACTIONS.items():
        assert action.kind == kind
        text = action.describe(ActionSpec(kind, "X", (("name", "n"), ("args", "a"))))
        assert text and any("\u4e00" <= ch <= "\u9fff" for ch in text)
    assert [k for k, a in ACTIONS.items() if not a.reversible] == ["run_uninstaller"]


def test_delete_reg_value_roundtrip(session):
    s = FakeSystem(); s.add_key(RUN, {"WPS": r"C:\wps.exe", "Other": "keep"})
    before = state(s)
    e = apply(ActionSpec("delete_reg_value", RUN, (("name", "WPS"),)), s, session, 3)
    assert s.reg_values(RUN) == {"Other": "keep"}
    assert e.backup == {"reg_file": str(session.backup_path("3.reg"))}
    undo(e, s, session)
    assert state(s) == before


def test_delete_reg_key_roundtrip_restores_removed_subtree(session):
    key = r"HKCU\Software\Kingsoft"
    s = FakeSystem(); s.add_key(key + r"\Office\6.0", {"ver": "12"}); s.add_key(key, {"a": 1})
    before = state(s)
    e = apply(ActionSpec("delete_reg_key", key), s, session)
    assert not s.reg_exists(key) and not s.reg_exists(key + r"\Office")
    undo(e, s, session)
    assert state(s) == before


def test_set_reg_value_roundtrip_existing_value(session):
    s = FakeSystem(); s.add_key(WINLOGON, {"Shell": r"explorer.exe, C:\evil.exe"})
    before = state(s)
    e = apply(ActionSpec("set_reg_value", WINLOGON, (("name", "Shell"), ("value", "explorer.exe"))),
              s, session)
    assert s.reg_values(WINLOGON)["Shell"] == "explorer.exe"
    undo(e, s, session)
    assert state(s) == before


def test_set_reg_value_roundtrip_previously_absent_value(session):
    s = FakeSystem(); s.add_key(WINLOGON, {"Userinit": "x"})
    before = state(s)
    e = apply(ActionSpec("set_reg_value", WINLOGON, (("name", "Shell"), ("value", "explorer.exe"))),
              s, session)
    assert s.reg_values(WINLOGON)["Shell"] == "explorer.exe"
    undo(e, s, session)
    assert state(s) == before


def set_assoc(s, ext, progid, openwith):
    s.add_key(f"{FILEEXTS}\\{ext}")
    s.add_key(f"{FILEEXTS}\\{ext}\\UserChoice", {"ProgId": progid, "Hash": "abc"})
    s.add_key(f"{FILEEXTS}\\{ext}\\OpenWithProgids", {n: "" for n in openwith})


def reset_spec(ext, openwith):
    return ActionSpec("reset_file_assoc", ext, (("progid", "WPS.PIC.jpg"), ("openwith", openwith)))


def test_reset_file_assoc_roundtrip(session):
    s = FakeSystem(); set_assoc(s, ".jpg", "WPS.PIC.jpg", ("WPS.PIC.jpg", PHOTOS, "WPS.PIC.x"))
    before = state(s)
    e = apply(reset_spec(".jpg", "WPS.PIC.jpg;WPS.PIC.x"), s, session)
    assert not s.reg_exists(FILEEXTS + r"\.jpg\UserChoice")
    assert s.reg_values(FILEEXTS + r"\.jpg\OpenWithProgids") == {PHOTOS: ""}
    assert e.backup["needs_default_apps"] == "1"
    undo(e, s, session)
    assert state(s) == before


def test_reset_file_assoc_roundtrip_with_denied_acl(session):
    s = FakeSystem(); set_assoc(s, ".jpg", "WPS.PIC.jpg", ("WPS.PIC.jpg", PHOTOS))
    s.deny(FILEEXTS + r"\.jpg\UserChoice")
    before = state(s)
    e = apply(reset_spec(".jpg", "WPS.PIC.jpg"), s, session)
    assert not s.reg_exists(FILEEXTS + r"\.jpg\UserChoice")
    assert s.reg_values(FILEEXTS + r"\.jpg\OpenWithProgids") == {PHOTOS: ""}
    undo(e, s, session)
    assert state(s) == before
    assert s.reg_values(FILEEXTS + r"\.jpg\UserChoice") == {"ProgId": "WPS.PIC.jpg", "Hash": "abc"}


def test_reset_file_assoc_tolerates_missing_userchoice_and_values(session):
    s = FakeSystem(); s.add_key(FILEEXTS + r"\.png\OpenWithProgids", {PHOTOS: ""})
    before = state(s)
    e = apply(reset_spec(".png", ";WPS.PIC.png;"), s, session)
    assert s.reg_values(FILEEXTS + r"\.png\OpenWithProgids") == {PHOTOS: ""}
    undo(e, s, session)
    assert state(s) == before


def test_reset_file_assoc_rolls_back_when_a_later_step_fails(session):
    s = FakeSystem(); set_assoc(s, ".jpg", "WPS.PIC.jpg", ("WPS.PIC.jpg",))
    before = state(s)
    original = s.reg_delete_value

    def failing(path, name):
        raise RuntimeError("boom")
    s.reg_delete_value = failing
    with pytest.raises(RuntimeError):
        apply(reset_spec(".jpg", "WPS.PIC.jpg"), s, session)
    s.reg_delete_value = original
    assert state(s) == before


def test_set_service_start_roundtrip(session):
    s = FakeSystem(); s.add_service(ServiceInfo("wpscloudsvr", "WPS", r"C:\w.exe", "auto", "running"))
    before = state(s)
    e = apply(ActionSpec("set_service_start", "wpscloudsvr",
                         (("start", "disabled"), ("previous", "auto")), high_risk=True), s, session)
    assert s.list_services()[0].start_type == "disabled"
    assert e.backup == {"previous": "auto"}
    undo(e, s, session)
    assert state(s) == before


def test_set_service_start_previous_falls_back_to_current(session):
    s = FakeSystem(); s.add_service(ServiceInfo("svc", "S", r"C:\s.exe", "manual", "stopped"))
    e = apply(ActionSpec("set_service_start", "SVC", (("start", "disabled"),)), s, session)
    assert e.backup == {"previous": "manual"}
    undo(e, s, session)
    assert s.list_services()[0].start_type == "manual"


@pytest.mark.parametrize("was_enabled", [True, False])
def test_disable_task_roundtrip(session, was_enabled):
    s = FakeSystem(); s.add_task(TaskInfo(r"\WpsUpdate", r"C:\u.exe", was_enabled, "WPS"))
    before = state(s)
    e = apply(ActionSpec("disable_task", r"\WpsUpdate"), s, session)
    assert s.list_tasks()[0].enabled is False
    undo(e, s, session)
    assert state(s) == before


def test_disable_task_missing_task_raises(session):
    with pytest.raises(KeyError):
        apply(ActionSpec("disable_task", r"\Nope"), FakeSystem(), session)


def test_quarantine_path_roundtrip_directory(session):
    src = r"C:\Users\tester\AppData\Roaming\kingsoft"
    s = FakeSystem(); s.add_file(src + r"\a.exe", size=5, content="x"); s.add_file(src + r"\b\c.dat")
    before = state(s)
    e = apply(ActionSpec("quarantine_path", src), s, session, 4)
    dest = str(session.quarantine_dir() / "4_kingsoft")
    assert e.backup == {"original": src, "moved_to": dest}
    assert not s.path_exists(src) and s.path_exists(ntpath.join(dest, "a.exe"))
    undo(e, s, session)
    assert state(s) == before


def test_quarantine_undo_refuses_to_overwrite(session):
    src = r"C:\Users\tester\Desktop\x.exe"
    s = FakeSystem(); s.add_file(src)
    e = apply(ActionSpec("quarantine_path", src), s, session)
    s.add_file(src)
    with pytest.raises(ActionError, match="原位置已存在同名文件，未覆盖"):
        undo(e, s, session)
    assert s.path_exists(e.backup["moved_to"])


def test_fix_shortcut_args_roundtrip(session):
    lnk = r"C:\Users\tester\Desktop\Chrome.lnk"
    s = FakeSystem(); s.add_shortcut(lnk, ShortcutInfo(r"C:\chrome.exe", "--x http://hao.example"))
    before = state(s)
    e = apply(ActionSpec("fix_shortcut_args", lnk, (("args", "--x"),)), s, session)
    assert s.read_shortcut(lnk).arguments == "--x"
    assert e.backup == {"args": "--x http://hao.example"}
    undo(e, s, session)
    assert state(s) == before


def test_run_uninstaller_launches_command(session):
    s = FakeSystem()
    apply(ActionSpec("run_uninstaller", r"HKLM\...\Uninstall\WPS", (("command", r'"C:\u.exe" /S'),)),
          s, session)
    assert s.launched == [r'"C:\u.exe" /S']


def test_run_uninstaller_without_command_fails(session):
    s = FakeSystem()
    with pytest.raises(ActionError, match="没有找到卸载程序"):
        apply(ActionSpec("run_uninstaller", r"HKLM\...\Uninstall\WPS", (("command", " "),)), s, session)
    assert s.launched == []
