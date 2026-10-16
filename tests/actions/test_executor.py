from app_triage.actions import execute, is_protected, undo_session
from app_triage.models import ActionSpec
from app_triage.safety.journal import Journal
from app_triage.sysapi.base import ServiceInfo, SignatureInfo, TaskInfo
from app_triage.sysapi.fake import FakeSystem

RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
FILEEXTS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
EXE = r"C:\Users\tester\AppData\Roaming\wps\wps.exe"
YES = lambda _: True  # noqa: E731


def base_system() -> FakeSystem:
    s = FakeSystem()
    s.add_key(RUN, {"WPS": EXE, "Other": "keep"})
    s.add_task(TaskInfo(r"\WpsUpdate", EXE, True, "WPS"))
    s.add_service(ServiceInfo("wpscloudsvr", "WPS", EXE, "auto", "running"))
    s.add_file(EXE)
    return s


def test_undo_skips_failed_entries_reverse_order(tmp_path):
    s = base_system()
    specs = [ActionSpec("delete_reg_value", RUN, (("name", "WPS"),)),
             ActionSpec("quarantine_path", r"C:\Users\tester\AppData\Roaming\missing"),
             ActionSpec("disable_task", r"\WpsUpdate")]
    r = execute(specs, s, Journal(tmp_path), confirm_high_risk=YES)
    assert [e.status for e in r.entries] == ["applied", "failed", "applied"]
    assert r.entries[1].message
    assert s.reg_values(RUN) == {"Other": "keep"} and not s.list_tasks()[0].enabled
    undone = undo_session(r.session_id, s, Journal(tmp_path))
    assert [e.index for e in undone] == [2, 0]
    assert all(e.status == "undone" for e in undone)
    assert s.reg_values(RUN) == {"WPS": EXE, "Other": "keep"}
    assert s.list_tasks()[0].enabled is True
    persisted = Journal(tmp_path).load(r.session_id).entries
    assert [e.status for e in persisted] == ["undone", "failed", "undone"]
    assert undo_session(r.session_id, s, Journal(tmp_path)) == []


def test_journal_records_params_and_index(tmp_path):
    s = base_system()
    r = execute([ActionSpec("delete_reg_value", RUN, (("name", "WPS"),))], s, Journal(tmp_path), YES)
    [e] = Journal(tmp_path).load(r.session_id).entries
    assert (e.index, e.kind, e.target, e.params, e.status) == \
        (0, "delete_reg_value", RUN, {"name": "WPS"}, "applied")
    assert Journal(tmp_path).load(r.session_id).label == "修复"


def test_protected_system_path_refused(tmp_path):
    s = base_system(); s.add_file(r"C:\Windows\System32\drivers\x.sys")
    r = execute([ActionSpec("quarantine_path", r"c:\windows\system32\drivers\x.sys")], s,
                Journal(tmp_path), YES)
    [e] = r.entries
    assert (e.status, e.message) == ("failed", "受保护的系统文件，已拒绝")
    assert s.path_exists(r"C:\Windows\System32\drivers\x.sys")


def test_is_protected_rules():
    s = FakeSystem()
    s.set_signature(r"C:\Program Files\MS\a.exe", SignatureInfo("valid", "Microsoft Corporation"))
    s.add_file(r"C:\Windows2\b.exe")
    q = lambda p: ActionSpec("quarantine_path", p)  # noqa: E731
    assert is_protected(q(r"C:\Windows"), s)
    assert is_protected(q(r"%SystemRoot%\explorer.exe"), s)
    assert is_protected(q(r"C:\Program Files\MS\a.exe"), s)
    assert not is_protected(q(r"C:\Windows2\b.exe"), s)
    assert not is_protected(q(EXE), s)
    assert not is_protected(ActionSpec("delete_reg_value", RUN, (("name", "x"),)), s)


def test_high_risk_declined_not_applied(tmp_path):
    s = base_system()
    asked = []
    specs = [ActionSpec("set_service_start", "wpscloudsvr",
                        (("start", "disabled"), ("previous", "auto")), high_risk=True),
             ActionSpec("disable_task", r"\WpsUpdate")]
    r = execute(specs, s, Journal(tmp_path), confirm_high_risk=lambda sp: asked.append(sp) or False)
    assert asked == [specs[0]]
    assert [(e.status, e.message) for e in r.entries] == [("failed", "用户取消"), ("applied", "")]
    assert s.list_services()[0].start_type == "auto"


def test_restore_point_failure_not_fatal(tmp_path, monkeypatch):
    s = base_system()
    monkeypatch.setattr(s, "create_restore_point", lambda description: False)
    r = execute([ActionSpec("disable_task", r"\WpsUpdate")], s, Journal(tmp_path), YES)
    assert r.restore_point is False
    assert [e.status for e in r.entries] == ["applied"]
    assert not s.list_tasks()[0].enabled


def test_restore_point_created_once_before_actions(tmp_path):
    s = base_system()
    specs = [ActionSpec("disable_task", r"\WpsUpdate"), ActionSpec("delete_reg_value", RUN, (("name", "WPS"),))]
    r = execute(specs, s, Journal(tmp_path), YES)
    assert r.restore_point is True and s.restore_points == ["AppTriage 修复前"]
    r = execute([], s, Journal(tmp_path), YES)
    assert r.restore_point is False and r.entries == [] and s.restore_points == ["AppTriage 修复前"]


def test_needs_default_apps_flag(tmp_path):
    s = base_system()
    s.add_key(FILEEXTS + r"\.jpg\UserChoice", {"ProgId": "WPS.PIC.jpg"})
    r = execute([ActionSpec("disable_task", r"\WpsUpdate")], s, Journal(tmp_path), YES)
    assert r.needs_default_apps is False
    r = execute([ActionSpec("reset_file_assoc", ".jpg", (("progid", "WPS.PIC.jpg"), ("openwith", "")))],
                s, Journal(tmp_path), YES)
    assert r.needs_default_apps is True
    r = execute([ActionSpec("reset_file_assoc", ".nope", (("openwith", ""),))], s, Journal(tmp_path), YES)
    assert r.entries[0].status == "failed" and r.needs_default_apps is False


def test_undo_quarantine_conflict_reports_message(tmp_path):
    s = base_system()
    r = execute([ActionSpec("quarantine_path", EXE)], s, Journal(tmp_path), YES)
    s.add_file(EXE)
    [e] = undo_session(r.session_id, s, Journal(tmp_path))
    assert (e.status, e.message) == ("undo_failed", "原位置已存在同名文件，未覆盖")
    assert Journal(tmp_path).load(r.session_id).entries[0].status == "undo_failed"


def test_unknown_kind_and_exceptions_fail_without_stopping(tmp_path):
    s = base_system(); s.deny(RUN)
    specs = [ActionSpec("format_disk", "C:"),
             ActionSpec("delete_reg_value", RUN, (("name", "WPS"),)),
             ActionSpec("run_uninstaller", r"HKLM\U\WPS", (("command", ""),)),
             ActionSpec("disable_task", r"\WpsUpdate")]
    r = execute(specs, s, Journal(tmp_path), YES)
    assert [e.status for e in r.entries] == ["failed", "failed", "failed", "applied"]
    assert r.entries[0].message == "未知的修复类型：format_disk"
    assert r.entries[1].message == f"权限不足：{RUN}"
    assert r.entries[2].message == "没有找到卸载程序"
    assert s.launched == []


def test_undo_uninstaller_is_irreversible_and_undo_continues_past_errors(tmp_path):
    s = base_system()
    specs = [ActionSpec("disable_task", r"\WpsUpdate"),
             ActionSpec("run_uninstaller", r"HKLM\U\WPS", (("command", "u.exe /S"),)),
             ActionSpec("delete_reg_value", RUN, (("name", "WPS"),))]
    r = execute(specs, s, Journal(tmp_path), YES)
    assert s.launched == ["u.exe /S"]
    s.deny(RUN)  # undo of the registry change will raise AccessDenied
    undone = undo_session(r.session_id, s, Journal(tmp_path))
    assert [(e.index, e.status) for e in undone] == [(2, "undo_failed"), (1, "undo_failed"), (0, "undone")]
    assert undone[0].message == f"权限不足：{RUN}"
    assert undone[1].message == "卸载操作无法撤销"
    assert s.list_tasks()[0].enabled is True
    assert s.launched == ["u.exe /S"]


def test_protection_check_error_fails_closed_and_continues(tmp_path):
    s = base_system()

    def broken(path):
        raise OSError("WinVerifyTrust failed")
    s.get_signature = broken
    specs = [ActionSpec("quarantine_path", EXE), ActionSpec("disable_task", r"\WpsUpdate")]
    r = execute(specs, s, Journal(tmp_path), YES)
    assert [e.status for e in r.entries] == ["failed", "applied"]
    assert "已拒绝" in r.entries[0].message
    assert s.path_exists(EXE) and not s.list_tasks()[0].enabled
    assert [e.status for e in Journal(tmp_path).load(r.session_id).entries] == ["failed", "applied"]


def test_confirm_raising_counts_as_cancel(tmp_path):
    s = base_system()

    def confirm(spec):
        raise RuntimeError("dialog closed")
    specs = [ActionSpec("set_service_start", "wpscloudsvr", (("start", "disabled"),), high_risk=True),
             ActionSpec("disable_task", r"\WpsUpdate")]
    r = execute(specs, s, Journal(tmp_path), confirm)
    assert [(e.status, e.message) for e in r.entries] == [("failed", "用户取消"), ("applied", "")]
    assert s.list_services()[0].start_type == "auto"


def test_device_prefixed_system_paths_protected():
    s = FakeSystem()
    for p in (r"\\?\C:\Windows\System32\x.dll", r"\\.\C:\Windows\x.dll", r"\??\C:\Windows\x.dll",
              "//?/C:/Windows/x.dll", r"C:\Windows\System32\..\x.dll"):
        assert is_protected(ActionSpec("quarantine_path", p), s), p
    assert not is_protected(ActionSpec("quarantine_path", r"\\?\C:\Windows2\x.dll"), s)


def test_quarantine_moves_exactly_the_checked_path(tmp_path):
    s = base_system()
    checked, moved = [], []
    sig, mv = s.get_signature, s.move
    s.get_signature = lambda p: checked.append(p) or sig(p)
    s.move = lambda src, dst: moved.append(src) or mv(src, dst)
    r = execute([ActionSpec("quarantine_path", r"\\?\%AppData%\wps\.\wps.exe")], s, Journal(tmp_path), YES)
    [e] = r.entries
    assert e.status == "applied" and not s.path_exists(EXE)
    assert checked == moved == [EXE] and e.backup["original"] == EXE


def test_error_messages_are_chinese(tmp_path):
    s = base_system(); s.deny(RUN)

    def broken(name, start):
        raise OSError("disk on fire")
    s.set_service_start = broken
    missing = r"C:\Users\tester\AppData\Roaming\missing"
    specs = [ActionSpec("delete_reg_value", RUN, (("name", "WPS"),)),
             ActionSpec("quarantine_path", missing),
             ActionSpec("set_service_start", "wpscloudsvr", (("start", "disabled"),))]
    r = execute(specs, s, Journal(tmp_path), YES)
    assert [e.message for e in r.entries] == [f"权限不足：{RUN}", f"未找到：{missing}",
                                              "操作失败：disk on fire"]
