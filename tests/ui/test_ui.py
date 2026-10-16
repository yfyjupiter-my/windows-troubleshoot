import json

from PySide6.QtCore import Qt

from app_triage.ai.client import AssistantMessage, ToolCall
from app_triage.models import ActionSpec, Finding, Risk, make_finding_id
from app_triage.scanners.base import SCANNERS
from tests.ui.conftest import FILEEXTS, RUN

JPG_ID = make_finding_id("file_assoc", ".jpg")
USERCHOICE = FILEEXTS + r"\.jpg\UserChoice"


def rows(tree):
    """All finding rows (children of the scanner-label groups)."""
    return [tree.topLevelItem(i).child(j)
            for i in range(tree.topLevelItemCount())
            for j in range(tree.topLevelItem(i).childCount())]


def row_with(tree, text):
    return next((r for r in rows(tree) if text in r.text(0)), None)


def scan(qtbot, env):
    page = env.win.scan_page
    qtbot.mouseClick(page.scan_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not page.scanning and row_with(page.tree, ".jpg") is not None)
    return page


def tool(name, args, cid):
    return AssistantMessage("", [ToolCall(cid, name, json.dumps(args))])


def test_window_has_four_pages(make_app):
    win = make_app().win
    assert win.windowTitle() == "AppTriage 应用排查工具"
    assert [win.nav.item(i).text() for i in range(win.nav.count())] == ["扫描", "AI 助手", "修复记录", "设置"]


def test_scan_populates_tree_and_errors(qtbot, make_app, monkeypatch):
    def broken(sys):
        raise RuntimeError("坏了")
    monkeypatch.setitem(SCANNERS, "broken", ("故障扫描项", broken))
    env = make_app()
    page = scan(qtbot, env)
    jpg = row_with(page.tree, ".jpg")
    assert jpg.foreground(0).color().name() == "#e8710a"
    assert jpg.flags() & Qt.ItemIsUserCheckable and jpg.checkState(0) == Qt.Unchecked
    assert "WPS.PIC.jpg" in jpg.toolTip(0)
    assert jpg.parent().text(0).startswith("文件默认打开方式")
    assert row_with(page.tree, "WPSCloud") is not None
    assert row_with(page.tree, "Kingsoft") is not None
    assert not page.error_banner.isHidden()
    assert "故障扫描项" in page.error_banner.text() and "坏了" in page.error_banner.text()
    assert JPG_ID in env.win.state.findings


def test_fix_selected_applies_and_opens_default_apps(qtbot, make_app):
    env = make_app()
    page = scan(qtbot, env)
    row_with(page.tree, ".jpg").setCheckState(0, Qt.Checked)
    qtbot.mouseClick(page.fix_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: env.sys.opened_uris == ["ms-settings:defaultapps"])
    assert [s.kind for s in env.confirmed[0]] == ["reset_file_assoc"]
    (session,) = env.journal.sessions()
    assert [e.status for e in session.entries] == ["applied"]
    assert not env.sys.reg_exists(USERCHOICE)
    titles = [t for t, _ in env.informed]
    assert "修复完成" in titles and "最后一步" in titles
    # only the fixed category is rescanned; the .jpg row disappears
    qtbot.waitUntil(lambda: not page.scanning and row_with(page.tree, ".jpg") is None)
    assert row_with(page.tree, "WPSCloud") is not None


def test_fix_warns_when_restore_point_fails(qtbot, make_app):
    env = make_app()
    env.sys.create_restore_point = lambda description: False
    page = scan(qtbot, env)
    row_with(page.tree, "WPSCloud").setCheckState(0, Qt.Checked)
    qtbot.mouseClick(page.fix_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: any(t == "修复完成" for t, _ in env.informed))
    text = dict(env.informed)["修复完成"]
    assert "系统还原点创建失败，但已备份注册表和文件" in text
    assert env.sys.opened_uris == []
    assert "WPSCloud" not in env.sys.reg_values(RUN)


def test_high_risk_confirmed_on_ui_thread_before_execute(qtbot, make_app):
    env = make_app(yes=False)
    spec = ActionSpec("delete_reg_value", RUN, (("name", "WPSCloud"),), high_risk=True)
    f = Finding("hr1", "autoruns", "高风险项", {}, Risk.HIGH, [spec])
    env.win.run_fixes([(f, spec)], "测试")
    # asked synchronously on the UI thread, before the worker starts
    assert len(env.asked) == 1 and "删除注册表值" in env.asked[0][1]
    qtbot.waitUntil(lambda: len(env.journal.sessions()) == 1 and bool(env.journal.sessions()[0].entries))
    (entry,) = env.journal.sessions()[0].entries
    assert entry.status == "failed" and entry.message == "用户取消"
    assert "WPSCloud" in env.sys.reg_values(RUN)


def test_cancelled_confirm_dialog_runs_nothing(qtbot, make_app):
    env = make_app()
    env.win.confirm_fixes = lambda specs: False
    page = scan(qtbot, env)
    row_with(page.tree, ".jpg").setCheckState(0, Qt.Checked)
    qtbot.mouseClick(page.fix_button, Qt.LeftButton)
    assert env.journal.sessions() == []


def test_explain_sends_checked_findings_and_switches_to_chat(qtbot, make_app):
    env = make_app(responses=[AssistantMessage("这是 WPS 的图片关联。", [])])
    page = scan(qtbot, env)
    row_with(page.tree, ".jpg").setCheckState(0, Qt.Checked)
    qtbot.mouseClick(page.explain_button, Qt.LeftButton)
    assert env.win.stack.currentWidget() is env.win.chat_page
    qtbot.waitUntil(lambda: "这是 WPS 的图片关联。" in env.win.chat_page.transcript.toPlainText())
    user_msg = env.backend.calls[0][-1]["content"]
    assert ".jpg" in user_msg and "WPSCloud" not in user_msg


def test_chat_shows_proposals(qtbot, make_app):
    env = make_app(responses=[
        tool("run_scanner", {"name": "file_assoc"}, "c1"),
        tool("propose_fix", {"finding_id": JPG_ID, "action_index": 0, "reason": "图片被 WPS 抢占"}, "c2"),
        AssistantMessage("建议重置 .jpg 的打开方式，需要你确认。", []),
    ])
    chat = env.win.chat_page
    chat.input.setText("图片都用 WPS 打开了")
    qtbot.mouseClick(chat.send_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: chat.proposal_list.count() == 1)
    item = chat.proposal_list.item(0)
    assert item.flags() & Qt.ItemIsUserCheckable
    assert "图片被 WPS 抢占" in item.text() and ".jpg" in item.text()
    assert "需要你确认" in chat.transcript.toPlainText()
    assert "图片都用 WPS 打开了" in chat.transcript.toPlainText()
    # executing the checked proposal goes through the same fix flow
    item.setCheckState(Qt.Checked)
    qtbot.mouseClick(chat.execute_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: env.sys.opened_uris == ["ms-settings:defaultapps"])
    assert [s.kind for s in env.confirmed[0]] == ["reset_file_assoc"]
    qtbot.waitUntil(lambda: chat.proposal_list.count() == 0)


def test_new_conversation_resets_agent_and_proposals(qtbot, make_app):
    env = make_app(responses=[
        tool("run_scanner", {"name": "file_assoc"}, "c1"),
        tool("propose_fix", {"finding_id": JPG_ID, "action_index": 0, "reason": "r"}, "c2"),
        AssistantMessage("好的", []),
    ])
    chat = env.win.chat_page
    chat.input.setText("看看")
    qtbot.mouseClick(chat.send_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: chat.proposal_list.count() == 1)
    qtbot.mouseClick(chat.new_button, Qt.LeftButton)
    assert chat.proposal_list.count() == 0 and env.win.state.proposals == []
    assert len(env.win.agent.history) == 1 and chat.transcript.toPlainText() == ""
    assert JPG_ID in env.win.state.findings  # findings survive a new conversation


def test_history_undo_restores_state(qtbot, make_app):
    env = make_app()
    page = scan(qtbot, env)
    row_with(page.tree, "WPSCloud").setCheckState(0, Qt.Checked)
    qtbot.mouseClick(page.fix_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: "WPSCloud" not in env.sys.reg_values(RUN))
    hist = env.win.history_page
    qtbot.waitUntil(lambda: hist.tree.topLevelItemCount() == 1)
    top = hist.tree.topLevelItem(0)
    assert "已执行" in top.child(0).text(2)
    hist.tree.setCurrentItem(top.child(0))  # selecting an entry selects its session
    qtbot.mouseClick(hist.undo_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: "WPSCloud" in env.sys.reg_values(RUN))
    assert any("撤销" in t for t, _ in env.asked)
    qtbot.waitUntil(lambda: "已撤销" in hist.tree.topLevelItem(0).child(0).text(2))


def test_history_undo_declined_changes_nothing(qtbot, make_app):
    env = make_app()
    page = scan(qtbot, env)
    row_with(page.tree, "WPSCloud").setCheckState(0, Qt.Checked)
    qtbot.mouseClick(page.fix_button, Qt.LeftButton)
    hist = env.win.history_page
    qtbot.waitUntil(lambda: hist.tree.topLevelItemCount() == 1 and not page.scanning)
    env.win.ask_yes_no = lambda title, text: False
    hist.tree.setCurrentItem(hist.tree.topLevelItem(0))
    qtbot.mouseClick(hist.undo_button, Qt.LeftButton)
    assert "WPSCloud" not in env.sys.reg_values(RUN)


def test_chat_disabled_without_api_key(make_app):
    chat = make_app(api_key="").win.chat_page
    assert not chat.input.isEnabled() and not chat.send_button.isEnabled()
    assert not chat.key_notice.isHidden()
    assert "请先在设置里填写 DeepSeek API Key" in chat.key_notice.text()


def test_settings_save_rebuilds_agent_and_keeps_state(qtbot, make_app):
    env = make_app(api_key="")
    win = env.win
    state, old_agent = win.state, win.agent
    s = win.settings_page
    s.key_edit.setText("sk-new")
    s.model_edit.setText("deepseek-reasoner")
    qtbot.mouseClick(s.save_button, Qt.LeftButton)
    assert env.saved[-1].api_key == "sk-new" and env.saved[-1].model == "deepseek-reasoner"
    assert env.built[-1].api_key == "sk-new" and len(env.built) == 2
    assert win.agent is not old_agent and win.state is state and win.agent.toolbox.state is state
    assert win.chat_page.input.isEnabled() and win.chat_page.key_notice.isHidden()


def test_settings_test_connection(qtbot, make_app, monkeypatch):
    from app_triage.ui import settings_page
    seen = []
    monkeypatch.setattr(settings_page, "test_connection", lambda cfg: seen.append(cfg) or "API Key 无效")
    env = make_app()
    s = env.win.settings_page
    s.key_edit.setText("sk-bad")
    qtbot.mouseClick(s.test_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: bool(env.informed))
    assert seen[0].api_key == "sk-bad"
    assert "API Key 无效" in env.informed[-1][1]


def test_confirm_dialog_marks_irreversible_and_high_risk(qtbot):
    from PySide6.QtWidgets import QListWidget
    from app_triage.ui.main_window import ConfirmFixesDialog
    specs = [ActionSpec("delete_reg_value", RUN, (("name", "WPSCloud"),)),
             ActionSpec("run_uninstaller", r"HKLM\U\WPS", (("command", "u.exe /S"),)),
             ActionSpec("delete_reg_value", RUN, (("name", "Debugger"),), high_risk=True)]
    dlg = ConfirmFixesDialog(specs)
    qtbot.addWidget(dlg)
    lst = dlg.findChild(QListWidget)
    texts = [lst.item(i).text() for i in range(lst.count())]
    assert texts[0] == "删除注册表值：" + RUN + " → WPSCloud"
    assert texts[1].endswith("（不可撤销）") and "u.exe /S" in texts[1]
    assert "高风险" in texts[2] and lst.item(2).foreground().color().name() == "#d93025"
    assert lst.item(0).foreground().color().name() != "#d93025"


def test_run_in_thread_delivers_on_ui_thread(qtbot):
    import threading
    from app_triage.ui.workers import run_in_thread
    seen = {}
    run_in_thread(lambda: threading.get_ident(),
                  lambda worker: seen.update(worker=worker, ui=threading.get_ident()), seen.update)
    run_in_thread(lambda: 1 / 0, seen.update, lambda exc: seen.update(error=exc))
    qtbot.waitUntil(lambda: "ui" in seen and "error" in seen)
    assert seen["ui"] == threading.main_thread().ident != seen["worker"]
    assert isinstance(seen["error"], ZeroDivisionError)
