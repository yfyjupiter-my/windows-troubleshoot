import copy
import json

from app_triage.ai.tools import Proposal, ToolBox, TriageState
from app_triage.models import ActionSpec, Finding, Risk
from app_triage.scanners.base import SCANNERS
from app_triage.sysapi.base import SignatureInfo
from app_triage.sysapi.fake import FakeSystem

RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
WPS_EXE = r"C:\Users\tester\AppData\Local\Kingsoft\WPS Office\wpscloudsvr.exe"
UNINSTALL = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


def finding(fid="f1"):
    return Finding(fid, "autoruns", "开机自启：WPSCloud",
                   {"command": WPS_EXE, "exe": WPS_EXE}, Risk.MEDIUM,
                   [ActionSpec("delete_reg_value", RUN, (("name", "WPSCloud"),))],
                   vendor="WPS (金山办公)")


def wps_system():
    s = FakeSystem()
    s.add_key(RUN, {"WPSCloud": f'"{WPS_EXE}" /tray'})
    s.set_signature(WPS_EXE, SignatureInfo("valid", "Zhuhai Kingsoft Office Software Co., Ltd."))
    return s


def call(tb, name, args):
    return json.loads(tb.call(name, json.dumps(args, ensure_ascii=False)))


def test_schemas_are_exactly_the_four_tools():
    tb = ToolBox(FakeSystem(), TriageState({}, []))
    names = [s["function"]["name"] for s in tb.schemas]
    assert names == ["run_scanner", "list_installed_apps", "get_finding", "propose_fix"]
    assert all(s["type"] == "function" for s in tb.schemas)
    run = tb.schemas[0]["function"]["parameters"]
    assert run["properties"]["name"]["enum"] == list(SCANNERS)
    assert run["required"] == ["name"]
    assert tb.schemas[3]["function"]["parameters"]["required"] == [
        "finding_id", "action_index", "reason"]


def test_propose_fix_dedupes_and_validates():
    f = finding()
    s = FakeSystem()
    tb = ToolBox(s, TriageState({f.id: f}, []))
    assert json.loads(tb.call("propose_fix", json.dumps({"finding_id": f.id, "action_index": 0, "reason": "r"}))) == {"ok": True}
    assert "note" in json.loads(tb.call("propose_fix", json.dumps({"finding_id": f.id, "action_index": 0, "reason": "r"})))
    assert "error" in json.loads(tb.call("propose_fix", json.dumps({"finding_id": "nope", "action_index": 0, "reason": "r"})))
    assert "error" in json.loads(tb.call("propose_fix", json.dumps({"finding_id": f.id, "action_index": 9, "reason": "r"})))
    assert "error" in json.loads(tb.call("propose_fix", "{bad json"))
    assert "error" in json.loads(tb.call("rm_rf", "{}"))
    assert len(tb.state.proposals) == 1
    assert tb.state.proposals == [Proposal(f.id, 0, "r")]


def test_propose_fix_rejects_bad_argument_types():
    f = finding()
    tb = ToolBox(FakeSystem(), TriageState({f.id: f}, []))
    for args in ({"finding_id": f.id, "action_index": "0", "reason": "r"},
                 {"finding_id": f.id, "action_index": True, "reason": "r"},
                 {"finding_id": f.id, "action_index": -1, "reason": "r"},
                 {"finding_id": f.id, "action_index": 0},
                 {"finding_id": f.id, "action_index": 0, "reason": 5}):
        assert "error" in call(tb, "propose_fix", args)
    assert "error" in json.loads(tb.call("propose_fix", "[1, 2]"))
    assert tb.state.proposals == []


def test_note_text_for_duplicate():
    f = finding()
    tb = ToolBox(FakeSystem(), TriageState({f.id: f}, []))
    args = {"finding_id": f.id, "action_index": 0, "reason": "r"}
    call(tb, "propose_fix", args)
    assert call(tb, "propose_fix", {**args, "reason": "另一个理由"}) == {"ok": True, "note": "已在待确认列表中"}


def test_run_scanner_merges_findings_and_returns_compact_list():
    s = wps_system()
    state = TriageState({}, [])
    tb = ToolBox(s, state)
    raw = tb.call("run_scanner", json.dumps({"name": "autoruns"}))
    (item,) = json.loads(raw)
    assert set(item) == {"id", "title", "risk", "vendor", "evidence"}
    assert item["risk"] == "medium" and item["vendor"] == "WPS (金山办公)"
    assert item["id"] in state.findings
    # stored finding is NOT redacted; what the model sees is
    assert state.findings[item["id"]].evidence["exe"] == WPS_EXE
    assert "tester" not in raw and "%USER%" in item["evidence"]["exe"]
    assert "金山" in raw  # ensure_ascii=False


def test_run_scanner_unknown_name_and_failing_scanner(monkeypatch):
    tb = ToolBox(FakeSystem(), TriageState({}, []))
    assert "error" in call(tb, "run_scanner", {"name": "nope"})
    assert "error" in call(tb, "run_scanner", {})
    from app_triage.scanners import base

    def boom(sys):
        raise ValueError("bad")
    monkeypatch.setitem(base.SCANNERS, "autoruns", ("开机自启", boom))
    out = call(tb, "run_scanner", {"name": "autoruns"})
    assert "error" in out and "bad" in out["error"]


def test_list_installed_apps_filters_case_insensitively():
    s = FakeSystem()
    s.add_key(UNINSTALL + r"\wps", {"DisplayName": "WPS Office", "Publisher": "Kingsoft Corp",
                                     "DisplayVersion": "12.1",
                                     "InstallLocation": r"C:\Users\tester\AppData\Local\Kingsoft"})
    s.add_key(UNINSTALL + r"\7z", {"DisplayName": "7-Zip", "Publisher": "Igor Pavlov"})
    tb = ToolBox(s, TriageState({}, []))
    assert len(call(tb, "list_installed_apps", {})) == 2
    assert len(json.loads(tb.call("list_installed_apps", ""))) == 2
    (app,) = call(tb, "list_installed_apps", {"keyword": "KINGSOFT"})
    assert app == {"name": "WPS Office", "publisher": "Kingsoft Corp", "version": "12.1",
                   "install_location": r"C:\Users\%USER%\AppData\Local\Kingsoft"}
    assert [a["name"] for a in call(tb, "list_installed_apps", {"keyword": "zip"})] == ["7-Zip"]
    assert "error" in call(tb, "list_installed_apps", {"keyword": 3})


def test_get_finding_includes_action_details():
    f = finding()
    f.actions.append(ActionSpec("run_uninstaller", UNINSTALL + r"\wps", (("command", "u.exe"),),
                                high_risk=True))
    tb = ToolBox(FakeSystem(), TriageState({f.id: f}, []))
    out = call(tb, "get_finding", {"finding_id": f.id})
    assert out["id"] == f.id and out["title"] == f.title and out["risk"] == "medium"
    a0, a1 = out["actions"]
    assert a0["index"] == 0 and a0["describe"].startswith("删除注册表值")
    assert a0["reversible"] is True and a0["high_risk"] is False
    assert a1["index"] == 1 and a1["reversible"] is False and a1["high_risk"] is True
    assert "error" in call(tb, "get_finding", {"finding_id": "nope"})


def test_tool_results_redacted_and_truncated():
    s = FakeSystem()
    for i in range(400):
        s.add_key(UNINSTALL + rf"\app{i}", {
            "DisplayName": f"App {i}", "Publisher": "Acme",
            "InstallLocation": rf"C:\Users\tester\AppData\Local\Acme\App{i}"})
    tb = ToolBox(s, TriageState({}, []))
    out = tb.call("list_installed_apps", "{}")
    assert out.endswith("…(已截断)")
    assert len(out) <= 12000 + len("…(已截断)")
    assert "tester" not in out and r"\\Users\\%USER%\\" in out

    small = tb.call("list_installed_apps", json.dumps({"keyword": "App 7"}))
    assert not small.endswith("…(已截断)")
    assert r"C:\Users\%USER%\AppData" in json.loads(small)[0]["install_location"]


def test_call_never_raises(monkeypatch):
    tb = ToolBox(FakeSystem(), TriageState({}, []))

    def boom(sys):
        raise RuntimeError("kaboom")
    monkeypatch.setattr("app_triage.ai.tools.list_installed", boom)
    out = call(tb, "list_installed_apps", {})
    assert "error" in out
    assert "error" in json.loads(tb.call("get_finding", "null"))


def test_toolbox_never_executes_actions():
    s = wps_system()
    f = finding()
    tb = ToolBox(s, TriageState({f.id: f}, []))
    before = copy.deepcopy(s.__dict__)
    for key in SCANNERS:
        tb.call("run_scanner", json.dumps({"name": key}))
    tb.call("list_installed_apps", "{}")
    tb.call("get_finding", json.dumps({"finding_id": f.id}))
    assert call(tb, "propose_fix", {"finding_id": f.id, "action_index": 0, "reason": "r"}) == {"ok": True}
    assert s.__dict__ == before
    assert s.launched == [] and s.opened_uris == [] and s.restore_points == []
