import json
from types import SimpleNamespace

import httpx2 as httpx
import openai
import pytest

from app_triage.ai import client as client_mod
from app_triage.ai.agent import SYSTEM_PROMPT, Agent
from app_triage.ai.client import AssistantMessage, DeepSeekBackend, ToolCall, describe_error, test_connection as check_connection
from app_triage.ai.tools import Proposal, ToolBox, TriageState
from app_triage.config import Config
from app_triage.models import ActionSpec, Finding, Risk
from app_triage.sysapi.base import SignatureInfo
from app_triage.sysapi.fake import FakeSystem
from tests.fakes import ScriptedBackend

RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
WPS_EXE = r"C:\Users\tester\AppData\Local\Kingsoft\WPS Office\wpscloudsvr.exe"
SYS = {"role": "system", "content": SYSTEM_PROMPT}


def wps_system():
    s = FakeSystem()
    s.add_key(RUN, {"WPSCloud": f'"{WPS_EXE}" /tray'})
    s.set_signature(WPS_EXE, SignatureInfo("valid", "Zhuhai Kingsoft Office Software Co., Ltd."))
    return s


def finding(fid="f1"):
    return Finding(fid, "autoruns", "开机自启：WPSCloud", {"exe": WPS_EXE}, Risk.MEDIUM,
                   [ActionSpec("delete_reg_value", RUN, (("name", "WPSCloud"),))], vendor="WPS (金山办公)")


def toolbox(s=None, findings=()):
    return ToolBox(s or FakeSystem(), TriageState({f.id: f for f in findings}, []))


def tool_msg(name, args, cid="c1", content=""):
    return AssistantMessage(content, [ToolCall(cid, name, json.dumps(args))])


def test_system_prompt_covers_the_rules():
    for phrase in ("Windows 排查助手", "propose_fix", "WPS", "2345", "360", "鲁大师", "不确定"):
        assert phrase in SYSTEM_PROMPT


def test_agent_runs_tool_then_answers():
    backend = ScriptedBackend([tool_msg("run_scanner", {"name": "autoruns"}, cid="call_1"),
                               AssistantMessage("发现 WPS 自启", [])])
    tb = toolbox(wps_system())
    agent = Agent(backend, tb)
    reply = agent.ask("开机很慢")
    assert reply.text == "发现 WPS 自启" and reply.new_proposals == []
    second = backend.calls[1]
    assert second[0] == SYS and second[1] == {"role": "user", "content": "开机很慢"}
    assert second[2] == {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_1", "type": "function",
         "function": {"name": "run_scanner", "arguments": json.dumps({"name": "autoruns"})}}]}
    tool = second[3]
    assert tool["role"] == "tool" and tool["tool_call_id"] == "call_1"
    assert "WPSCloud" in tool["content"] and "tester" not in tool["content"]
    assert agent.history[-1] == {"role": "assistant", "content": "发现 WPS 自启"}
    assert backend.tools[0] == tb.schemas
    assert len(tb.state.findings) == 1


def test_new_proposals_are_those_added_during_the_call():
    f = finding()
    tb = toolbox(findings=[f])
    tb.state.proposals.append(Proposal("old", 0, "earlier"))
    backend = ScriptedBackend([
        tool_msg("propose_fix", {"finding_id": f.id, "action_index": 0, "reason": "拖慢开机"}),
        AssistantMessage("建议删除该自启项，需要你确认。", [])])
    reply = Agent(backend, tb).ask("帮我处理")
    assert reply.new_proposals == [Proposal(f.id, 0, "拖慢开机")]
    assert len(tb.state.proposals) == 2


def test_backend_error_returns_chinese_message_and_history_stays_valid():
    tb = toolbox()
    agent = Agent(ScriptedBackend([TimeoutError("timed out"), AssistantMessage("好的", [])]), tb)
    r1 = agent.ask("开机很慢"); assert r1.text.startswith("AI 调用失败")
    assert r1.text == "AI 调用失败：请求超时。请检查网络或在设置里检查 API Key。"
    assert agent.history == [{"role": "system", "content": SYSTEM_PROMPT}]
    assert agent.ask("再试一次").text == "好的"


def test_backend_error_after_tool_round_rolls_back_everything():
    f = finding()
    tb = toolbox(wps_system(), [f])
    backend = ScriptedBackend([
        AssistantMessage("第一轮", []),
        tool_msg("propose_fix", {"finding_id": f.id, "action_index": 0, "reason": "r"}),
        RuntimeError("boom"),
        AssistantMessage("恢复了", [])])
    agent = Agent(backend, tb)
    agent.ask("你好")
    kept = list(agent.history)
    r = agent.ask("修一下")
    assert r.text == "AI 调用失败：RuntimeError。请检查网络或在设置里检查 API Key。"
    assert r.new_proposals == []
    assert agent.history == kept and tb.state.proposals == []
    assert agent.ask("再来").text == "恢复了"
    assert backend.calls[-1][-1] == {"role": "user", "content": "再来"}
    assert backend.calls[-1][:-1] == kept


def test_max_rounds_stops_loop():
    backend = ScriptedBackend([tool_msg("list_installed_apps", {}, cid=f"c{i}", content=f"第{i}轮")
                               for i in range(2)])
    agent = Agent(backend, toolbox(), max_rounds=2)
    r = agent.ask("查一下")
    assert r.text.startswith("已达到本次最大排查轮数")
    assert r.text == "已达到本次最大排查轮数（2 轮），以下是目前的结论：第1轮"
    assert len(backend.calls) == 2
    # the last tool calls were answered, so history is still valid
    assert agent.history[-1]["role"] == "tool" and agent.history[-1]["tool_call_id"] == "c1"


def test_default_max_rounds_message_says_8():
    backend = ScriptedBackend([tool_msg("list_installed_apps", {}, cid=f"c{i}") for i in range(8)])
    r = Agent(backend, toolbox()).ask("查")
    assert r.text == "已达到本次最大排查轮数（8 轮），以下是目前的结论："
    assert len(backend.calls) == 8


def test_explain_adds_findings_and_sends_redacted_json():
    f = finding()
    tb = toolbox()
    backend = ScriptedBackend([AssistantMessage("解释完毕", [])])
    reply = Agent(backend, tb).explain([f])
    assert reply.text == "解释完毕"
    assert tb.state.findings == {f.id: f}
    assert tb.state.findings[f.id].evidence["exe"] == WPS_EXE  # stored copy stays unredacted
    user = backend.calls[0][1]
    assert user["role"] == "user"
    prefix = "请逐项解释以下扫描结果，并对你认为应该修复的项调用 propose_fix：\n"
    assert user["content"].startswith(prefix)
    payload = json.loads(user["content"][len(prefix):])
    assert payload[0]["id"] == f.id
    assert payload[0]["evidence"]["exe"] == r"C:\Users\%USER%\AppData\Local\Kingsoft\WPS Office\wpscloudsvr.exe"
    assert "金山" in user["content"]


def test_explain_without_findings_does_not_call_backend():
    backend = ScriptedBackend([])
    agent = Agent(backend, toolbox())
    r = agent.explain([])
    assert r.text == "没有需要解释的扫描结果。" and r.new_proposals == []
    assert backend.calls == [] and agent.history == [SYS]


def test_ask_redacts_user_text():
    backend = ScriptedBackend([AssistantMessage("ok", [])])
    Agent(backend, toolbox()).ask(r"C:\Users\tester\a.exe 是什么？")
    assert backend.calls[0][1]["content"] == r"C:\Users\%USER%\a.exe 是什么？"


def test_reset_clears_history():
    agent = Agent(ScriptedBackend([AssistantMessage("hi", [])]), toolbox())
    agent.ask("hello")
    assert len(agent.history) == 3
    agent.reset()
    assert agent.history == [SYS]


# ---- client -------------------------------------------------------------

REQ = httpx.Request("GET", "https://api.deepseek.com/models")


@pytest.mark.parametrize("exc, text", [
    (TimeoutError("x"), "请求超时"),
    (openai.APITimeoutError(request=REQ), "请求超时"),
    (openai.AuthenticationError("bad key", response=httpx.Response(401, request=REQ), body=None),
     "API Key 无效"),
    (openai.APIConnectionError(request=REQ), "网络连接失败"),
    (ValueError("x"), "ValueError"),
])
def test_describe_error(exc, text):
    assert describe_error(exc) == text


class FakeOpenAI:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.created = []
        self.list_error = None
        self.response = None
        FakeOpenAI.instances.append(self)
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
        self.models = SimpleNamespace(list=self._list)

    def _create(self, **kwargs):
        self.created.append(kwargs)
        return self.response

    def _list(self):
        if self.list_error:
            raise self.list_error
        return []


@pytest.fixture
def fake_openai(monkeypatch):
    FakeOpenAI.instances = []
    monkeypatch.setattr(client_mod, "OpenAI", FakeOpenAI)
    return FakeOpenAI


def sdk_response(content, tool_calls=None):
    msg = SimpleNamespace(content=content, tool_calls=tool_calls)
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_deepseek_backend_converts_response(fake_openai):
    cfg = Config(api_key="sk-1", base_url="https://example.test", model="m1")
    backend = DeepSeekBackend(cfg)
    (inst,) = fake_openai.instances
    assert inst.kwargs == {"api_key": "sk-1", "base_url": "https://example.test", "timeout": 60}
    inst.response = sdk_response(None, [SimpleNamespace(
        id="t1", type="function", function=SimpleNamespace(name="get_finding", arguments='{"finding_id":"x"}'))])
    msgs, tools = [SYS], [{"type": "function"}]
    out = backend.complete(msgs, tools)
    assert out == AssistantMessage("", [ToolCall("t1", "get_finding", '{"finding_id":"x"}')])
    assert inst.created == [{"model": "m1", "messages": msgs, "tools": tools}]
    inst.response = sdk_response("你好")
    assert backend.complete(msgs, tools) == AssistantMessage("你好", [])


def test_connection_requires_key_without_network(fake_openai):
    assert check_connection(Config(api_key="  ")) == "请先填写 API Key"
    assert fake_openai.instances == []


def test_connection_ok_and_error_mapping(fake_openai, monkeypatch):
    assert check_connection(Config(api_key="sk")) is None
    orig_init = FakeOpenAI.__init__

    def failing_init(self, **kw):
        orig_init(self, **kw)
        self.list_error = openai.AuthenticationError(
            "bad", response=httpx.Response(401, request=REQ), body=None)
    monkeypatch.setattr(FakeOpenAI, "__init__", failing_init)
    assert check_connection(Config(api_key="sk")) == "API Key 无效"
