"""Conversation loop: the model investigates with read-only tools and may only propose fixes."""
from __future__ import annotations

import json
from dataclasses import dataclass

from app_triage.models import Finding
from app_triage.safety.redact import redact

from .client import AssistantMessage, ChatBackend, describe_error
from .tools import Proposal, ToolBox

SYSTEM_PROMPT = """你是 AppTriage 的 Windows 排查助手，服务对象是这台电脑的主人。

规则：
1. 你只能通过提供给你的工具查看这台电脑的信息，不能用其他方式。
2. 对每个发现，用通俗易懂的中文说明：它是什么、为什么可疑、修复（删除/禁用/重置）有什么风险或副作用。
3. 你不能直接修改系统。任何修改都必须调用 propose_fix 加入待确认列表，由用户确认后才会执行。绝不要声称你已经修改、删除或修复了任何东西。
4. 不确定时要明确说“不确定”，并说明还需要哪些信息，不要猜测。
5. WPS、2345、360、鲁大师等厂商规则只是线索，不是证据；请结合路径、签名、发行商等证据判断。
6. 用户的用户名在路径中显示为 %USER%，这是正常的隐私处理。"""

EXPLAIN_PREFIX = "请逐项解释以下扫描结果，并对你认为应该修复的项调用 propose_fix：\n"
NOTHING_TO_EXPLAIN = "没有需要解释的扫描结果。"


@dataclass
class AgentReply:
    text: str
    new_proposals: list[Proposal]


def _assistant_dict(msg: AssistantMessage) -> dict:
    if not msg.tool_calls:
        return {"role": "assistant", "content": msg.content}
    return {"role": "assistant", "content": msg.content or None, "tool_calls": [
        {"id": tc.id, "type": "function", "function": {"name": tc.name, "arguments": tc.arguments}}
        for tc in msg.tool_calls]}


class Agent:
    def __init__(self, backend: ChatBackend, toolbox: ToolBox, max_rounds: int = 8) -> None:
        self.backend = backend
        self.toolbox = toolbox
        self.max_rounds = max_rounds
        self.history: list[dict] = []
        self.reset()

    def reset(self) -> None:
        self.history = [{"role": "system", "content": SYSTEM_PROMPT}]

    def _redact(self, text: str) -> str:
        return redact(text, self.toolbox.sys.username())

    def ask(self, user_text: str) -> AgentReply:
        return self._converse(self._redact(user_text))

    def explain(self, findings: list[Finding]) -> AgentReply:
        if not findings:
            return AgentReply(NOTHING_TO_EXPLAIN, [])
        for f in findings:
            self.toolbox.state.findings[f.id] = f
        payload = json.dumps([f.to_dict() for f in findings], ensure_ascii=False)
        return self._converse(EXPLAIN_PREFIX + self._redact(payload))

    def _converse(self, user_content: str) -> AgentReply:
        proposals = self.toolbox.state.proposals
        history_mark, proposals_mark = len(self.history), len(proposals)
        self.history.append({"role": "user", "content": user_content})
        rounds = 0
        while True:
            try:
                msg = self.backend.complete(self.history, self.toolbox.schemas)
            except Exception as e:  # noqa: BLE001 - any backend failure becomes a Chinese message
                # Roll back so history never ends with a dangling user/tool-call turn, and drop
                # proposals the model would no longer remember making.
                del self.history[history_mark:]
                del proposals[proposals_mark:]
                return AgentReply(
                    f"AI 调用失败：{describe_error(e)}。请检查网络或在设置里检查 API Key。", [])
            rounds += 1
            self.history.append(_assistant_dict(msg))
            if not msg.tool_calls:
                return AgentReply(msg.content, list(proposals[proposals_mark:]))
            for tc in msg.tool_calls:
                self.history.append({"role": "tool", "tool_call_id": tc.id,
                                     "content": self.toolbox.call(tc.name, tc.arguments)})
            if rounds >= self.max_rounds:
                return AgentReply(
                    f"已达到本次最大排查轮数（{self.max_rounds} 轮），以下是目前的结论：{msg.content}",
                    list(proposals[proposals_mark:]))
