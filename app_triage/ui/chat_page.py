"""AI 助手 page: chat transcript, input, and the list of fixes the AI proposed."""
from __future__ import annotations

import html
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton, QTextBrowser,
    QVBoxLayout, QWidget,
)

from app_triage.actions import ExecResult
from app_triage.ai.agent import AgentReply
from app_triage.ai.tools import Proposal
from app_triage.models import ActionSpec, Finding

from . import describe_spec
from .workers import run_in_thread

if TYPE_CHECKING:
    from .main_window import MainWindow

PROPOSAL_ROLE = Qt.UserRole
KEY_NOTICE = '<a href="settings">请先在设置里填写 DeepSeek API Key</a>'


class ChatPage(QWidget):
    def __init__(self, main: MainWindow) -> None:
        super().__init__()
        self.main = main
        self.busy = False

        self.new_button = QPushButton("新对话")
        self.key_notice = QLabel(KEY_NOTICE)
        self.key_notice.linkActivated.connect(lambda _: main.show_page(main.settings_page))
        self.transcript = QTextBrowser()
        self.thinking = QLabel("AI 正在分析，请稍候…")
        self.thinking.hide()
        self.input = QLineEdit()
        self.input.setPlaceholderText("描述你遇到的问题，例如：图片都被 WPS 打开了")
        self.send_button = QPushButton("发送")
        self.proposal_list = QListWidget()
        self.execute_button = QPushButton("执行所选修复")

        top = QHBoxLayout()
        top.addWidget(self.key_notice)
        top.addStretch(1)
        top.addWidget(self.new_button)
        send_row = QHBoxLayout()
        send_row.addWidget(self.input, 1)
        send_row.addWidget(self.send_button)
        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.transcript, 3)
        layout.addWidget(self.thinking)
        layout.addLayout(send_row)
        layout.addWidget(QLabel("待确认的修复（AI 只能建议，勾选并确认后才会执行）："))
        layout.addWidget(self.proposal_list, 1)
        layout.addWidget(self.execute_button, 0, Qt.AlignLeft)

        self.send_button.clicked.connect(self._send)
        self.input.returnPressed.connect(self._send)
        self.new_button.clicked.connect(self.new_conversation)
        self.execute_button.clicked.connect(self._execute)
        self.refresh_key_state()

    # ---- state -------------------------------------------------------------
    def _has_key(self) -> bool:
        return bool(self.main.cfg.api_key.strip())

    def refresh_key_state(self) -> None:
        has_key = self._has_key()
        self.key_notice.setVisible(not has_key)
        self.input.setEnabled(has_key and not self.busy)
        self.send_button.setEnabled(has_key and not self.busy)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self.thinking.setVisible(busy)
        self.new_button.setEnabled(not busy)
        self.refresh_key_state()

    def _append(self, who: str, text: str) -> None:
        body = html.escape(text).replace("\n", "<br>")
        self.transcript.append(f"<p><b>{who}：</b>{body}</p>")

    # ---- talking to the agent ---------------------------------------------
    def _send(self) -> None:
        text = self.input.text().strip()
        if not text or self.busy or not self._has_key():
            return
        self.input.clear()
        self._append("你", text)
        agent = self.main.agent
        self._run(lambda: agent.ask(text))

    def explain(self, findings: list[Finding]) -> None:
        """Ask the AI to explain scan findings (called by the scan page)."""
        if not self._has_key():
            self.main.inform("需要 API Key", "请先在设置里填写 DeepSeek API Key。")
            return
        if self.busy:
            self.main.inform("请稍候", "AI 还在回答上一个问题。")
            return
        self._append("你", f"请解释这 {len(findings)} 项扫描结果。")
        agent = self.main.agent
        self._run(lambda: agent.explain(findings))

    def _run(self, call) -> None:
        self._set_busy(True)
        run_in_thread(call, self._reply, self._failed)

    def _reply(self, reply: AgentReply) -> None:
        self._set_busy(False)
        self._append("AI", reply.text)
        self.refresh_proposals()

    def _failed(self, exc: BaseException) -> None:
        self._set_busy(False)
        self._append("AI", f"出现意外错误：{exc}")

    def new_conversation(self) -> None:
        if self.busy:
            return
        self.main.agent.reset()
        self.main.state.proposals.clear()
        self.transcript.clear()
        self.refresh_proposals()

    # ---- proposals ---------------------------------------------------------
    def _resolve(self, p: Proposal) -> tuple[Finding, ActionSpec] | None:
        f = self.main.state.findings.get(p.finding_id)
        if f is None or not 0 <= p.action_index < len(f.actions):
            return None
        return f, f.actions[p.action_index]

    def refresh_proposals(self) -> None:
        checked = {id(p) for p in self._checked()}
        self.proposal_list.clear()
        for p in self.main.state.proposals:
            resolved = self._resolve(p)
            if resolved is None:
                continue
            f, spec = resolved
            item = QListWidgetItem(f"{describe_spec(spec)}\n    理由：{p.reason}")
            item.setToolTip(f.title)
            item.setData(PROPOSAL_ROLE, p)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if id(p) in checked else Qt.Unchecked)
            self.proposal_list.addItem(item)

    def _checked(self) -> list[Proposal]:
        items = (self.proposal_list.item(i) for i in range(self.proposal_list.count()))
        return [it.data(PROPOSAL_ROLE) for it in items if it.checkState() == Qt.Checked]

    def _execute(self) -> None:
        chosen = [(p, r) for p in self._checked() if (r := self._resolve(p)) is not None]

        def done(result: ExecResult) -> None:
            applied = [chosen[e.index][0] for e in result.entries if e.status == "applied"]
            # by identity: Proposal is an unhashable dataclass and equal ones may coexist
            self.main.state.proposals[:] = [p for p in self.main.state.proposals
                                            if all(p is not a for a in applied)]
            self.refresh_proposals()

        self.main.run_fixes([r for _, r in chosen], "执行 AI 建议的修复", done)
