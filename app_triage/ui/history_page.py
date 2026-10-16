"""修复记录 page: every fix session from the journal, with undo."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

from app_triage.actions import undo_session
from app_triage.models import ActionSpec
from app_triage.safety.journal import FixSession, JournalEntry

from . import describe_spec
from .workers import run_in_thread

if TYPE_CHECKING:
    from .main_window import MainWindow

SESSION_ROLE = Qt.UserRole
STATUS_NAMES = {"applied": "已执行", "failed": "未执行", "undone": "已撤销", "undo_failed": "撤销失败"}


def describe_entry(e: JournalEntry) -> str:
    return describe_spec(ActionSpec(e.kind, e.target, tuple(e.params.items())))


def _status_text(e: JournalEntry) -> str:
    name = STATUS_NAMES.get(e.status, e.status)
    return f"{name}：{e.message}" if e.message else name


def _session_summary(s: FixSession) -> str:
    counts: dict[str, int] = {}
    for e in s.entries:
        counts[e.status] = counts.get(e.status, 0) + 1
    return "，".join(f"{STATUS_NAMES.get(k, k)} {n}" for k, n in counts.items()) or "无操作"


class HistoryPage(QWidget):
    def __init__(self, main: MainWindow) -> None:
        super().__init__()
        self.main = main
        self.busy = False
        self.refresh_button = QPushButton("刷新")
        self.undo_button = QPushButton("撤销此次修复")
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["时间", "内容", "结果"])
        self.tree.header().setSectionResizeMode(1, QHeaderView.Stretch)

        buttons = QHBoxLayout()
        buttons.addWidget(self.refresh_button)
        buttons.addWidget(self.undo_button)
        buttons.addStretch(1)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("每次修复前都会备份，选中一次修复后可以撤销。卸载操作无法撤销。"))
        layout.addLayout(buttons)
        layout.addWidget(self.tree, 1)

        self.refresh_button.clicked.connect(self.refresh)
        self.undo_button.clicked.connect(self._undo)
        self.refresh()

    def refresh(self) -> None:
        self.tree.clear()
        try:
            sessions = self.main.journal.sessions()
        except OSError as exc:
            self.main.inform("无法读取修复记录", str(exc))
            return
        for s in sessions:
            top = QTreeWidgetItem([s.created.replace("T", " "), s.label, _session_summary(s)])
            top.setData(0, SESSION_ROLE, s.id)
            for e in s.entries:
                child = QTreeWidgetItem(["", describe_entry(e), _status_text(e)])
                child.setToolTip(2, _status_text(e))
                top.addChild(child)
            self.tree.addTopLevelItem(top)

    def _selected_session(self) -> str | None:
        item = self.tree.currentItem()
        while item is not None and item.parent() is not None:
            item = item.parent()
        return None if item is None else item.data(0, SESSION_ROLE)

    def _undo(self) -> None:
        if self.busy:
            return
        session_id = self._selected_session()
        if session_id is None:
            self.main.inform("未选择", "请先选中一次修复记录。")
            return
        session = self.main.journal.load(session_id)
        applied = [e for e in session.entries if e.status == "applied"]
        if not applied:
            self.main.inform("无需撤销", "此次修复没有可撤销的操作。")
            return
        if not self.main.ask_yes_no(
                "撤销修复", f"确定要撤销“{session.label}”（{session.created.replace('T', ' ')}）"
                            f"中已执行的 {len(applied)} 项操作吗？"):
            return
        self.busy = True
        main = self.main
        run_in_thread(lambda: undo_session(session_id, main.sys, main.journal),
                      self._undo_done, self._undo_failed)

    def _undo_done(self, results: list[JournalEntry]) -> None:
        self.busy = False
        failed = [e for e in results if e.status != "undone"]
        lines = [f"已撤销 {len(results) - len(failed)} 项，失败 {len(failed)} 项。"]
        lines += [f"· {describe_entry(e)}：{e.message}" for e in failed]
        self.refresh()
        self.main.inform("撤销完成", "\n".join(lines))

    def _undo_failed(self, exc: BaseException) -> None:
        self.busy = False
        self.refresh()
        self.main.inform("撤销出错", f"撤销过程中出现意外错误：{exc}")
