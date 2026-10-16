"""Main window: left navigation, the four pages, the shared AI state and the fix flow."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QStackedWidget, QVBoxLayout, QWidget,
)

from app_triage.actions import ExecResult, execute
from app_triage.actions.base import resolve_fs_path
from app_triage.ai.agent import Agent
from app_triage.ai.client import ChatBackend
from app_triage.ai.tools import ToolBox, TriageState
from app_triage.config import Config
from app_triage.models import ActionSpec, Finding
from app_triage.safety.journal import Journal, JournalEntry
from app_triage.scanners.base import SCANNERS
from app_triage.sysapi.base import SystemAPI

from . import HIGH_RISK_COLOR, describe_spec, is_reversible
from .chat_page import ChatPage
from .history_page import HistoryPage, describe_entry
from .scan_page import ScanPage
from .settings_page import SettingsPage
from .workers import run_in_thread

WINDOW_TITLE = "AppTriage 应用排查工具"
RESTORE_POINT_WARNING = "系统还原点创建失败，但已备份注册表和文件"
DEFAULT_APPS_URI = "ms-settings:defaultapps"
DEFAULT_APPS_MESSAGE = (
    "还差最后一步：Windows 不允许程序直接替你选择默认应用。\n"
    "点击“确定”后会打开系统的“默认应用”设置，请为刚才重置的文件类型（例如 .jpg）"
    "重新选择你想用的程序（例如“照片”）。")


class ConfirmFixesDialog(QDialog):
    """Lists every action that will run; irreversible ones are marked, high-risk ones are red."""

    def __init__(self, specs: list[ActionSpec], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("确认修复")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"即将执行以下 {len(specs)} 项修复。执行前会尝试创建系统还原点，"
                                "并备份相关的注册表和文件："))
        items = QListWidget()
        for spec in specs:
            text = describe_spec(spec)
            if not is_reversible(spec):
                text += "（不可撤销）"
            item = QListWidgetItem(text)
            if spec.high_risk:
                item.setText(text + "（高风险，执行时会再次确认）")
                item.setForeground(QColor(HIGH_RISK_COLOR))
            items.addItem(item)
        layout.addWidget(items)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("执行修复")
        buttons.button(QDialogButtonBox.Cancel).setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.resize(640, 360)


class MainWindow(QMainWindow):
    def __init__(self, sys: SystemAPI, journal: Journal, cfg: Config,
                 save_cfg: Callable[[Config], None],
                 backend_factory: Callable[[Config], ChatBackend]) -> None:
        super().__init__()
        self.sys, self.journal, self.cfg = sys, journal, cfg
        self._save_cfg, self._backend_factory = save_cfg, backend_factory
        self.state = TriageState({}, [])
        self.toolbox = ToolBox(sys, self.state)
        self.agent = Agent(backend_factory(cfg), self.toolbox)
        self._fixing = False
        # Dialog hooks used by every page; tests replace them with plain callables.
        self.ask_yes_no: Callable[[str, str], bool] = self._ask_yes_no
        self.confirm_fixes: Callable[[list[ActionSpec]], bool] = self._confirm_fixes
        self.inform: Callable[[str, str], None] = self._inform

        self.setWindowTitle(WINDOW_TITLE)
        self.resize(1100, 720)
        self.nav = QListWidget()
        self.nav.setFixedWidth(130)
        self.stack = QStackedWidget()
        self.scan_page = ScanPage(self)
        self.chat_page = ChatPage(self)
        self.history_page = HistoryPage(self)
        self.settings_page = SettingsPage(self)
        for name, page in (("扫描", self.scan_page), ("AI 助手", self.chat_page),
                           ("修复记录", self.history_page), ("设置", self.settings_page)):
            self.nav.addItem(name)
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)
        central = QWidget()
        row = QHBoxLayout(central)
        row.addWidget(self.nav)
        row.addWidget(self.stack, 1)
        self.setCentralWidget(central)

    # ---- navigation and settings ----------------------------------------
    def show_page(self, page: QWidget) -> None:
        self.nav.setCurrentRow(self.stack.indexOf(page))

    def apply_settings(self, cfg: Config) -> None:
        """Persist ``cfg`` and rebuild the agent; findings and proposals are kept."""
        self._save_cfg(cfg)
        self.cfg = cfg
        self.agent = Agent(self._backend_factory(cfg), self.toolbox)
        self.chat_page.refresh_key_state()

    # ---- fix flow shared by the scan and chat pages ---------------------
    def run_fixes(self, items: list[tuple[Finding, ActionSpec]], label: str,
                  on_done: Callable[[ExecResult], None] | None = None) -> None:
        """Confirm on the UI thread, execute on a worker, then report and rescan."""
        if self._fixing:
            self.inform("请稍候", "上一次修复还在进行中。")
            return
        if not items:
            self.inform("未选择", "请先勾选要修复的项目。")
            return
        specs = [spec for _, spec in items]
        if not self.confirm_fixes(specs):
            return
        answers = self._ask_high_risk(specs)
        keys = sorted({f.category for f, _ in items if f.category in SCANNERS})
        self._fixing = True
        run_in_thread(
            lambda: execute(specs, self.sys, self.journal, lambda s: answers.get(s, False), label),
            lambda result: self._fixes_done(result, keys, on_done), self._fixes_failed)

    def _ask_high_risk(self, specs: list[ActionSpec]) -> dict[ActionSpec, bool]:
        """Per-item Yes/No for high-risk specs (a QMessageBox cannot run on the worker thread).

        Answers are also keyed by the resolved quarantine path, the form ``execute`` asks about.
        """
        answers: dict[ActionSpec, bool] = {}
        for spec in specs:
            if not spec.high_risk:
                continue
            ok = self.ask_yes_no("高风险操作确认",
                                 f"以下操作风险较高，可能影响系统或软件的正常使用：\n\n"
                                 f"{describe_spec(spec)}\n\n确定要执行吗？")
            keys = [spec]
            if spec.kind == "quarantine_path":
                try:
                    keys.append(replace(spec, target=resolve_fs_path(self.sys, spec.target)))
                except Exception:  # noqa: BLE001 - unresolvable targets are refused by execute
                    pass
            for key in keys:
                answers[key] = answers.get(key, True) and ok
        return answers

    def _fixes_done(self, result: ExecResult, keys: list[str],
                    on_done: Callable[[ExecResult], None] | None) -> None:
        self._fixing = False
        self.inform("修复完成", self._summary(result))
        if result.needs_default_apps:
            self.inform("最后一步", DEFAULT_APPS_MESSAGE)
            try:
                self.sys.open_uri(DEFAULT_APPS_URI)
            except Exception as exc:  # noqa: BLE001
                self.inform("无法打开设置", f"请手动打开“设置 → 应用 → 默认应用”。（{exc}）")
        self.history_page.refresh()
        if on_done is not None:
            on_done(result)
        if keys:
            self.scan_page.rescan(keys)

    def _fixes_failed(self, exc: BaseException) -> None:
        self._fixing = False
        self.history_page.refresh()
        self.inform("修复出错", f"修复过程中出现意外错误：{exc}")

    @staticmethod
    def _summary(result: ExecResult) -> str:
        failed: list[JournalEntry] = [e for e in result.entries if e.status != "applied"]
        lines = [f"成功 {len(result.entries) - len(failed)} 项，未完成 {len(failed)} 项。"]
        lines += [f"· {describe_entry(e)}：{e.message}" for e in failed]
        if not result.restore_point:
            lines.append(RESTORE_POINT_WARNING)
        lines.append("如需恢复，可在“修复记录”页撤销此次修复。")
        return "\n".join(lines)

    # ---- default dialog hooks -------------------------------------------
    def _ask_yes_no(self, title: str, text: str) -> bool:
        answer = QMessageBox.warning(self, title, text, QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)
        return answer == QMessageBox.Yes

    def _confirm_fixes(self, specs: list[ActionSpec]) -> bool:
        return ConfirmFixesDialog(specs, self).exec() == QDialog.Accepted

    def _inform(self, title: str, text: str) -> None:
        QMessageBox.information(self, title, text)
