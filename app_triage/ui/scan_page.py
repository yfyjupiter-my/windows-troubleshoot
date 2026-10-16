"""扫描 page: run the scanners, show findings grouped by scanner, explain or fix the checked ones."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
    QWidget,
)

import app_triage.scanners  # noqa: F401 - registers every scanner in SCANNERS
from app_triage.models import Finding
from app_triage.scanners.base import SCANNERS, ScanResult, run_scan

from . import RISK_COLORS, RISK_NAMES
from .workers import run_in_thread

if TYPE_CHECKING:
    from .main_window import MainWindow

FINDING_ID_ROLE = Qt.UserRole
BANNER_STYLE = ("background:#fef7e0; color:#5f4b00; border:1px solid #f9d36b;"
                "border-radius:4px; padding:6px;")


def _evidence_text(f: Finding) -> str:
    return "\n".join(f"{k}：{v}" for k, v in f.evidence.items() if v) or "（无更多证据）"


class ScanPage(QWidget):
    def __init__(self, main: MainWindow) -> None:
        super().__init__()
        self.main = main
        self.scanning = False
        self._results: dict[str, list[Finding]] = {}  # scanner key -> latest findings
        self._errors: dict[str, str] = {}
        self._queued: list[str] | None = None  # keys requested while a scan was running
        self._queued_all = False

        self.scan_button = QPushButton("开始扫描")
        self.explain_button = QPushButton("让 AI 解释")
        self.fix_button = QPushButton("修复所选")
        self.status = QLabel("点击“开始扫描”检查这台电脑。扫描只读取信息，不会做任何修改。")
        self.error_banner = QLabel()
        self.error_banner.setWordWrap(True)
        self.error_banner.setStyleSheet(BANNER_STYLE)
        self.error_banner.hide()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["发现", "风险", "厂商"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)

        buttons = QHBoxLayout()
        for b in (self.scan_button, self.explain_button, self.fix_button):
            buttons.addWidget(b)
        buttons.addStretch(1)
        layout = QVBoxLayout(self)
        layout.addLayout(buttons)
        layout.addWidget(self.status)
        layout.addWidget(self.error_banner)
        layout.addWidget(self.tree, 1)

        self.scan_button.clicked.connect(lambda: self.rescan(None))
        self.explain_button.clicked.connect(self._explain)
        self.fix_button.clicked.connect(self._fix)

    # ---- scanning --------------------------------------------------------
    def rescan(self, keys: list[str] | None) -> None:
        """Run the given scanner keys (all when None) off the UI thread and refresh the tree."""
        if self.scanning:
            if keys is None:
                self._queued_all = True
            else:
                self._queued = sorted(set(self._queued or []) | set(keys))
            return
        self.scanning = True
        self.scan_button.setEnabled(False)
        self.status.setText("正在扫描，请稍候…")
        sys = self.main.sys
        scanned = list(SCANNERS) if keys is None else list(keys)
        run_in_thread(lambda: run_scan(sys, scanned),
                      lambda result: self._scan_done(scanned, result), self._scan_failed)

    def _scan_done(self, keys: list[str], result: ScanResult) -> None:
        for key in keys:
            self._results[key] = []
            self._errors.pop(key, None)
        for f in result.findings:
            self.main.state.findings[f.id] = f
            self._results.setdefault(f.category, []).append(f)
        self._errors.update(result.errors)
        self._finish(f"扫描完成，共发现 {sum(map(len, self._results.values()))} 项。")

    def _scan_failed(self, exc: BaseException) -> None:
        self._finish(f"扫描失败：{exc}")

    def _finish(self, status: str) -> None:
        self.scanning = False
        self.scan_button.setEnabled(True)
        self.status.setText(status)
        self._show_errors()
        self._fill_tree()
        if self._queued_all or self._queued:
            keys = None if self._queued_all else self._queued
            self._queued, self._queued_all = None, False
            self.rescan(keys)

    def _show_errors(self) -> None:
        if not self._errors:
            self.error_banner.hide()
            return
        lines = [f"{SCANNERS[k][0] if k in SCANNERS else k}：{msg}" for k, msg in self._errors.items()]
        self.error_banner.setText("以下扫描项未能完成，其他结果不受影响：\n" + "\n".join(lines))
        self.error_banner.show()

    def _fill_tree(self) -> None:
        self.tree.clear()
        for key, findings in self._results.items():
            if not findings:
                continue
            label = SCANNERS[key][0] if key in SCANNERS else key
            group = QTreeWidgetItem([f"{label}（{len(findings)}）"])
            self.tree.addTopLevelItem(group)
            for f in findings:
                group.addChild(self._row(f))
            group.setExpanded(True)

    @staticmethod
    def _row(f: Finding) -> QTreeWidgetItem:
        item = QTreeWidgetItem([f.title, RISK_NAMES[f.risk], f.vendor or ""])
        item.setData(0, FINDING_ID_ROLE, f.id)
        tip = _evidence_text(f)
        color = RISK_COLORS.get(f.risk)
        for col in range(3):
            item.setToolTip(col, tip)
            if color:
                item.setForeground(col, QColor(color))
        if f.actions:
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Unchecked)
        return item

    # ---- selection -------------------------------------------------------
    def _rows(self) -> list[QTreeWidgetItem]:
        return [self.tree.topLevelItem(i).child(j)
                for i in range(self.tree.topLevelItemCount())
                for j in range(self.tree.topLevelItem(i).childCount())]

    def _finding(self, item: QTreeWidgetItem) -> Finding:
        return self.main.state.findings[item.data(0, FINDING_ID_ROLE)]

    def checked_findings(self) -> list[Finding]:
        return [self._finding(r) for r in self._rows()
                if r.flags() & Qt.ItemIsUserCheckable and r.checkState(0) == Qt.Checked]

    def _explain(self) -> None:
        findings = self.checked_findings() or [self._finding(r) for r in self._rows()]
        if not findings:
            self.main.inform("没有扫描结果", "请先点击“开始扫描”。")
            return
        self.main.show_page(self.main.chat_page)
        self.main.chat_page.explain(findings)

    def _fix(self) -> None:
        # scanners emit one action per finding: a row's fix is its first action
        items = [(f, f.actions[0]) for f in self.checked_findings()]
        self.main.run_fixes(items, "修复扫描结果")
