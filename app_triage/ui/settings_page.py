"""设置 page: DeepSeek API Key, Base URL and model; test the connection and save."""
from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtWidgets import (
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget,
)

from app_triage.ai.client import test_connection
from app_triage.config import DEFAULT_BASE_URL, DEFAULT_MODEL, Config

from .workers import run_in_thread

if TYPE_CHECKING:
    from .main_window import MainWindow


class SettingsPage(QWidget):
    def __init__(self, main: MainWindow) -> None:
        super().__init__()
        self.main = main
        cfg = main.cfg
        self.key_edit = QLineEdit(cfg.api_key)
        self.key_edit.setEchoMode(QLineEdit.Password)
        self.key_edit.setPlaceholderText("sk-…")
        self.base_url_edit = QLineEdit(cfg.base_url)
        self.base_url_edit.setPlaceholderText(DEFAULT_BASE_URL)
        self.model_edit = QLineEdit(cfg.model)
        self.model_edit.setPlaceholderText(DEFAULT_MODEL)
        self.test_button = QPushButton("测试连接")
        self.save_button = QPushButton("保存")

        form = QFormLayout()
        form.addRow("DeepSeek API Key：", self.key_edit)
        form.addRow("Base URL：", self.base_url_edit)
        form.addRow("模型：", self.model_edit)
        buttons = QHBoxLayout()
        buttons.addWidget(self.test_button)
        buttons.addWidget(self.save_button)
        buttons.addStretch(1)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(QLabel("API Key 只保存在本机，并使用 Windows 加密保护。"
                                "发送给 AI 的只有程序名称、路径、注册表项等信息，用户名会被隐藏。"))
        layout.addLayout(buttons)
        layout.addStretch(1)

        self.test_button.clicked.connect(self._test)
        self.save_button.clicked.connect(self._save)

    def current_config(self) -> Config:
        return Config(api_key=self.key_edit.text().strip(),
                      base_url=self.base_url_edit.text().strip() or DEFAULT_BASE_URL,
                      model=self.model_edit.text().strip() or DEFAULT_MODEL)

    def _test(self) -> None:
        cfg = self.current_config()
        self.test_button.setEnabled(False)
        self.test_button.setText("正在测试…")
        run_in_thread(lambda: test_connection(cfg), self._test_done, self._test_done)

    def _test_done(self, error: object) -> None:
        self.test_button.setEnabled(True)
        self.test_button.setText("测试连接")
        if error is None:
            self.main.inform("测试连接", "连接成功。")
        else:
            self.main.inform("测试连接", f"连接失败：{error}")

    def _save(self) -> None:
        try:
            self.main.apply_settings(self.current_config())
        except Exception as exc:  # noqa: BLE001 - e.g. the config file cannot be written
            self.main.inform("保存失败", f"无法保存设置：{exc}")
            return
        self.main.inform("设置已保存", "设置已保存。")
