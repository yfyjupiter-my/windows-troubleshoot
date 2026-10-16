"""Program entry: wires the system layer, config, journal and the main window together."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from PySide6.QtWidgets import QApplication, QMessageBox

from app_triage.ai.client import DeepSeekBackend
from app_triage.config import (
    Config, Crypto, DpapiCrypto, NullCrypto, default_config_path, load_config, save_config,
)
from app_triage.safety.journal import Journal
from app_triage.sysapi.base import SystemAPI
from app_triage.sysapi.demo import demo_system
from app_triage.ui.main_window import MainWindow

NOT_ADMIN_TITLE = "需要管理员权限"
NOT_ADMIN_TEXT = ("当前不是以管理员身份运行。扫描可以正常使用，但修复系统服务、计划任务、"
                  "HKLM 注册表等项目需要管理员权限，可能会失败。\n"
                  "请右键以“管理员身份运行”后重试。")


def _use_demo(demo: bool) -> bool:
    return demo or sys.platform != "win32"


def data_dir(demo: bool) -> Path:
    """Root of the app's data: %APPDATA%\\AppTriage on Windows, ~/.apptriage for demo / elsewhere."""
    appdata = os.environ.get("APPDATA")
    if not _use_demo(demo) and appdata:
        return Path(appdata) / "AppTriage"
    return Path.home() / ".apptriage"


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - cannot tell: do not nag
        return True


def _build_environment(demo: bool) -> tuple[SystemAPI, Crypto, Path]:
    """System implementation, key encryption and config path for the chosen mode."""
    if _use_demo(demo):
        # a real API key is entered even in demo mode: keep it DPAPI-protected wherever DPAPI exists
        crypto: Crypto = DpapiCrypto() if sys.platform == "win32" else NullCrypto()
        return demo_system(), crypto, Path.home() / ".apptriage" / "config.json"
    from app_triage.sysapi.windows import WindowsSystem  # imports winreg: Windows only
    return WindowsSystem(), DpapiCrypto(), default_config_path()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app_triage", description="AppTriage 应用排查工具")
    parser.add_argument("--demo", action="store_true",
                        help="使用内置的模拟系统（WPS 卸载后残留的场景），不读取也不修改真实系统")
    args = parser.parse_args(argv)
    demo = _use_demo(args.demo)

    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName("AppTriage")
    system, crypto, config_path = _build_environment(args.demo)
    cfg = load_config(config_path, crypto)

    def save_cfg(new: Config) -> None:
        save_config(new, config_path, crypto)

    window = MainWindow(system, Journal(data_dir(args.demo) / "sessions"), cfg, save_cfg,
                        DeepSeekBackend)
    if demo:
        window.setWindowTitle(window.windowTitle() + "（演示模式）")
    window.show()
    if not demo and not _is_admin():
        QMessageBox.warning(window, NOT_ADMIN_TITLE, NOT_ADMIN_TEXT)
    return QApplication.exec()
