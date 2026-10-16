import os

os.environ["QT_QPA_PLATFORM"] = "offscreen"  # before any Qt import / QApplication

from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402

from app_triage.config import Config  # noqa: E402
from app_triage.safety.journal import Journal  # noqa: E402
from app_triage.sysapi.base import SignatureInfo  # noqa: E402
from app_triage.sysapi.fake import FakeSystem  # noqa: E402
from tests.fakes import ScriptedBackend  # noqa: E402

FILEEXTS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
WPS_DIR = r"C:\Users\tester\AppData\Local\Kingsoft\WPS Office"
WPS_LEFTOVER = r"C:\Users\tester\AppData\Roaming\Kingsoft"


def wps_system() -> FakeSystem:
    """WPS scenario: hijacked .jpg, WPS Run value, WPS leftover dir."""
    s = FakeSystem()
    s.add_key(FILEEXTS + r"\.jpg\UserChoice", {"ProgId": "WPS.PIC.jpg"})
    s.add_key(FILEEXTS + r"\.jpg\OpenWithProgids", {"WPS.PIC.jpg": ""})  # FakeSystem.reg_export cannot serialize bytes
    s.add_key(r"HKCR\WPS.PIC.jpg\shell\open\command", {"": f'"{WPS_DIR}\\ksolaunch.exe" "%1"'})
    s.add_key(RUN, {"WPSCloud": f'"{WPS_DIR}\\wpscloudsvr.exe" /tray'})
    s.set_signature(WPS_DIR + r"\wpscloudsvr.exe",
                    SignatureInfo("valid", "Zhuhai Kingsoft Office Software Co., Ltd."))
    s.add_file(WPS_LEFTOVER + r"\WPS Office\cfg.ini", size=100)
    return s


@pytest.fixture
def make_app(qtbot, tmp_path):
    """Build a MainWindow over the WPS FakeSystem with non-modal hooks recorded for asserts."""
    from app_triage.ui.main_window import MainWindow

    def make(api_key: str = "sk-test", responses=(), yes: bool = True):
        env = SimpleNamespace(sys=wps_system(), journal=Journal(tmp_path / "sessions"),
                              saved=[], built=[], informed=[], asked=[], confirmed=[])
        env.backend = ScriptedBackend(list(responses))

        def factory(cfg: Config):
            env.built.append(cfg)
            return env.backend

        win = MainWindow(env.sys, env.journal, Config(api_key=api_key), env.saved.append, factory)
        qtbot.addWidget(win)
        win.inform = lambda title, text: env.informed.append((title, text))
        win.ask_yes_no = lambda title, text: env.asked.append((title, text)) or yes
        win.confirm_fixes = lambda specs: env.confirmed.append(list(specs)) or True
        env.win = win
        return env

    return make


@pytest.fixture(autouse=True)
def _drain_workers(qtbot):
    yield
    from PySide6.QtCore import QThreadPool
    QThreadPool.globalInstance().waitForDone(5000)
