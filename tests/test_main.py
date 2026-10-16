import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")  # before any Qt import

from PySide6.QtWidgets import QApplication  # noqa: E402

import app_triage.scanners  # noqa: E402,F401  (registers the scanners)
from app_triage import main as main_module  # noqa: E402
from app_triage.scanners.base import SCANNERS, run_scan  # noqa: E402
from app_triage.sysapi.demo import demo_system  # noqa: E402


def test_demo_scan_finds_all_scenario_items():
    result = run_scan(demo_system())
    assert result.errors == {}
    assert {f.category for f in result.findings} == set(SCANNERS) == {
        "installed", "file_assoc", "autoruns", "leftovers", "hidden", "browser"}
    exts = {f.evidence["ext"]: f for f in result.findings if f.category == "file_assoc"}
    assert exts[".jpg"].evidence["acl"] == "denied"
    assert {".png", ".pdf"} <= set(exts) and "acl" not in exts[".png"].evidence
    titles = " ".join(f.title for f in result.findings)
    assert "WPSCloud" in titles and "wpscloudsvr".lower() in " ".join(
        f.evidence.get("name", "") for f in result.findings).lower()
    assert any(f.evidence.get("source") == "task" for f in result.findings)
    assert not any("WPS Office" in f.evidence.get("name", "") and f.category == "installed"
                   for f in result.findings)  # WPS itself is uninstalled: only traces remain
    assert any(f.category == "browser" and "2345.com" in str(f.evidence) for f in result.findings)


def test_main_demo_constructs_window(qapp, monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    shown = []
    monkeypatch.setattr(QApplication, "exec", lambda *a: shown.append(
        [w for w in qapp.topLevelWidgets() if w.isVisible()]) or 0)
    assert main_module.main(["--demo"]) == 0
    [windows] = shown
    assert any("演示模式" in w.windowTitle() for w in windows)
    for w in windows:
        w.close()
        w.deleteLater()


def test_data_dir_demo_is_under_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "Roaming"))
    assert main_module.data_dir(True) == tmp_path / ".apptriage"
