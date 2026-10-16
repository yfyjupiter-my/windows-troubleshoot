"""Demo scenario for --demo / non-Windows: WPS was uninstalled but its traces remain."""
from __future__ import annotations

import json

from .base import ServiceInfo, ShortcutInfo, SignatureInfo, TaskInfo
from .fake import FakeSystem

USER = r"C:\Users\tester"
FILEEXTS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
UNINSTALL = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
RUN = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
WPS_DIR = USER + r"\AppData\Local\Kingsoft\WPS Office\12.1.0"
KINGSOFT_COMMON = USER + r"\AppData\Roaming\Kingsoft"
VIEWER_DIR = r"C:\Program Files\2345Soft\2345Pic"
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
KINGSOFT_PUBLISHER = "Zhuhai Kingsoft Office Software Co., Ltd."


def _hijack(s: FakeSystem, ext: str, progid: str, *, denied: bool = False) -> None:
    """A file type whose default app was taken over by WPS (ProgId command points at ksolaunch)."""
    s.add_key(f"{FILEEXTS}\\{ext}\\UserChoice", {"ProgId": progid})
    s.add_key(f"{FILEEXTS}\\{ext}\\OpenWithProgids", {progid: b""})
    s.add_key(rf"HKCR\{ext}", {"": progid})
    s.add_key(rf"HKCR\{progid}\shell\open\command", {"": f'"{WPS_DIR}\\ksolaunch.exe" "%1"'})
    if denied:  # WPS locks UserChoice; deleting it needs ownership first
        s.deny(f"{FILEEXTS}\\{ext}\\UserChoice")


def demo_system() -> FakeSystem:
    s = FakeSystem()

    # installed: a bundled vendor app that is still installed (so every category has a finding)
    s.add_key(UNINSTALL + r"\2345Pic", {
        "DisplayName": "2345看图王", "Publisher": "2345", "DisplayVersion": "11.2.0",
        "InstallLocation": VIEWER_DIR,
        "UninstallString": f'"{VIEWER_DIR}\\Uninstall.exe"',
    })

    # file_assoc: .jpg (UserChoice access-denied), .png and .pdf hijacked by WPS
    _hijack(s, ".jpg", "WPS.PIC.jpg", denied=True)
    _hijack(s, ".png", "WPS.PIC.png")
    _hijack(s, ".pdf", "WPS.PDF.12")
    s.add_key(FILEEXTS + r"\.gif\UserChoice", {"ProgId": "PhotoViewer.FileAssoc.Gif"})
    s.add_key(r"HKCR\PhotoViewer.FileAssoc.Gif\shell\open\command",
              {"": r"%SystemRoot%\System32\rundll32.exe photoviewer.dll,ImageView_Fullscreen %1"})

    # autoruns: Run value, auto-start service, scheduled task (all unsigned leftovers of WPS)
    s.add_key(RUN, {"WPSCloud": f'"{WPS_DIR}\\wpscloudsvr.exe" /tray'})
    s.set_signature(WPS_DIR + r"\wpscloudsvr.exe", SignatureInfo("unsigned", ""))
    s.set_signature(WPS_DIR + r"\ksolaunch.exe", SignatureInfo("valid", KINGSOFT_PUBLISHER))
    s.add_service(ServiceInfo("wpscloudsvr", "WPS Cloud Service",
                              f'"{WPS_DIR}\\wpscloudsvr.exe" -service', "auto", "running"))
    s.add_task(TaskInfo(r"\WPS\WpsUpdateTask", f'"{WPS_DIR}\\wpsupdate.exe" -silent', True, "Kingsoft"))

    # leftovers: folders (Roaming and Local) and a registry key of the removed WPS
    s.add_file(KINGSOFT_COMMON + r"\WPS Office\cfg.ini", size=2048)
    s.add_file(KINGSOFT_COMMON + r"\WPS Office\cache\thumb.db", size=409600)
    s.add_key(r"HKCU\Software\Kingsoft\Office", {"Version": "12.1.0"})

    # hidden: a hidden unsigned executable in ProgramData
    s.add_file(r"C:\ProgramData\SysCache\svchost32.exe", size=183296, hidden=True)
    s.set_signature(r"C:\ProgramData\SysCache\svchost32.exe", SignatureInfo("unsigned", ""))

    # browser: Edge shortcut that forces a 2345 start page, plus a tampered homepage
    s.add_shortcut(USER + r"\Desktop\Microsoft Edge.lnk", ShortcutInfo(EDGE, "https://www.2345.com"))
    s.add_file(USER + r"\AppData\Local\Microsoft\Edge\User Data\Default\Preferences",
               content=json.dumps({"homepage": "https://www.2345.com/?31208"}))
    return s
