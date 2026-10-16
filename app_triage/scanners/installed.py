"""Installed-programs scanner (registry Uninstall keys)."""
from __future__ import annotations

from dataclasses import dataclass

from ..models import ActionSpec, Finding, Risk, make_finding_id
from ..rules import match_vendor
from ..sysapi.base import SystemAPI
from .base import Problems, register

UNINSTALL_ROOTS = (
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
)


@dataclass
class InstalledApp:
    name: str
    publisher: str
    version: str
    install_location: str
    uninstall_string: str
    key_path: str


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _is_system_component(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return value == 1
    return isinstance(value, str) and value.strip() == "1"


def list_installed(sys: SystemAPI, problems: Problems | None = None) -> list[InstalledApp]:
    """Every readable Uninstall entry; unreadable ones are skipped (and noted in problems)."""
    problems = problems if problems is not None else Problems()
    apps: list[InstalledApp] = []
    for root in UNINSTALL_ROOTS:
        subkeys: list[str] = []
        with problems.guard(f"卸载信息 {root}"):
            subkeys = sys.reg_subkeys(root)
        for sub in subkeys:
            key_path = f"{root}\\{sub}"
            with problems.guard(f"卸载信息 {key_path}"):
                vals = sys.reg_values(key_path)
                name = _text(vals.get("DisplayName"))
                if not name or _is_system_component(vals.get("SystemComponent")):
                    continue
                apps.append(InstalledApp(
                    name=name,
                    publisher=_text(vals.get("Publisher")),
                    version=_text(vals.get("DisplayVersion")),
                    install_location=_text(vals.get("InstallLocation")),
                    uninstall_string=_text(vals.get("UninstallString")),
                    key_path=key_path,
                ))
    return apps


@register("installed", "已安装程序")
def scan_installed(sys: SystemAPI) -> list[Finding]:
    problems = Problems()
    findings: list[Finding] = []
    for app in list_installed(sys, problems):
        rule = match_vendor(app.name, app.publisher, app.install_location)
        if rule is None:
            continue
        findings.append(Finding(
            id=make_finding_id("installed", app.key_path),
            category="installed",
            title=f"已安装：{app.name}",
            evidence={
                "name": app.name, "publisher": app.publisher, "version": app.version,
                "install_location": app.install_location,
                "uninstall_string": app.uninstall_string,
            },
            risk=Risk.LOW,
            actions=[ActionSpec("run_uninstaller", app.key_path,
                                (("command", app.uninstall_string),))],
            vendor=rule.name,
        ))
    return problems.result(findings)
