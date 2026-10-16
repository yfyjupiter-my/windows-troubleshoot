"""Autoruns scanner: Run keys, Startup folders, services, scheduled tasks, Winlogon, IFEO."""
from __future__ import annotations

import ntpath

from ..models import ActionSpec, Finding, Risk, make_finding_id
from ..rules import match_vendor
from ..sysapi.base import AccessDenied, SignatureInfo, SystemAPI
from .base import register
from .cmdline import extract_exe_path, is_microsoft

RUN_KEYS = (
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
)
STARTUP_FOLDERS = ("Startup", "CommonStartup")
WINLOGON = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
WINLOGON_DEFAULTS = (
    ("Shell", "explorer.exe"),
    ("Userinit", r"C:\Windows\system32\userinit.exe,"),
)


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _value(values: dict[str, object], name: str) -> object | None:
    """Case-insensitive registry value lookup; None when absent."""
    for n, v in values.items():
        if n.lower() == name.lower():
            return v
    return None


def _signature(sys: SystemAPI, exe: str) -> SignatureInfo:
    if not exe:
        return SignatureInfo("unknown", "")
    try:
        return sys.get_signature(exe)
    except (KeyError, AccessDenied):
        return SignatureInfo("unknown", "")


def _inspect(sys: SystemAPI, command: str, *names: str) -> tuple[dict[str, str], str | None, SignatureInfo]:
    """Evidence core (command/exe/publisher/signature), matched vendor name and signature."""
    exe = extract_exe_path(command, expand=sys.expand_env, exists=sys.path_exists)
    sig = _signature(sys, exe)
    rule = match_vendor(command, exe, *names)
    evidence = {"command": command, "exe": exe, "publisher": sig.publisher, "signature": sig.status}
    return evidence, rule.name if rule else None, sig


def _autorun_finding(sys: SystemAPI, source: str, unique_key: str, title: str, name: str,
                     command: str, actions: list[ActionSpec]) -> Finding | None:
    """Apply the shared risk rule; None when the entry is Microsoft-signed (not reported)."""
    evidence, vendor, sig = _inspect(sys, command, name)
    if vendor is not None:
        risk = Risk.MEDIUM
    elif is_microsoft(sig):
        return None
    elif sig.status == "valid":
        risk = Risk.INFO
    else:
        risk = Risk.LOW
    return Finding(
        id=make_finding_id("autoruns", f"{source}|{unique_key}"),
        category="autoruns",
        title=title,
        evidence={"source": source, "name": name, **evidence},
        risk=risk,
        actions=actions,
        vendor=vendor,
    )


def _scan_run_keys(sys: SystemAPI) -> list[Finding]:
    findings: list[Finding] = []
    for key in RUN_KEYS:
        try:
            values = sys.reg_values(key)
        except (KeyError, AccessDenied):
            continue
        for name, raw in values.items():
            command = _text(raw)
            if not name or not command:
                continue
            f = _autorun_finding(
                sys, "run", f"{key}\\{name}", f"开机自启动：{name}", name, command,
                [ActionSpec("delete_reg_value", key, (("name", name),))])
            if f:
                findings.append(f)
    return findings


def _scan_startup_folders(sys: SystemAPI) -> list[Finding]:
    findings: list[Finding] = []
    folders = sys.known_folders()
    for folder_key in STARTUP_FOLDERS:
        folder = folders.get(folder_key)
        if not folder:
            continue
        try:
            entries = sys.list_dir(folder)
        except (KeyError, AccessDenied):
            continue
        for entry in entries:
            if entry.is_dir or entry.name.lower() == "desktop.ini":
                continue
            command = f'"{entry.path}"' if " " in entry.path else entry.path
            if entry.name.lower().endswith(".lnk"):
                try:
                    link = sys.read_shortcut(entry.path)
                except (KeyError, AccessDenied):
                    link = None
                if link is not None and link.target:
                    target = f'"{link.target}"' if " " in link.target else link.target
                    command = f"{target} {link.arguments}".strip()
            f = _autorun_finding(
                sys, "startup", entry.path, f"启动文件夹：{entry.name}", entry.name, command,
                [ActionSpec("quarantine_path", entry.path)])
            if f:
                findings.append(f)
    return findings


def _under(path: str, root: str) -> bool:
    p = ntpath.normcase(ntpath.normpath(path))
    r = ntpath.normcase(ntpath.normpath(root)).rstrip("\\")
    return p.startswith(r + "\\")


def _scan_services(sys: SystemAPI) -> list[Finding]:
    try:
        services = sys.list_services()
    except (KeyError, AccessDenied):
        return []
    system_root = sys.known_folders().get("SystemRoot", r"C:\Windows")
    findings: list[Finding] = []
    for svc in services:
        if svc.start_type != "auto":
            continue
        exe = extract_exe_path(svc.binary_path, expand=sys.expand_env, exists=sys.path_exists)
        if exe and _under(exe, system_root):
            continue
        f = _autorun_finding(
            sys, "service", svc.name, f"后台服务：{svc.display_name or svc.name}", svc.name,
            svc.binary_path,
            [ActionSpec("set_service_start", svc.name,
                        (("start", "disabled"), ("previous", svc.start_type)), high_risk=True)])
        if f:
            f.evidence["display_name"] = svc.display_name
            findings.append(f)
    return findings


def _scan_tasks(sys: SystemAPI) -> list[Finding]:
    try:
        tasks = sys.list_tasks()
    except (KeyError, AccessDenied):
        return []
    findings: list[Finding] = []
    for task in tasks:
        # Disabled tasks are already inert; offering to "disable" them again is noise.
        if task.path.lower().startswith("\\microsoft\\") or not task.enabled:
            continue
        f = _autorun_finding(
            sys, "task", task.path, f"计划任务：{task.path}", task.path, task.command,
            [ActionSpec("disable_task", task.path)])
        if f:
            f.evidence["author"] = task.author
            findings.append(f)
    return findings


def _hijack_finding(sys: SystemAPI, source: str, unique_key: str, title: str, name: str,
                    command: str, actions: list[ActionSpec]) -> Finding:
    evidence, vendor, _ = _inspect(sys, command, name)
    return Finding(
        id=make_finding_id("autoruns", f"{source}|{unique_key}"),
        category="autoruns",
        title=title,
        evidence={"source": source, "name": name, **evidence},
        risk=Risk.HIGH,
        actions=actions,
        vendor=vendor,
    )


def _winlogon_matches_default(name: str, value: str) -> bool:
    got = value.strip().lower()
    if name == "Userinit":
        got = got.rstrip(",")
        return got == r"c:\windows\system32\userinit.exe"
    return got == "explorer.exe"


def _scan_winlogon(sys: SystemAPI) -> list[Finding]:
    try:
        values = sys.reg_values(WINLOGON)
    except (KeyError, AccessDenied):
        return []
    findings: list[Finding] = []
    for name, default in WINLOGON_DEFAULTS:
        raw = _value(values, name)
        if raw is None:
            continue
        current = raw if isinstance(raw, str) else str(raw)
        if _winlogon_matches_default(name, current):
            continue
        f = _hijack_finding(
            sys, "winlogon", name, f"登录项 {name} 被修改", name, current,
            [ActionSpec("set_reg_value", WINLOGON, (("name", name), ("value", default)),
                        high_risk=True)])
        f.evidence["location"] = WINLOGON
        f.evidence["expected"] = default
        findings.append(f)
    return findings


def _scan_ifeo(sys: SystemAPI) -> list[Finding]:
    try:
        subkeys = sys.reg_subkeys(IFEO)
    except (KeyError, AccessDenied):
        return []
    findings: list[Finding] = []
    for sub in subkeys:
        key = f"{IFEO}\\{sub}"
        try:
            debugger = _text(_value(sys.reg_values(key), "Debugger"))
        except (KeyError, AccessDenied):
            continue
        if not debugger:
            continue
        f = _hijack_finding(
            sys, "ifeo", key, f"映像劫持：{sub}", sub, debugger,
            [ActionSpec("delete_reg_value", key, (("name", "Debugger"),), high_risk=True)])
        f.evidence["location"] = key
        findings.append(f)
    return findings


@register("autoruns", "开机自启动与后台")
def scan_autoruns(sys: SystemAPI) -> list[Finding]:
    findings: list[Finding] = []
    for part in (_scan_run_keys, _scan_startup_folders, _scan_services, _scan_tasks,
                 _scan_winlogon, _scan_ifeo):
        findings.extend(part(sys))
    return findings
