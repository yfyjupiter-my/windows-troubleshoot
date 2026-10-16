"""Leftovers scanner: folders and registry keys left behind after an uninstall."""
from __future__ import annotations

import ntpath

from ..models import ActionSpec, Finding, Risk, make_finding_id
from ..rules import match_vendor
from ..sysapi.base import DirEntry, SystemAPI
from .base import Problems, register
from .installed import InstalledApp, list_installed

FOLDER_ROOTS = ("ProgramFiles", "ProgramFilesX86", "ProgramData", "AppData", "LocalAppData")
PROGRAM_FILES_ROOTS = ("ProgramFiles", "ProgramFilesX86")
REGISTRY_ROOTS = (r"HKCU\Software", r"HKLM\SOFTWARE", r"HKLM\SOFTWARE\WOW6432Node")

SKIP_DIRS = frozenset(n.lower() for n in (
    "Common Files", "Microsoft", "Microsoft.NET", "Windows Defender", "Windows Mail",
    "Windows Media Player", "Windows NT", "Windows Photo Viewer", "WindowsApps",
    "WindowsPowerShell", "Internet Explorer", "ModifiableWindowsApps", "Packages", "Temp",
    "Microsoft Office", "Uninstall Information",
))
MIN_TOKEN_LEN = 4


def _skipped(name: str) -> bool:
    low = name.lower()
    return low in SKIP_DIRS or low.startswith(("microsoft", "windows"))


def _tokens(text: str) -> set[str]:
    """Lowercase alphanumeric runs (Chinese characters count) of at least 4 characters."""
    out: set[str] = set()
    cur: list[str] = []
    for ch in text.lower() + " ":
        if ch.isalnum():
            cur.append(ch)
            continue
        if len(cur) >= MIN_TOKEN_LEN:
            out.add("".join(cur))
        cur = []
    return out


def _norm(path: str) -> str:
    return ntpath.normpath(ntpath.normcase(path.strip().strip('"')))


def _within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("\\") + "\\")


class _Owners:
    """Decides whether a folder or registry key still belongs to an installed program."""

    def __init__(self, apps: list[InstalledApp], scan_roots: list[str]) -> None:
        roots = [_norm(r) for r in scan_roots]
        self._locations: list[str] = []
        for app in apps:
            if not app.install_location:
                continue
            loc = _norm(app.install_location)
            # a drive root or scan root as InstallLocation would make everything "owned"
            if ntpath.splitdrive(loc)[1] in ("", "\\", ".") or any(_within(r, loc) for r in roots):
                continue
            self._locations.append(loc)
        self._app_tokens = [_tokens(a.name) | _tokens(a.publisher) for a in apps]

    def folder_owned(self, path: str, name: str) -> bool:
        p = _norm(path)
        if any(_within(loc, p) or _within(p, loc) for loc in self._locations):
            return True
        return self.name_owned(name)

    def name_owned(self, name: str) -> bool:
        toks = _tokens(name)
        return any(toks & app for app in self._app_tokens)


def _folder_size(sys: SystemAPI, path: str, problems: Problems) -> int:
    total = 0
    stack = [path]
    while stack:
        folder = stack.pop()
        entries: list[DirEntry] = []
        with problems.guard(f"文件夹 {folder}"):  # count what is readable
            entries = sys.list_dir(folder)
        for e in entries:
            if e.is_dir:
                stack.append(e.path)
            else:
                total += e.size
    return total


def _subdirs(sys: SystemAPI, path: str, problems: Problems) -> list[DirEntry]:
    entries: list[DirEntry] = []
    with problems.guard(f"文件夹 {path}"):
        entries = sys.list_dir(path)
    return [e for e in entries if e.is_dir and not _skipped(e.name)]


@register("leftovers", "卸载残留")
def scan_leftovers(sys: SystemAPI) -> list[Finding]:
    folders = sys.known_folders()
    roots = [(k, folders[k]) for k in FOLDER_ROOTS if folders.get(k)]
    problems = Problems()
    owners = _Owners(list_installed(sys, problems), [p for _, p in roots])
    findings: list[Finding] = []
    seen: set[str] = set()

    def report(entry: DirEntry, under_program_files: bool) -> None:
        if owners.folder_owned(entry.path, entry.name) or _norm(entry.path) in seen:
            return
        rule = match_vendor(entry.path)
        if rule is not None:
            risk = Risk.MEDIUM
        elif under_program_files:
            risk = Risk.LOW
        else:
            return
        seen.add(_norm(entry.path))
        findings.append(Finding(
            id=make_finding_id("leftovers", entry.path),
            category="leftovers",
            title=f"残留文件夹：{entry.name}",
            evidence={"path": entry.path, "size": str(_folder_size(sys, entry.path, problems))},
            risk=risk,
            actions=[ActionSpec("quarantine_path", entry.path)],
            vendor=rule.name if rule else None,
        ))

    for key, root in roots:
        in_pf = key in PROGRAM_FILES_ROOTS
        for top in _subdirs(sys, root, problems):
            with problems.guard(f"文件夹 {top.path}"):
                if not owners.folder_owned(top.path, top.name):
                    report(top, in_pf)
                elif match_vendor(top.path) is not None:
                    # an owned vendor folder (e.g. Kingsoft) may still hold orphaned children
                    for child in _subdirs(sys, top.path, problems):
                        with problems.guard(f"文件夹 {child.path}"):
                            report(child, in_pf)

    for reg_root in REGISTRY_ROOTS:
        subkeys: list[str] = []
        with problems.guard(f"注册表 {reg_root}"):
            subkeys = sys.reg_subkeys(reg_root)
        for sub in subkeys:
            rule = match_vendor(sub)
            if rule is None or owners.name_owned(sub):
                continue
            key_path = f"{reg_root}\\{sub}"
            findings.append(Finding(
                id=make_finding_id("leftovers", key_path),
                category="leftovers",
                title=f"残留注册表项：{sub}",
                evidence={"key": key_path},
                risk=Risk.LOW,
                actions=[ActionSpec("delete_reg_key", key_path)],
                vendor=rule.name,
            ))
    return problems.result(findings)
