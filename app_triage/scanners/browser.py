"""Browser hijack scanner: shortcuts that force a start page, and hijacked Chrome/Edge settings."""
from __future__ import annotations

import json
import ntpath
import re

from ..models import ActionSpec, Finding, Risk, make_finding_id
from ..rules import match_vendor
from ..sysapi.base import DirEntry, ShortcutInfo, SystemAPI
from .base import Problems, register

SHORTCUT_FOLDERS = ("Desktop", "StartMenu", "CommonStartMenu")
TASKBAR_PINS = r"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"  # under AppData
BROWSER_EXES = frozenset(("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "360se.exe"))
PREFERENCES = (  # (browser, path under LocalAppData)
    ("Chrome", r"Google\Chrome\User Data\Default\Preferences"),
    ("Edge", r"Microsoft\Edge\User Data\Default\Preferences"),
)
HIJACK_URL = re.compile(r"hao123|2345|360", re.IGNORECASE)


# One argument: runs of non-space characters and "quoted segments" (which may hold spaces).
_ARG = re.compile(r'(\s*)((?:"[^"]*"|[^\s"]|")+)')


def _is_url_token(token: str) -> bool:
    return token.lstrip("\"'").lower().startswith(("http://", "https://"))


def _has_url(args: str) -> bool:
    return any(_is_url_token(m.group(2)) for m in _ARG.finditer(args))


def _strip_urls(args: str) -> str:
    """Remove http(s) URL arguments (optionally quoted), leaving all other text untouched."""
    return _ARG.sub(lambda m: "" if _is_url_token(m.group(2)) else m.group(0), args).strip()


def _shortcut_files(sys: SystemAPI, root: str, problems: Problems) -> list[str]:
    out: list[str] = []
    stack = [root]
    while stack:
        folder = stack.pop()
        entries: list[DirEntry] = []
        with problems.guard(f"文件夹 {folder}"):
            entries = sys.list_dir(folder)
        for e in entries:
            if e.is_dir:
                stack.append(e.path)
            elif e.name.lower().endswith(".lnk"):
                out.append(e.path)
    return out


def _scan_shortcuts(sys: SystemAPI, problems: Problems) -> list[Finding]:
    folders = sys.known_folders()
    roots = [folders[k] for k in SHORTCUT_FOLDERS if folders.get(k)]
    if folders.get("AppData"):
        roots.append(ntpath.join(folders["AppData"], TASKBAR_PINS))
    findings: list[Finding] = []
    seen: set[str] = set()
    for root in roots:
        for lnk in _shortcut_files(sys, root, problems):
            norm = ntpath.normcase(ntpath.normpath(lnk))
            if norm in seen:
                continue
            seen.add(norm)
            with problems.guard(f"快捷方式 {lnk}"):
                f = _shortcut_finding(lnk, sys.read_shortcut(lnk))
                if f is not None:
                    findings.append(f)
    return findings


def _shortcut_finding(lnk: str, link: ShortcutInfo) -> Finding | None:
    if ntpath.basename(link.target.strip().strip('"')).lower() not in BROWSER_EXES:
        return None
    if not _has_url(link.arguments):
        return None  # no bare URL argument to remove
    cleaned = _strip_urls(link.arguments)
    return Finding(
        id=make_finding_id("browser", lnk),
        category="browser",
        title=f"浏览器快捷方式被附加网址：{ntpath.basename(lnk)}",
        evidence={"path": lnk, "target": link.target, "arguments": link.arguments},
        risk=Risk.MEDIUM,
        actions=[ActionSpec("fix_shortcut_args", lnk, (("args", cleaned),))],
        vendor=(rule.name if (rule := match_vendor(link.arguments)) else None),
    )


def _preference_urls(data: object) -> list[tuple[str, str]]:
    """(setting, url) pairs from a parsed Preferences file."""
    if not isinstance(data, dict):
        return []
    out: list[tuple[str, str]] = []
    homepage = data.get("homepage")
    if isinstance(homepage, str) and homepage.strip():
        out.append(("homepage", homepage.strip()))
    session = data.get("session")
    urls = session.get("startup_urls") if isinstance(session, dict) else None
    if isinstance(urls, list):
        out.extend(("startup_urls", u.strip()) for u in urls if isinstance(u, str) and u.strip())
    return out


def _scan_preferences(sys: SystemAPI, problems: Problems) -> list[Finding]:
    local = sys.known_folders().get("LocalAppData")
    if not local:
        return []
    findings: list[Finding] = []
    for browser, rel in PREFERENCES:
        path = ntpath.join(local, rel)
        text: str | None = None
        with problems.guard(f"{browser} 设置文件 {path}"):  # missing/denied stay silent
            text = sys.read_text(path)
        if text is None:
            continue
        try:
            data = json.loads(text)
        except ValueError:
            continue  # malformed: nothing to report
        seen: set[str] = set()
        for setting, url in _preference_urls(data):
            rule = match_vendor(url)
            if (rule is None and not HIJACK_URL.search(url)) or url.lower() in seen:
                continue
            seen.add(url.lower())
            findings.append(Finding(
                id=make_finding_id("browser", f"{browser}|{url}"),
                category="browser",
                title=f"{browser} 主页/启动页疑似被篡改：{url}（请在浏览器设置中修改）",
                evidence={"browser": browser, "setting": setting, "url": url, "path": path},
                risk=Risk.INFO,
                actions=[],
                vendor=rule.name if rule else None,
            ))
    return findings


@register("browser", "浏览器劫持")
def scan_browser(sys: SystemAPI) -> list[Finding]:
    problems = Problems()
    findings: list[Finding] = []
    for part in (_scan_shortcuts, _scan_preferences):
        with problems.guard("浏览器劫持"):
            findings.extend(part(sys, problems))
    return problems.result(findings)
