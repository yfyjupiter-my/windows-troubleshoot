"""Browser hijack scanner: shortcuts that force a start page, and hijacked Chrome/Edge settings."""
from __future__ import annotations

import json
import ntpath
import re

from ..models import ActionSpec, Finding, Risk, make_finding_id
from ..rules import match_vendor
from ..sysapi.base import AccessDenied, SystemAPI
from .base import register

SHORTCUT_FOLDERS = ("Desktop", "StartMenu", "CommonStartMenu")
TASKBAR_PINS = r"Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"  # under AppData
BROWSER_EXES = frozenset(("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "360se.exe"))
PREFERENCES = (  # (browser, path under LocalAppData)
    ("Chrome", r"Google\Chrome\User Data\Default\Preferences"),
    ("Edge", r"Microsoft\Edge\User Data\Default\Preferences"),
)
HIJACK_URL = re.compile(r"hao123|2345|360", re.IGNORECASE)


def _strip_urls(args: str) -> str:
    """Drop whitespace-separated tokens that are http(s) URLs (optionally quoted)."""
    kept = [t for t in args.split()
            if not t.lstrip("\"'").lower().startswith(("http://", "https://"))]
    return " ".join(kept)


def _shortcut_files(sys: SystemAPI, root: str) -> list[str]:
    out: list[str] = []
    stack = [root]
    while stack:
        try:
            entries = sys.list_dir(stack.pop())
        except (KeyError, AccessDenied):
            continue
        for e in entries:
            if e.is_dir:
                stack.append(e.path)
            elif e.name.lower().endswith(".lnk"):
                out.append(e.path)
    return out


def _scan_shortcuts(sys: SystemAPI) -> list[Finding]:
    folders = sys.known_folders()
    roots = [folders[k] for k in SHORTCUT_FOLDERS if folders.get(k)]
    if folders.get("AppData"):
        roots.append(ntpath.join(folders["AppData"], TASKBAR_PINS))
    findings: list[Finding] = []
    seen: set[str] = set()
    for root in roots:
        for lnk in _shortcut_files(sys, root):
            norm = ntpath.normcase(ntpath.normpath(lnk))
            if norm in seen:
                continue
            seen.add(norm)
            try:
                link = sys.read_shortcut(lnk)
            except (KeyError, AccessDenied):
                continue
            if ntpath.basename(link.target.strip().strip('"')).lower() not in BROWSER_EXES:
                continue
            cleaned = _strip_urls(link.arguments)
            if cleaned == link.arguments.strip():
                continue  # no bare URL argument to remove
            findings.append(Finding(
                id=make_finding_id("browser", lnk),
                category="browser",
                title=f"浏览器快捷方式被附加网址：{ntpath.basename(lnk)}",
                evidence={"path": lnk, "target": link.target, "arguments": link.arguments},
                risk=Risk.MEDIUM,
                actions=[ActionSpec("fix_shortcut_args", lnk, (("args", cleaned),))],
                vendor=(rule.name if (rule := match_vendor(link.arguments)) else None),
            ))
    return findings


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


def _scan_preferences(sys: SystemAPI) -> list[Finding]:
    local = sys.known_folders().get("LocalAppData")
    if not local:
        return []
    findings: list[Finding] = []
    for browser, rel in PREFERENCES:
        path = ntpath.join(local, rel)
        try:
            data = json.loads(sys.read_text(path))
        except (KeyError, AccessDenied, ValueError):
            continue  # missing, unreadable or malformed
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
    return _scan_shortcuts(sys) + _scan_preferences(sys)
