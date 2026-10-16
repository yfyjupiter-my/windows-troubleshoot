"""Hidden-files scanner: hidden/system executables and scripts in user-writable locations."""
from __future__ import annotations

import ntpath

from ..models import ActionSpec, Finding, Risk, make_finding_id
from ..rules import match_vendor
from ..sysapi.base import AccessDenied, SignatureInfo, SystemAPI
from .base import register
from .cmdline import is_microsoft

# (known folder key, depth); depth 1 = the root's direct children
SCAN_ROOTS = (
    ("AppData", 3), ("LocalAppData", 3), ("ProgramData", 3), ("Temp", 3), ("UserProfile", 1),
)
EXECUTABLE_EXTS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".com")
UNTRUSTED_STATUSES = ("unsigned", "invalid")


def _signature(sys: SystemAPI, path: str) -> SignatureInfo:
    try:
        return sys.get_signature(path)
    except (KeyError, AccessDenied):
        return SignatureInfo("unknown", "")


def _walk(sys: SystemAPI, root: str, max_depth: int):
    """Yield file entries up to max_depth levels below root; unreadable directories are skipped."""
    stack = [(root, 1)]
    while stack:
        folder, depth = stack.pop()
        try:
            entries = sys.list_dir(folder)
        except (KeyError, AccessDenied):
            continue
        for e in entries:
            if e.is_dir:
                if depth < max_depth:
                    stack.append((e.path, depth + 1))
            else:
                yield e


@register("hidden", "隐藏的可执行文件")
def scan_hidden(sys: SystemAPI) -> list[Finding]:
    folders = sys.known_folders()
    findings: list[Finding] = []
    seen: set[str] = set()  # AppData & co. sit under UserProfile, so roots overlap
    for key, depth in SCAN_ROOTS:
        root = folders.get(key)
        if not root:
            continue
        for e in _walk(sys, root, depth):
            if not (e.hidden or e.system) or not e.name.lower().endswith(EXECUTABLE_EXTS):
                continue
            norm = ntpath.normcase(ntpath.normpath(e.path))
            if norm in seen:
                continue
            seen.add(norm)
            sig = _signature(sys, e.path)
            if is_microsoft(sig):
                continue
            rule = match_vendor(e.path)
            risk = Risk.MEDIUM if rule or sig.status in UNTRUSTED_STATUSES else Risk.LOW
            findings.append(Finding(
                id=make_finding_id("hidden", e.path),
                category="hidden",
                title=f"隐藏的可执行文件：{e.name}",
                evidence={"path": e.path, "size": str(e.size), "hidden": str(e.hidden),
                          "system": str(e.system), "publisher": sig.publisher,
                          "signature": sig.status},
                risk=risk,
                actions=[ActionSpec("quarantine_path", e.path)],
                vendor=rule.name if rule else None,
            ))
    return findings
