"""Command-line helpers: find the real binary behind a startup/service command, signer checks."""
from __future__ import annotations

import ntpath
import re
from collections.abc import Callable

from ..sysapi.base import AccessDenied, DirEntry, SignatureInfo, SystemAPI

_BINARY_EXTS = (".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".com", ".scr")
_DLL_HOSTS = frozenset(("rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe"))
_TOKEN = re.compile(r'"[^"]*"|\S+')


def is_microsoft(sig: SignatureInfo) -> bool:
    return sig.status == "valid" and "Microsoft" in sig.publisher


# Microsoft-signed files that third-party programs ship next to their own (VC++/UCRT runtimes,
# .NET/NuGet assemblies, WebView2 loader...). Finding one says nothing about who owns the folder.
_REDISTRIBUTABLE_PREFIXES = (
    "vcruntime", "msvcp", "msvcr", "msvcm", "ucrtbase", "api-ms-win-", "concrt", "vccorlib", "vcomp",
    "mfc", "atl", "d3dcompiler", "d3dx", "xinput", "xaudio", "dbghelp", "dbgcore", "gdiplus", "msxml",
    "msdia", "webview2loader", "microsoft.", "system.", "vc_redist", "vcredist",
)


def _is_redistributable(name: str) -> bool:
    return name.lower().startswith(_REDISTRIBUTABLE_PREFIXES)


def contains_microsoft_binary(sys: SystemAPI, folder: str, max_depth: int, max_checks: int,
                              strict: bool) -> bool:
    """Whether folder holds a Microsoft-signed .exe/.dll (redistributables aside).

    Breadth-first, at most ``max_depth`` levels (1 = the folder's own files) and ``max_checks``
    signature checks. ``folder`` not being a directory (KeyError) -> False. ``strict``: any
    other listing failure is raised, so the caller can fail closed; otherwise unreadable
    folders are skipped.
    """
    try:
        level = [sys.list_dir(folder)]
    except KeyError:
        return False  # a file (or nothing): no directory to look into
    except AccessDenied:
        if strict:
            raise
        return False
    checks = 0
    for depth in range(1, max_depth + 1):
        subdirs: list[str] = []
        for entries in level:
            for e in entries:
                if e.is_dir:
                    subdirs.append(e.path)
                elif e.name.lower().endswith((".exe", ".dll")) and not _is_redistributable(e.name):
                    if checks >= max_checks:
                        return False
                    checks += 1
                    if is_microsoft(sys.get_signature(e.path)):
                        return True
        if depth == max_depth:
            break
        level = [_listing(sys, d, strict) for d in subdirs]
    return False


def _listing(sys: SystemAPI, path: str, strict: bool) -> list[DirEntry]:
    try:
        return sys.list_dir(path)
    except (KeyError, AccessDenied):
        if strict:
            raise
        return []


def _has_binary_ext(path: str) -> bool:
    return path.lower().endswith(_BINARY_EXTS)


def _strip_entry(path: str) -> str:
    """`x.dll,Entry` -> `x.dll`; the part after the last comma is only an entry point."""
    head, sep, tail = path.rpartition(",")
    return head if sep and "\\" not in tail and "/" not in tail else path


def _grow(tokens: list[str], exists: Callable[[str], bool], clean: Callable[[str], str]) -> str:
    """Join tokens one at a time; first prefix with a binary extension that exists, else the
    first prefix with a binary extension (the file may be gone), else ""."""
    first_plain = ""
    for i in range(1, len(tokens) + 1):
        candidate = clean(" ".join(tokens[:i]))
        if not _has_binary_ext(candidate):
            continue
        if exists(candidate):
            return candidate
        first_plain = first_plain or candidate
    return first_plain


def _dll_argument(args: list[str], exists: Callable[[str], bool]) -> str:
    args = [a for a in args if not a.startswith(("/", "-"))]
    if args and args[0].startswith('"') and args[0].endswith('"') and len(args[0]) > 1:
        # quoted path, possibly followed by ",Entry" glued on after the closing quote
        return _strip_entry(args[0].strip('"'))
    if args and args[0].startswith('"'):
        args[0] = args[0].lstrip('"')
    return _grow(args, exists, lambda p: _strip_entry(p.strip('"')))


def extract_exe_path(command: str, expand: Callable[[str], str] = lambda s: s,
                     exists: Callable[[str], bool] = lambda p: True) -> str:
    """Return the binary path behind a command line, or "" when none can be found."""
    cmd = expand(command or "").strip()
    if not cmd:
        return ""
    tokens = _TOKEN.findall(cmd)
    first = tokens[0]
    host = ntpath.basename(first.strip('"')).lower()
    if host in _DLL_HOSTS:
        return _dll_argument(tokens[1:], exists)
    if first.startswith('"') and first.endswith('"') and len(first) > 1:
        return first.strip('"')
    tokens[0] = first.lstrip('"')
    return _grow(tokens, exists, lambda p: p)
