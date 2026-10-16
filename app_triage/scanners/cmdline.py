"""Command-line helpers: find the real binary behind a startup/service command, signer checks."""
from __future__ import annotations

import ntpath
import re
from collections.abc import Callable

from ..sysapi.base import SignatureInfo

_BINARY_EXTS = (".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".com", ".scr")
_DLL_HOSTS = frozenset(("rundll32", "rundll32.exe", "regsvr32", "regsvr32.exe"))
_TOKEN = re.compile(r'"[^"]*"|\S+')


def is_microsoft(sig: SignatureInfo) -> bool:
    return sig.status == "valid" and "Microsoft" in sig.publisher


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
