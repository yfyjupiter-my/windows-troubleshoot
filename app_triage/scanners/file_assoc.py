"""File-association scanner: finds default-app associations taken over by bundled software."""
from __future__ import annotations

from ..models import ActionSpec, Finding, Risk, make_finding_id
from ..rules import match_vendor
from ..sysapi.base import AccessDenied, SystemAPI
from .base import Problems, register

WATCHED_EXTS = (
    ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp", ".heic", ".ico",
    ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)
# WPS owning these may be the user's deliberate choice of office suite.
OFFICE_EXTS = frozenset((".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"))

FILEEXTS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _default_value(sys: SystemAPI, key: str) -> str:
    """Default value of a registry key; "" when missing, denied or not a string."""
    try:
        return _text(sys.reg_values(key).get(""))
    except (KeyError, AccessDenied):
        return ""


def _user_choice(sys: SystemAPI, ext: str) -> tuple[str, bool, bool]:
    """The effective ProgId for ext, whether UserChoice was access-denied (WPS locks it), and
    whether the ProgId came only from the HKCR\\<ext> fallback (no readable UserChoice)."""
    denied = False
    try:
        progid = _text(sys.reg_values(f"{FILEEXTS}\\{ext}\\UserChoice").get("ProgId"))
    except KeyError:
        progid = ""
    except AccessDenied:
        progid, denied = "", True
    if progid:
        return progid, denied, False
    return _default_value(sys, rf"HKCR\{ext}"), denied, True


def _open_with(sys: SystemAPI, ext: str) -> list[str]:
    try:
        return list(sys.reg_values(f"{FILEEXTS}\\{ext}\\OpenWithProgids"))
    except (KeyError, AccessDenied):
        return []


@register("file_assoc", "文件默认打开方式")
def scan_file_assoc(sys: SystemAPI) -> list[Finding]:
    problems = Problems()
    findings: list[Finding] = []
    for ext in WATCHED_EXTS:
        with problems.guard(f"文件类型 {ext}"):
            f = _ext_finding(sys, ext)
            if f is not None:
                findings.append(f)
    return problems.result(findings)


def _ext_finding(sys: SystemAPI, ext: str) -> Finding | None:
    if not sys.reg_exists(f"{FILEEXTS}\\{ext}"):
        return None
    progid, denied, fallback = _user_choice(sys, ext)
    if not progid:
        return None
    command = _default_value(sys, rf"HKCR\{progid}\shell\open\command")
    rule = match_vendor(progid, command)
    if rule is None:
        return None
    vendor_progids = [n for n in _open_with(sys, ext) if match_vendor(n)]
    openwith = ";".join(vendor_progids)
    evidence = {"ext": ext, "progid": progid, "command": command, "openwith": openwith}
    if denied:
        evidence["acl"] = "denied"
    is_wps = rule.name.startswith("WPS")
    if fallback and not denied:
        # No UserChoice (e.g. just reset): Windows asks the user next time; HKCR is only the
        # leftover default until then, so this is not (yet) a hijack.
        title, risk = f"{ext} 等待在“默认应用”中选择新的打开方式（当前仍为 {rule.name}）", Risk.INFO
    else:
        title = f"{ext} 的默认打开方式被 {rule.name} 占用"
        risk = Risk.INFO if is_wps and ext in OFFICE_EXTS else Risk.MEDIUM
    return Finding(
        id=make_finding_id("file_assoc", ext),
        category="file_assoc",
        title=title,
        evidence=evidence,
        risk=risk,
        actions=[ActionSpec("reset_file_assoc", ext,
                            (("progid", progid), ("openwith", openwith)))],
        vendor=rule.name,
    )
