"""Action protocol shared by every fix kind, plus user-facing error text."""
from __future__ import annotations

import ntpath
from typing import Protocol

from app_triage.models import ActionSpec
from app_triage.safety.journal import FixSession, JournalEntry
from app_triage.sysapi.base import AccessDenied, SystemAPI

IRREVERSIBLE_MESSAGE = "卸载操作无法撤销"


class ActionError(Exception):
    """An action refused or failed; ``str(exc)`` is a Chinese message for the user."""


class Action(Protocol):
    kind: str
    reversible: bool

    def describe(self, spec: ActionSpec) -> str:
        """Chinese one-liner for the confirmation list."""
        ...

    def apply(self, spec: ActionSpec, sys: SystemAPI, session: FixSession,
              index: int) -> dict[str, str]:
        """Back up, then change the system. ``index`` names backup files; returns backup info."""
        ...

    def undo(self, entry: JournalEntry, sys: SystemAPI, session: FixSession) -> None:
        """Restore the state saved in ``entry.backup``; raise on failure."""
        ...


def resolve_fs_path(sys: SystemAPI, path: str) -> str:
    """Expanded, device-prefix-free, normalized path: the one string both checked and acted on."""
    p = sys.expand_env(path).replace("/", "\\")
    if p[:8].lower() == "\\\\?\\unc\\":
        p = "\\\\" + p[8:]
    else:
        for prefix in ("\\\\?\\", "\\\\.\\", "\\??\\"):
            if p.startswith(prefix):
                p = p[len(prefix):]
                break
    return ntpath.normpath(p)


def error_message(exc: BaseException, target: str) -> str:
    """Chinese text for an exception raised while applying or undoing an action on ``target``."""
    if isinstance(exc, ActionError):
        return str(exc)
    if isinstance(exc, (KeyError, FileNotFoundError)):
        return f"未找到：{target}"
    if isinstance(exc, (AccessDenied, PermissionError)):
        return f"权限不足：{target}"
    if isinstance(exc, FileExistsError):
        return f"目标已存在：{exc.filename or exc}"
    return f"操作失败：{exc}" if str(exc) else f"操作失败：{type(exc).__name__}"
