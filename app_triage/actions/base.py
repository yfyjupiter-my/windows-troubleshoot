"""Action protocol shared by every fix kind, plus user-facing error text."""
from __future__ import annotations

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


def error_message(exc: BaseException) -> str:
    """Chinese text for an exception raised while applying or undoing an action."""
    if isinstance(exc, ActionError):
        return str(exc)
    if isinstance(exc, AccessDenied):
        return f"拒绝访问：{exc}"
    if isinstance(exc, KeyError):
        return f"未找到：{exc.args[0] if exc.args else ''}"
    if isinstance(exc, FileExistsError):
        return f"目标已存在：{exc}"
    return f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
