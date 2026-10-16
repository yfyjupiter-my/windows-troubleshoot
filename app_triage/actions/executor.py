"""Run confirmed fixes with backups and a journal; undo a recorded session."""
from __future__ import annotations

import ntpath
from collections.abc import Callable
from dataclasses import dataclass, replace

from app_triage.models import ActionSpec
from app_triage.safety.journal import FixSession, Journal, JournalEntry
from app_triage.scanners.cmdline import is_microsoft
from app_triage.sysapi.base import SystemAPI

from .base import IRREVERSIBLE_MESSAGE, Action, error_message, resolve_fs_path
from .registry_actions import DeleteRegKey, DeleteRegValue, ResetFileAssoc, SetRegValue
from .system_actions import (
    DisableTask, FixShortcutArgs, QuarantinePath, RunUninstaller, SetServiceStart,
)

RESTORE_POINT_DESCRIPTION = "AppTriage 修复前"

ACTIONS: dict[str, Action] = {a.kind: a for a in (
    DeleteRegValue(), DeleteRegKey(), SetRegValue(), ResetFileAssoc(), SetServiceStart(),
    DisableTask(), QuarantinePath(), FixShortcutArgs(), RunUninstaller(),
)}


@dataclass
class ExecResult:
    session_id: str
    entries: list[JournalEntry]
    restore_point: bool
    needs_default_apps: bool


def _fold(path: str) -> str:
    return ntpath.normcase(path).rstrip("\\")


def _resolved(spec: ActionSpec, sys: SystemAPI) -> ActionSpec:
    """Quarantine targets are resolved once, so the protection check and the move see one path."""
    if spec.kind != "quarantine_path":
        return spec
    return replace(spec, target=resolve_fs_path(sys, spec.target))


def is_protected(spec: ActionSpec, sys: SystemAPI) -> bool:
    """Quarantining anything under SystemRoot, or a Microsoft-signed file, is never allowed."""
    if spec.kind != "quarantine_path":
        return False
    path = resolve_fs_path(sys, spec.target)
    root = resolve_fs_path(sys, sys.known_folders().get("SystemRoot", r"C:\Windows"))
    target, root = _fold(path), _fold(root)
    if target == root or target.startswith(root + "\\"):
        return True
    return is_microsoft(sys.get_signature(path))


def _try_restore_point(sys: SystemAPI) -> bool:
    try:
        return bool(sys.create_restore_point(RESTORE_POINT_DESCRIPTION))
    except Exception:
        return False


def execute(specs: list[ActionSpec], sys: SystemAPI, journal: Journal,
            confirm_high_risk: Callable[[ActionSpec], bool], label: str = "修复") -> ExecResult:
    session = journal.begin(label)
    restore_point = _try_restore_point(sys) if specs else False
    for index, spec in enumerate(specs):
        session.record(_run_one(index, spec, sys, session, confirm_high_risk))
    return ExecResult(
        session_id=session.id,
        entries=list(session.entries),
        restore_point=restore_point,
        needs_default_apps=any(e.status == "applied" and e.backup.get("needs_default_apps") == "1"
                               for e in session.entries),
    )


def _run_one(index: int, spec: ActionSpec, sys: SystemAPI, session: FixSession,
             confirm_high_risk: Callable[[ActionSpec], bool]) -> JournalEntry:
    """Decide and apply one spec; never raises, always returns its journal entry."""
    entry = JournalEntry(index, spec.kind, spec.target, dict(spec.params), "failed", {})
    action = ACTIONS.get(spec.kind)
    if action is None:
        entry.message = f"未知的修复类型：{spec.kind}"
        return entry
    try:
        spec = _resolved(spec, sys)
        protected = is_protected(spec, sys)
    except Exception as exc:  # fail closed: an unverifiable target is never touched
        entry.message = f"无法确认是否为受保护的系统文件，已拒绝（{error_message(exc, spec.target)}）"
        return entry
    if protected:
        entry.message = "受保护的系统文件，已拒绝"
        return entry
    if spec.high_risk:
        try:
            confirmed = confirm_high_risk(spec)
        except Exception:
            confirmed = False
        if not confirmed:
            entry.message = "用户取消"
            return entry
    try:
        entry.backup = action.apply(spec, sys, session, index)
        entry.status = "applied"
    except Exception as exc:
        entry.message = error_message(exc, spec.target)
    return entry


def undo_session(session_id: str, sys: SystemAPI, journal: Journal) -> list[JournalEntry]:
    """Undo the applied entries newest first; returns them with their new status."""
    session = journal.load(session_id)
    results: list[JournalEntry] = []
    for entry in reversed([e for e in session.entries if e.status == "applied"]):
        action = ACTIONS.get(entry.kind)
        if action is None:
            done = replace(entry, status="undo_failed", message=f"未知的修复类型：{entry.kind}")
        elif not action.reversible:
            done = replace(entry, status="undo_failed", message=IRREVERSIBLE_MESSAGE)
        else:
            try:
                action.undo(entry, sys, session)
                done = replace(entry, status="undone", message="")
            except Exception as exc:
                done = replace(entry, status="undo_failed", message=error_message(exc, entry.target))
        session.update(done)
        results.append(done)
    return results
