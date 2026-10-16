"""Service, scheduled-task, file, shortcut and uninstaller fixes."""
from __future__ import annotations

import ntpath

from app_triage.models import ActionSpec
from app_triage.safety.journal import FixSession, JournalEntry
from app_triage.sysapi.base import SystemAPI

from .base import ActionError

_START_NAMES = {"auto": "自动", "manual": "手动", "disabled": "禁用", "boot": "引导", "system": "系统"}


class SetServiceStart:
    kind = "set_service_start"
    reversible = True

    def describe(self, spec: ActionSpec) -> str:
        start = spec.param("start")
        return f"修改服务 {spec.target} 的启动类型为「{_START_NAMES.get(start, start)}」"

    def apply(self, spec, sys, session, index):
        previous = spec.param("previous") or _current_start(sys, spec.target)
        sys.set_service_start(spec.target, spec.param("start"))
        return {"previous": previous}

    def undo(self, entry, sys, session):
        sys.set_service_start(entry.target, entry.backup["previous"])


def _current_start(sys: SystemAPI, name: str) -> str:
    for svc in sys.list_services():
        if svc.name.lower() == name.lower():
            return svc.start_type
    raise KeyError(name)


class DisableTask:
    kind = "disable_task"
    reversible = True

    def describe(self, spec: ActionSpec) -> str:
        return f"禁用计划任务：{spec.target}"

    def apply(self, spec, sys, session, index):
        task = next((t for t in sys.list_tasks() if t.path.lower() == spec.target.lower()), None)
        if task is None:
            raise KeyError(spec.target)
        sys.set_task_enabled(spec.target, False)
        return {"enabled": "1" if task.enabled else "0"}

    def undo(self, entry, sys, session):
        sys.set_task_enabled(entry.target, entry.backup["enabled"] == "1")


class QuarantinePath:
    kind = "quarantine_path"
    reversible = True

    def describe(self, spec: ActionSpec) -> str:
        return f"移到隔离区（可恢复）：{spec.target}"

    def apply(self, spec, sys, session, index):
        name = ntpath.basename(spec.target.rstrip("\\/")) or "item"
        dest = str(session.quarantine_dir() / f"{index}_{name}")
        sys.move(spec.target, dest)
        return {"original": spec.target, "moved_to": dest}

    def undo(self, entry, sys, session):
        if sys.path_exists(entry.backup["original"]):
            raise ActionError("原位置已存在同名文件，未覆盖")
        sys.move(entry.backup["moved_to"], entry.backup["original"])


class FixShortcutArgs:
    kind = "fix_shortcut_args"
    reversible = True

    def describe(self, spec: ActionSpec) -> str:
        return f"清除快捷方式中被添加的网址：{spec.target}"

    def apply(self, spec, sys, session, index):
        old = sys.read_shortcut(spec.target).arguments
        sys.set_shortcut_arguments(spec.target, spec.param("args"))
        return {"args": old}

    def undo(self, entry, sys, session):
        sys.set_shortcut_arguments(entry.target, entry.backup["args"])


class RunUninstaller:
    kind = "run_uninstaller"
    reversible = False

    def describe(self, spec: ActionSpec) -> str:
        return f"运行卸载程序：{spec.param('command') or spec.target}"

    def apply(self, spec, sys, session, index):
        command = spec.param("command").strip()
        if not command:
            raise ActionError("没有找到卸载程序")
        sys.launch(command)
        return {"command": command}

    def undo(self, entry: JournalEntry, sys: SystemAPI, session: FixSession) -> None:
        """Uninstalling cannot be undone; the executor records IRREVERSIBLE_MESSAGE instead."""

