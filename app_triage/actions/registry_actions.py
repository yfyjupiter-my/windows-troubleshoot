"""Registry fixes: every change is preceded by a ``reg_export`` of the key it touches."""
from __future__ import annotations

from app_triage.models import ActionSpec
from app_triage.safety.journal import FixSession, JournalEntry
from app_triage.sysapi.base import AccessDenied, SystemAPI

FILEEXTS = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"


def _export(sys: SystemAPI, key: str, session: FixSession, index: int) -> str:
    dest = str(session.backup_path(f"{index}.reg"))
    sys.reg_export(key, dest)
    return dest


def _has_value(sys: SystemAPI, key: str, name: str) -> bool:
    return any(n.lower() == name.lower() for n in sys.reg_values(key))


class _RegistryAction:
    reversible = True

    def undo(self, entry: JournalEntry, sys: SystemAPI, session: FixSession) -> None:
        sys.reg_import(entry.backup["reg_file"])


class DeleteRegValue(_RegistryAction):
    kind = "delete_reg_value"

    def describe(self, spec: ActionSpec) -> str:
        return f"删除注册表值：{spec.target} → {spec.param('name')}"

    def apply(self, spec, sys, session, index):
        backup = {"reg_file": _export(sys, spec.target, session, index)}
        sys.reg_delete_value(spec.target, spec.param("name"))
        return backup


class DeleteRegKey(_RegistryAction):
    kind = "delete_reg_key"

    def describe(self, spec: ActionSpec) -> str:
        return f"删除注册表项：{spec.target}"

    def apply(self, spec, sys, session, index):
        backup = {"reg_file": _export(sys, spec.target, session, index)}
        sys.reg_delete_key(spec.target)
        return backup


class SetRegValue(_RegistryAction):
    kind = "set_reg_value"

    def describe(self, spec: ActionSpec) -> str:
        return f"恢复注册表值：{spec.target} → {spec.param('name')} = {spec.param('value')}"

    def apply(self, spec, sys, session, index):
        name = spec.param("name")
        backup = {"reg_file": _export(sys, spec.target, session, index),
                  "had_value": "1" if _has_value(sys, spec.target, name) else "0"}
        sys.reg_set_value(spec.target, name, spec.param("value"))
        return backup

    def undo(self, entry, sys, session):
        super().undo(entry, sys, session)
        # an import only merges, so a value that did not exist before must be removed explicitly
        name = entry.params.get("name", "")
        if entry.backup.get("had_value") == "0" and _has_value(sys, entry.target, name):
            sys.reg_delete_value(entry.target, name)


class ResetFileAssoc(_RegistryAction):
    kind = "reset_file_assoc"

    def describe(self, spec: ActionSpec) -> str:
        return f"重置 {spec.target} 的默认打开方式（移除 {spec.param('progid') or '第三方程序'} 的关联）"

    def apply(self, spec, sys, session, index):
        key = f"{FILEEXTS}\\{spec.target}"
        user_choice = key + r"\UserChoice"
        try:
            reg_file = _export(sys, key, session, index)
        except AccessDenied:
            sys.reg_take_ownership(user_choice)
            reg_file = _export(sys, key, session, index)
        backup = {"reg_file": reg_file, "needs_default_apps": "1"}
        try:
            self._remove(sys, key, user_choice, spec.param("openwith"))
        except BaseException:
            sys.reg_import(reg_file)  # leave the system as it was; the entry will be "failed"
            raise
        return backup

    @staticmethod
    def _remove(sys: SystemAPI, key: str, user_choice: str, openwith: str) -> None:
        if sys.reg_exists(user_choice):
            try:
                sys.reg_delete_key(user_choice)
            except AccessDenied:
                sys.reg_take_ownership(user_choice)
                sys.reg_delete_key(user_choice)
        progids = key + r"\OpenWithProgids"
        if not sys.reg_exists(progids):
            return
        for name in (n.strip() for n in openwith.split(";")):
            if name and _has_value(sys, progids, name):
                sys.reg_delete_value(progids, name)
