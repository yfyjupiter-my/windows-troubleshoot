"""Pure helpers for the Windows backend: parse PowerShell JSON, normalize paths, quote arguments.

Everything here is plain string work, so it is tested on Linux; ``windows.py`` only wires it to the OS.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping

from .base import ServiceInfo, SignatureInfo, TaskInfo

HIVES = {"HKLM": "HKEY_LOCAL_MACHINE", "HKCU": "HKEY_CURRENT_USER", "HKCR": "HKEY_CLASSES_ROOT"}
_HIVE_ALIASES = {**{k: k for k in HIVES}, **{v: k for k, v in HIVES.items()}}

# Windows PowerShell 5.1 ConvertTo-Json writes enums as their numeric value.
_TASK_STATES = {0: "Unknown", 1: "Disabled", 2: "Queued", 3: "Ready", 4: "Running"}
_SIG_STATES = {0: "Valid", 1: "UnknownError", 2: "NotSigned", 3: "HashMismatch", 4: "NotTrusted",
               5: "NotSupportedFileFormat", 6: "Incompatible"}
_SIG_MAP = {"Valid": "valid", "NotSigned": "unsigned", "HashMismatch": "invalid", "NotTrusted": "invalid"}
_CN = re.compile(r'(?:^|,)\s*CN=("(?:[^"]|"")*"|[^,]*)', re.IGNORECASE)
_DENIED = ("access is denied", "拒绝访问", "error accessing the registry", "访问注册表时出错")


def _load_objects(text: str) -> list[dict]:
    """ConvertTo-Json emits nothing for no input, an object for one, and a list for several."""
    text = text.lstrip("\ufeff").strip()
    if not text:
        return []
    data = json.loads(text)
    if data is None:
        return []
    return [d for d in (data if isinstance(data, list) else [data]) if isinstance(d, dict)]


def _s(obj: dict, key: str) -> str:
    value = obj.get(key)
    return "" if value is None else str(value)


def _enum(value: object, names: dict[int, str]) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return names.get(value, str(value))
    return "" if value is None else str(value)


def parse_tasks_json(text: str) -> list[TaskInfo]:
    tasks = []
    for o in _load_objects(text):
        state = _enum(o.get("State"), _TASK_STATES)
        tasks.append(TaskInfo(path=_s(o, "TaskPath") + _s(o, "TaskName"), command=_s(o, "Command"),
                              enabled=state.lower() != "disabled", author=_s(o, "Author")))
    return tasks


def parse_service_json(text: str) -> list[ServiceInfo]:
    services = []
    for o in _load_objects(text):
        services.append(ServiceInfo(name=_s(o, "Name"), display_name=_s(o, "DisplayName"),
                                    binary_path=_s(o, "PathName"),
                                    start_type=_s(o, "StartMode").lower(), status=_s(o, "State")))
    return services


def _common_name(subject: str) -> str:
    m = _CN.search(subject)
    if not m:
        return subject.strip()
    value = m.group(1).strip()
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        value = value[1:-1].replace('""', '"')
    return value


def parse_signature_json(text: str) -> SignatureInfo:
    objects = _load_objects(text)
    if not objects:
        return SignatureInfo("unknown", "")
    o = objects[0]
    status = _SIG_MAP.get(_enum(o.get("Status"), _SIG_STATES), "unknown")
    return SignatureInfo(status, _common_name(_s(o, "Publisher")))


def normalize_image_path(path: str) -> str:
    r"""Turn NT-style service image paths into ordinary ones (env vars left unexpanded).

    ``\??\C:\x`` -> ``C:\x``; ``\SystemRoot\...`` and bare ``system32\...`` -> ``%SystemRoot%\...``.
    """
    quote = '"' if path.startswith('"') else ""
    body = path[len(quote):].removeprefix("\\??\\")
    if body.lower().startswith("\\systemroot\\"):
        body = "%SystemRoot%\\" + body[len("\\systemroot\\"):]
    elif body.lower().startswith("system32\\"):
        body = "%SystemRoot%\\" + body
    return quote + body


def expand_env_vars(s: str, env: Mapping[str, str]) -> str:
    """Expand ``%NAME%`` case-insensitively; unknown names are left as written (like Windows)."""
    lower = {k.lower(): v for k, v in env.items()}
    return re.sub(r"%([^%]+)%", lambda m: lower.get(m.group(1).lower(), m.group(0)), s)


def ps_quote(s: str) -> str:
    """A PowerShell single-quoted literal; PowerShell also treats curly single quotes as quotes."""
    return "'" + re.sub("(['\u2018\u2019\u201a\u201b])", r"\1\1", s) + "'"


def split_reg_path(path: str) -> tuple[str, str]:
    r"""``HKEY_CURRENT_USER/Software/x`` -> ``("HKCU", "Software\x")``; unknown hive -> KeyError."""
    parts = [p for p in path.replace("/", "\\").split("\\") if p]
    hive = _HIVE_ALIASES.get(parts[0].upper()) if parts else None
    if hive is None:
        raise KeyError(path)
    return hive, "\\".join(parts[1:])


def split_task_path(path: str) -> tuple[str, str]:
    r"""``\Folder\Name`` -> ``("\Folder\", "Name")`` as Enable/Disable-ScheduledTask expect."""
    head, sep, name = path.rpartition("\\")
    return (head + sep) or "\\", name


def looks_access_denied(text: str) -> bool:
    """reg.exe reports failures only as (localized) text; exit code is always 1."""
    low = text.lower()
    return any(p in low for p in _DENIED)
