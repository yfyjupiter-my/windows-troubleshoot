"""In-memory SystemAPI with Windows semantics (case-insensitive registry/paths, backslashes)."""
from __future__ import annotations

import base64
import json
import ntpath
import re
from dataclasses import replace

from .base import (
    AccessDenied, DirEntry, ServiceInfo, ShortcutInfo, SignatureInfo, TaskInfo,
)


def _fs_key(path: str) -> str:
    return ntpath.normpath(ntpath.normcase(path))


def _reg_parts(path: str) -> list[str]:
    return [p for p in path.replace("/", "\\").split("\\") if p]


def _reg_key(path: str) -> str:
    return "\\".join(_reg_parts(path)).lower()


def _encode_value(value: object) -> object:
    """JSON form of a registry value; bytes become a tagged base64 object."""
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode("ascii")}
    return value


def _decode_value(value: object) -> object:
    if isinstance(value, dict) and set(value) == {"__bytes__"}:
        return base64.b64decode(value["__bytes__"])
    return value


def _within(key: str, root: str) -> bool:
    return key == root or key.startswith(root.rstrip("\\") + "\\")


class FakeSystem:
    def __init__(self) -> None:
        self._reg: dict[str, tuple[str, dict[str, object]]] = {}  # lower path -> (display, values)
        self._fs: dict[str, DirEntry] = {}
        self._content: dict[str, str] = {}
        self._denied: set[str] = set()  # registry and file paths share one deny list
        self._services: list[ServiceInfo] = []
        self._tasks: list[TaskInfo] = []
        self._signatures: dict[str, SignatureInfo] = {}
        self._shortcuts: dict[str, ShortcutInfo] = {}
        self.launched: list[str] = []
        self.opened_uris: list[str] = []
        self.restore_points: list[str] = []
        user = r"C:\Users\tester"
        start = user + r"\AppData\Roaming\Microsoft\Windows\Start Menu"
        common = r"C:\ProgramData\Microsoft\Windows\Start Menu"
        self._folders = {
            "ProgramFiles": r"C:\Program Files", "ProgramFilesX86": r"C:\Program Files (x86)",
            "ProgramData": r"C:\ProgramData", "AppData": user + r"\AppData\Roaming",
            "LocalAppData": user + r"\AppData\Local", "Temp": user + r"\AppData\Local\Temp",
            "UserProfile": user, "Desktop": user + r"\Desktop", "StartMenu": start,
            "CommonStartMenu": common, "Startup": start + r"\Programs\Startup",
            "CommonStartup": common + r"\Programs\Startup", "SystemRoot": r"C:\Windows",
        }

    # ---- access control -------------------------------------------------
    def deny(self, path: str) -> None:
        self._denied.add(self._norm(path))

    def reg_take_ownership(self, path: str) -> None:
        self._denied.discard(self._norm(path))

    @staticmethod
    def _norm(path: str) -> str:
        head = _reg_parts(path)[:1]
        return _reg_key(path) if head and head[0].upper() in ("HKLM", "HKCU", "HKCR") else _fs_key(path)

    def _check(self, path: str, subtree: bool = False) -> None:
        k = self._norm(path)
        for d in self._denied:
            if _within(k, d) or (subtree and _within(d, k)):
                raise AccessDenied(path)

    # ---- registry -------------------------------------------------------
    def add_key(self, path: str, values: dict | None = None) -> None:
        parts = _reg_parts(path)
        for i in range(1, len(parts) + 1):
            disp = "\\".join(parts[:i])
            self._reg.setdefault(disp.lower(), (disp, {}))
        if values:
            self._reg[_reg_key(path)][1].update(values)

    def _key(self, path: str) -> dict[str, object]:
        self._check(path)
        try:
            return self._reg[_reg_key(path)][1]
        except KeyError:
            raise KeyError(path) from None

    def reg_exists(self, path: str) -> bool:
        return _reg_key(path) in self._reg

    def reg_values(self, path: str) -> dict[str, object]:
        return dict(self._key(path))

    def reg_subkeys(self, path: str) -> list[str]:
        self._key(path)
        base = _reg_key(path)
        return sorted((d.rsplit("\\", 1)[-1] for k, (d, _) in self._reg.items()
                       if k.startswith(base + "\\") and "\\" not in k[len(base) + 1:]), key=str.lower)

    def reg_set_value(self, path: str, name: str, value: object) -> None:
        self._check(path)
        self.add_key(path)
        vals = self._reg[_reg_key(path)][1]
        existing = next((n for n in vals if n.lower() == name.lower()), name)
        vals[existing] = value

    def reg_delete_value(self, path: str, name: str) -> None:
        vals = self._key(path)
        for n in vals:
            if n.lower() == name.lower():
                del vals[n]
                return
        raise KeyError(name)

    def _subtree(self, path: str) -> list[str]:
        base = _reg_key(path)
        return [k for k in self._reg if _within(k, base)]

    def reg_delete_key(self, path: str) -> None:
        self._check(path, subtree=True)
        keys = self._subtree(path)
        if not keys:
            raise KeyError(path)
        for k in keys:
            del self._reg[k]

    def reg_export(self, path: str, dest_file: str) -> None:
        self._check(path, subtree=True)
        keys = self._subtree(path)
        if not keys:
            raise KeyError(path)
        snapshot = {"root": path, "keys": [
            [self._reg[k][0], {n: _encode_value(v) for n, v in self._reg[k][1].items()}]
            for k in sorted(keys)]}
        text = json.dumps(snapshot)  # serialize first: a failure must not leave a partial file
        with open(dest_file, "w", encoding="utf-8") as f:
            f.write(text)

    def reg_import(self, src_file: str) -> None:
        with open(src_file, encoding="utf-8") as f:
            snapshot = json.load(f)
        for disp, _ in snapshot["keys"]:
            self._check(disp)
        for disp, values in snapshot["keys"]:
            self.add_key(disp)
            self._reg[_reg_key(disp)] = (disp, {n: _decode_value(v) for n, v in values.items()})

    # ---- environment ----------------------------------------------------
    def known_folders(self) -> dict[str, str]:
        return dict(self._folders)

    def username(self) -> str:
        return "tester"

    def expand_env(self, s: str) -> str:
        env = {k.lower(): v for k, v in self._folders.items()}
        env["programfiles(x86)"] = self._folders["ProgramFilesX86"]
        env["windir"] = self._folders["SystemRoot"]
        return re.sub(r"%([^%]+)%", lambda m: env.get(m.group(1).lower(), m.group(0)), s)

    # ---- filesystem -----------------------------------------------------
    def _ensure_dir(self, path: str) -> None:
        disp = ntpath.normpath(path)
        while True:
            key = _fs_key(disp)
            if key not in self._fs:
                self._fs[key] = DirEntry(ntpath.basename(disp) or disp, disp, True, False, False, 0)
            parent = ntpath.dirname(disp)
            if parent == disp or not parent:
                return
            disp = parent

    def add_dir(self, path: str) -> None:
        self._ensure_dir(path)

    def add_file(self, path: str, size: int = 0, hidden: bool = False, system: bool = False,
                 content: str = "") -> None:
        disp = ntpath.normpath(path)
        self._ensure_dir(ntpath.dirname(disp))
        self._fs[_fs_key(disp)] = DirEntry(ntpath.basename(disp), disp, False, hidden, system, size)
        self._content[_fs_key(disp)] = content

    def path_exists(self, path: str) -> bool:
        return _fs_key(path) in self._fs

    def list_dir(self, path: str) -> list[DirEntry]:
        self._check(path)
        base = _fs_key(path)
        if base not in self._fs or not self._fs[base].is_dir:
            raise KeyError(path)
        return sorted((e for k, e in self._fs.items() if k != base and ntpath.dirname(k) == base),
                      key=lambda e: e.name.lower())

    def read_text(self, path: str) -> str:
        self._check(path)
        try:
            return self._content[_fs_key(path)]
        except KeyError:
            raise KeyError(path) from None

    def move(self, src: str, dst: str) -> None:
        self._check(src, subtree=True)
        sk, dk = _fs_key(src), _fs_key(dst)
        if sk not in self._fs:
            raise KeyError(src)
        if dk in self._fs:
            raise FileExistsError(dst)
        src_disp, dst_disp = ntpath.normpath(src), ntpath.normpath(dst)
        self._ensure_dir(ntpath.dirname(dst_disp))
        for k in [k for k in self._fs if _within(k, sk)]:
            entry = self._fs.pop(k)
            content = self._content.pop(k, None)
            new_path = dst_disp + entry.path[len(src_disp):]
            nk = _fs_key(new_path)
            for table in (self._shortcuts, self._signatures):
                if k in table:
                    table[nk] = table.pop(k)
            name = ntpath.basename(dst_disp) if k == sk else entry.name
            self._fs[_fs_key(new_path)] = replace(entry, name=name, path=new_path)
            if content is not None:
                self._content[_fs_key(new_path)] = content

    # ---- services and tasks --------------------------------------------
    def add_service(self, svc: ServiceInfo) -> None:
        self._services.append(svc)

    def list_services(self) -> list[ServiceInfo]:
        return [replace(s) for s in self._services]

    def set_service_start(self, name: str, start_type: str) -> None:
        for i, s in enumerate(self._services):
            if s.name.lower() == name.lower():
                self._services[i] = replace(s, start_type=start_type)
                return
        raise KeyError(name)

    def add_task(self, task: TaskInfo) -> None:
        self._tasks.append(task)

    def list_tasks(self) -> list[TaskInfo]:
        return [replace(t) for t in self._tasks]

    def set_task_enabled(self, path: str, enabled: bool) -> None:
        for i, t in enumerate(self._tasks):
            if t.path.lower() == path.lower():
                self._tasks[i] = replace(t, enabled=enabled)
                return
        raise KeyError(path)

    # ---- signatures, shortcuts, misc -----------------------------------
    def set_signature(self, path: str, info: SignatureInfo) -> None:
        if not self.path_exists(path):
            self.add_file(path)
        self._signatures[_fs_key(path)] = info

    def get_signature(self, file_path: str) -> SignatureInfo:
        key = _fs_key(file_path)
        return self._signatures.get(key, SignatureInfo("unknown", "")) if key in self._fs \
            else SignatureInfo("unknown", "")

    def add_shortcut(self, path: str, info: ShortcutInfo) -> None:
        self.add_file(path)
        self._shortcuts[_fs_key(path)] = info

    def read_shortcut(self, lnk: str) -> ShortcutInfo:
        key = _fs_key(lnk)
        if key not in self._fs or key not in self._shortcuts:
            raise KeyError(lnk)
        return self._shortcuts[key]

    def set_shortcut_arguments(self, lnk: str, args: str) -> None:
        self._shortcuts[_fs_key(lnk)] = replace(self.read_shortcut(lnk), arguments=args)

    def create_restore_point(self, description: str) -> bool:
        self.restore_points.append(description)
        return True

    def open_uri(self, uri: str) -> None:
        self.opened_uris.append(uri)

    def launch(self, command_line: str) -> None:
        self.launched.append(command_line)
