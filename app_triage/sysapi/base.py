"""SystemAPI: the only way scanners and actions touch the OS.

Registry paths use hive prefixes (HKLM\\, HKCU\\, HKCR\\) and are case-insensitive.
Missing registry key / path -> KeyError; permission problems -> AccessDenied.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class AccessDenied(Exception):
    """The OS refused access to a registry key or file path."""


@dataclass
class DirEntry:
    name: str
    path: str
    is_dir: bool
    hidden: bool
    system: bool
    size: int


@dataclass
class ServiceInfo:
    name: str
    display_name: str
    binary_path: str
    start_type: str  # "auto" | "manual" | "disabled" | "boot" | "system"
    status: str


@dataclass
class TaskInfo:
    path: str
    command: str
    enabled: bool
    author: str


@dataclass
class SignatureInfo:
    status: str  # "valid" | "unsigned" | "invalid" | "unknown"
    publisher: str


@dataclass
class ShortcutInfo:
    target: str
    arguments: str


class SystemAPI(Protocol):
    # registry
    def reg_subkeys(self, path: str) -> list[str]: ...
    def reg_values(self, path: str) -> dict[str, object]: ...  # "" key = default value
    def reg_exists(self, path: str) -> bool: ...
    def reg_set_value(self, path: str, name: str, value: object) -> None: ...
    def reg_delete_value(self, path: str, name: str) -> None: ...
    def reg_delete_key(self, path: str) -> None: ...  # recursive
    def reg_export(self, path: str, dest_file: str) -> None: ...
    def reg_import(self, src_file: str) -> None: ...
    def reg_take_ownership(self, path: str) -> None: ...

    # environment
    def known_folders(self) -> dict[str, str]: ...
    def username(self) -> str: ...
    def expand_env(self, s: str) -> str: ...

    # filesystem
    def list_dir(self, path: str) -> list[DirEntry]: ...
    def path_exists(self, path: str) -> bool: ...
    def move(self, src: str, dst: str) -> None: ...
    def read_text(self, path: str) -> str: ...

    # services and scheduled tasks
    def list_services(self) -> list[ServiceInfo]: ...
    def set_service_start(self, name: str, start_type: str) -> None: ...
    def list_tasks(self) -> list[TaskInfo]: ...
    def set_task_enabled(self, path: str, enabled: bool) -> None: ...

    # files of interest
    def get_signature(self, file_path: str) -> SignatureInfo: ...
    def read_shortcut(self, lnk: str) -> ShortcutInfo: ...
    def set_shortcut_arguments(self, lnk: str, args: str) -> None: ...

    # misc
    def create_restore_point(self, description: str) -> bool: ...
    def open_uri(self, uri: str) -> None: ...
    def launch(self, command_line: str) -> None: ...
