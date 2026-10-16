"""Redaction of the local user name before any text leaves the machine."""
from __future__ import annotations

import ntpath
import re

from app_triage.sysapi.base import SystemAPI

PLACEHOLDER = "%USER%"


class Redactor:
    """Replaces every given user name that directly follows ``\\`` or ``/`` with ``%USER%``.

    That covers profile paths (``C:\\Users\\<name>``) and account names (``DESKTOP-1\\<name>``).
    Matching is case-insensitive and only the name itself is replaced, so separators stay as
    written. A longer name that merely starts with a user name (``tester2``) is left alone,
    but ``tester.PC`` / ``tester-PC`` are still redacted. Longer names are tried first.
    """

    def __init__(self, *names: str) -> None:
        unique: dict[str, str] = {}
        for n in names:
            if n and n.lower() not in unique:
                unique[n.lower()] = n
        self.names: tuple[str, ...] = tuple(sorted(unique.values(), key=len, reverse=True))
        self._pattern = re.compile(
            r"(?<=[\\/])(?:" + "|".join(map(re.escape, self.names)) + r")(?!\w)", re.IGNORECASE,
        ) if self.names else None

    @classmethod
    def for_system(cls, sys: SystemAPI) -> Redactor:
        """The account name and the profile folder's name, which differ for renamed and
        Microsoft accounts."""
        names = [sys.username()]
        try:
            profile = sys.known_folders().get("UserProfile", "")
        except Exception:  # noqa: BLE001 - the account name alone is still redacted
            profile = ""
        names.append(ntpath.basename(profile.rstrip("\\/")))
        return cls(*names)

    def text(self, text: str) -> str:
        return self._pattern.sub(PLACEHOLDER, text) if self._pattern else text

    def data(self, obj: object) -> object:
        """Redact every string (dict keys included) in a JSON-like structure.

        Redact before ``json.dumps``: in JSON text a backslash may start an escape (``\\n``).
        """
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.data(k): self.data(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.data(v) for v in obj]
        return obj


def redact(text: str, *names: str) -> str:
    """Replace each of ``names`` that follows a ``\\`` or ``/`` in text with ``%USER%``."""
    return Redactor(*names).text(text)
