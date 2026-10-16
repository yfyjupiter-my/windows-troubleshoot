"""Fix journal: every change is recorded here so it can be undone."""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

JOURNAL_FILE = "journal.json"
CORRUPT_LABEL = "（日志损坏）"
STATUSES = ("applied", "failed", "undone", "undo_failed")


@dataclass
class JournalEntry:
    index: int
    kind: str
    target: str
    params: dict[str, str]
    status: str  # one of STATUSES
    backup: dict[str, str]
    message: str = ""


def _write_atomic(path: Path, data: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


@dataclass
class FixSession:
    id: str
    dir: Path
    created: str
    label: str
    entries: list[JournalEntry] = field(default_factory=list)

    def backup_path(self, name: str) -> Path:
        d = self.dir / "backup"
        d.mkdir(parents=True, exist_ok=True)
        return d / name

    def quarantine_dir(self) -> Path:
        d = self.dir / "quarantine"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def record(self, entry: JournalEntry) -> None:
        self.entries.append(entry)
        self._save()

    def update(self, entry: JournalEntry) -> None:
        for i, existing in enumerate(self.entries):
            if existing.index == entry.index:
                self.entries[i] = entry
                self._save()
                return
        raise KeyError(f"no journal entry with index {entry.index}")

    def _save(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(
            self.dir / JOURNAL_FILE,
            {
                "id": self.id,
                "created": self.created,
                "label": self.label,
                "entries": [asdict(e) for e in self.entries],
            },
        )


class Journal:
    """Sessions directory; each session lives in ``root/<id>/journal.json``."""

    def __init__(self, root: Path, now: Callable[[], datetime] = datetime.now):
        self.root = Path(root)
        self._now = now

    def begin(self, label: str) -> FixSession:
        moment = self._now()
        base = moment.strftime("%Y%m%d-%H%M%S")
        self.root.mkdir(parents=True, exist_ok=True)
        session_id, n = base, 1
        while True:
            try:
                (self.root / session_id).mkdir()
                break
            except FileExistsError:
                n += 1
                session_id = f"{base}-{n}"
        session = FixSession(
            id=session_id,
            dir=self.root / session_id,
            created=moment.isoformat(timespec="seconds"),
            label=label,
        )
        session._save()
        return session

    def sessions(self) -> list[FixSession]:
        if not self.root.is_dir():
            return []
        found = [
            self.load(d.name)
            for d in self.root.iterdir()
            if d.is_dir() and (d / JOURNAL_FILE).is_file()
        ]
        # newest first: created, then id (-10 after -2 by length)
        found.sort(key=lambda s: (s.created, len(s.id), s.id), reverse=True)
        return found

    def load(self, session_id: str) -> FixSession:
        d = self.root / session_id
        path = d / JOURNAL_FILE
        if not path.is_file():
            raise FileNotFoundError(f"no journal for session {session_id}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            return FixSession(
                id=session_id,
                dir=d,
                created=str(raw["created"]),
                label=str(raw["label"]),
                entries=[JournalEntry(**e) for e in raw["entries"]],
            )
        except (OSError, ValueError, TypeError, KeyError):
            return FixSession(
                id=session_id, dir=d, created=_fallback_created(session_id, d), label=CORRUPT_LABEL
            )


def _fallback_created(session_id: str, d: Path) -> str:
    try:
        return datetime.strptime(session_id[:15], "%Y%m%d-%H%M%S").isoformat(timespec="seconds")
    except ValueError:
        return datetime.fromtimestamp(d.stat().st_mtime).isoformat(timespec="seconds")
