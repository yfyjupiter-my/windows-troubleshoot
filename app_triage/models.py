"""Core data models shared by scanners, the fixer and the UI."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from enum import Enum


class Risk(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class ActionSpec:
    kind: str
    target: str
    params: tuple[tuple[str, str], ...] = ()
    high_risk: bool = False

    def param(self, key: str, default: str = "") -> str:
        for k, v in self.params:
            if k == key:
                return v
        return default


@dataclass
class Finding:
    id: str
    category: str
    title: str
    evidence: dict[str, str]
    risk: Risk
    actions: list[ActionSpec]
    vendor: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = self.risk.value
        d["actions"] = [
            {**asdict(a), "params": [list(p) for p in a.params]} for a in self.actions
        ]
        return d


def make_finding_id(category: str, key: str) -> str:
    """Stable, case-insensitive 12-char id for a finding."""
    return hashlib.sha1(f"{category}|{key.lower()}".encode("utf-8")).hexdigest()[:12]
