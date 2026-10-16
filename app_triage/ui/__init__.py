"""PySide6 desktop UI: scan, AI assistant, fix history and settings pages."""
from __future__ import annotations

from app_triage.actions import ACTIONS
from app_triage.models import ActionSpec, Risk

RISK_COLORS: dict[Risk, str] = {Risk.HIGH: "#d93025", Risk.MEDIUM: "#e8710a", Risk.LOW: "#80868b"}
RISK_NAMES: dict[Risk, str] = {Risk.HIGH: "高", Risk.MEDIUM: "中", Risk.LOW: "低", Risk.INFO: "提示"}
HIGH_RISK_COLOR = RISK_COLORS[Risk.HIGH]


def describe_spec(spec: ActionSpec) -> str:
    """Chinese one-liner for a fix action (falls back to kind and target for unknown kinds)."""
    action = ACTIONS.get(spec.kind)
    return action.describe(spec) if action else f"{spec.kind}：{spec.target}"


def is_reversible(spec: ActionSpec) -> bool:
    action = ACTIONS.get(spec.kind)
    return bool(action and action.reversible)
