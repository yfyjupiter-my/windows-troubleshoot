"""Read-only tools the AI may call. ``propose_fix`` only records a proposal; nothing is executed."""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass

import app_triage.scanners  # noqa: F401 - registers every scanner in SCANNERS
from app_triage.actions import ACTIONS
from app_triage.models import Finding
from app_triage.safety.redact import redact
from app_triage.scanners.base import SCANNERS, run_scan
from app_triage.scanners.installed import list_installed
from app_triage.sysapi.base import SystemAPI

MAX_RESULT_CHARS = 12000
TRUNCATION_SUFFIX = "…(已截断)"


@dataclass
class Proposal:
    finding_id: str
    action_index: int
    reason: str


@dataclass
class TriageState:
    findings: dict[str, Finding]  # stored unredacted: fix specs are built from these
    proposals: list[Proposal]


class ToolError(Exception):
    """Bad tool input; ``str(exc)`` goes back to the model as ``{"error": ...}``."""


def _function(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required},
    }}


def _str_arg(args: dict, name: str, default: str | None = None) -> str:
    value = args.get(name, default)
    if not isinstance(value, str):
        raise ToolError(f"参数 {name} 必须是字符串")
    return value


class ToolBox:
    def __init__(self, sys: SystemAPI, state: TriageState) -> None:
        self.sys = sys
        self.state = state
        self._handlers: dict[str, Callable[[dict], object]] = {
            "run_scanner": self._run_scanner,
            "list_installed_apps": self._list_installed_apps,
            "get_finding": self._get_finding,
            "propose_fix": self._propose_fix,
        }
        scanner_list = "、".join(f"{k}（{label}）" for k, (label, _) in SCANNERS.items())
        self.schemas: list[dict] = [
            _function("run_scanner", f"运行一个只读扫描项并返回发现的问题。可选：{scanner_list}",
                      {"name": {"type": "string", "enum": list(SCANNERS)}}, ["name"]),
            _function("list_installed_apps", "列出已安装程序，可按名称或发行商关键字过滤（不区分大小写）",
                      {"keyword": {"type": "string", "description": "关键字，留空列出全部"}}, []),
            _function("get_finding", "查看某个发现的完整证据和可用的修复操作（含 action_index）",
                      {"finding_id": {"type": "string"}}, ["finding_id"]),
            _function("propose_fix", "把某个发现的一个修复操作加入待用户确认列表。不会执行任何修改。",
                      {"finding_id": {"type": "string"},
                       "action_index": {"type": "integer", "description": "get_finding 返回的操作序号"},
                       "reason": {"type": "string", "description": "给用户看的中文理由"}},
                      ["finding_id", "action_index", "reason"]),
        ]

    # ---- dispatch -------------------------------------------------------
    def call(self, name: str, arguments: str) -> str:
        """Run one tool; always returns JSON text (redacted, truncated) and never raises."""
        try:
            result = self._dispatch(name, arguments)
        except ToolError as e:
            result = {"error": str(e)}
        except Exception as e:  # noqa: BLE001 - a tool failure must go back to the model, not crash
            result = {"error": f"工具执行出错：{type(e).__name__}: {e}"}
        text = redact(json.dumps(result, ensure_ascii=False), self.sys.username())
        if len(text) > MAX_RESULT_CHARS:
            text = text[:MAX_RESULT_CHARS] + TRUNCATION_SUFFIX
        return text

    def _dispatch(self, name: str, arguments: str) -> object:
        handler = self._handlers.get(name)
        if handler is None:
            raise ToolError(f"未知的工具：{name}")
        try:
            args = json.loads(arguments) if arguments and arguments.strip() else {}
        except json.JSONDecodeError as e:
            raise ToolError(f"参数不是合法的 JSON：{e}") from None
        if not isinstance(args, dict):
            raise ToolError("参数必须是 JSON 对象")
        return handler(args)

    # ---- tools ----------------------------------------------------------
    def _run_scanner(self, args: dict) -> object:
        key = _str_arg(args, "name", "")
        if key not in SCANNERS:
            raise ToolError(f"未知的扫描项：{key}，可选：{', '.join(SCANNERS)}")
        result = run_scan(self.sys, [key])
        if key in result.errors:
            raise ToolError(result.errors[key])
        for f in result.findings:
            self.state.findings[f.id] = f
        return [{"id": f.id, "title": f.title, "risk": f.risk.value, "vendor": f.vendor,
                 "evidence": f.evidence} for f in result.findings]

    def _list_installed_apps(self, args: dict) -> object:
        keyword = _str_arg(args, "keyword", "").strip().lower()
        return [{"name": a.name, "publisher": a.publisher, "version": a.version,
                 "install_location": a.install_location}
                for a in list_installed(self.sys)
                if keyword in a.name.lower() or keyword in a.publisher.lower()]

    def _finding(self, finding_id: str) -> Finding:
        f = self.state.findings.get(finding_id)
        if f is None:
            raise ToolError(f"找不到发现：{finding_id}（请先运行扫描）")
        return f

    def _get_finding(self, args: dict) -> object:
        f = self._finding(_str_arg(args, "finding_id"))
        d = f.to_dict()
        for i, (spec, action) in enumerate(zip(f.actions, d["actions"])):
            impl = ACTIONS.get(spec.kind)
            action["index"] = i
            action["describe"] = impl.describe(spec) if impl else spec.kind
            action["reversible"] = bool(impl and impl.reversible)
        return d

    def _propose_fix(self, args: dict) -> object:
        f = self._finding(_str_arg(args, "finding_id"))
        index = args.get("action_index")
        if isinstance(index, bool) or not isinstance(index, int):
            raise ToolError("参数 action_index 必须是整数")
        if not 0 <= index < len(f.actions):
            raise ToolError(f"action_index 超出范围：该发现只有 {len(f.actions)} 个修复操作")
        reason = _str_arg(args, "reason")
        if any(p.finding_id == f.id and p.action_index == index for p in self.state.proposals):
            return {"ok": True, "note": "已在待确认列表中"}
        self.state.proposals.append(Proposal(f.id, index, reason))
        return {"ok": True}
