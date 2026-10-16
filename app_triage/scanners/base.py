"""Scanner registry and the scan runner."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from ..models import Finding
from ..sysapi.base import AccessDenied, SystemAPI

Scanner = Callable[[SystemAPI], list[Finding]]

# key -> (Chinese label, scanner fn), in registration order
SCANNERS: dict[str, tuple[str, Scanner]] = {}


def register(key: str, label: str) -> Callable[[Scanner], Scanner]:
    def deco(fn: Scanner) -> Scanner:
        SCANNERS[key] = (label, fn)
        return fn
    return deco


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)  # scanner key -> Chinese error text


def run_scan(sys: SystemAPI, keys: list[str] | None = None,
             progress: Callable[[str], None] | None = None) -> ScanResult:
    """Run the selected scanners (all, in registration order, when keys is None).

    A scanner that raises never aborts the scan; its failure is recorded in errors.
    """
    scanners = SCANNERS  # looked up at call time
    result = ScanResult()
    for key in (list(scanners) if keys is None else keys):
        if key not in scanners:
            result.errors[key] = f"未知的扫描项：{key}"
            continue
        label, fn = scanners[key]
        if progress is not None:
            progress(f"正在扫描：{label}")
        try:
            result.findings.extend(fn(sys))
        except AccessDenied as e:
            result.errors[key] = f"权限不足：{e}"
        except Exception as e:  # noqa: BLE001 - one scanner must never abort the scan
            result.errors[key] = f"扫描出错：{type(e).__name__}: {e}"
    return result
