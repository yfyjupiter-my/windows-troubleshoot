"""Scanner registry and the scan runner."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
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


MAX_LISTED_PROBLEMS = 3


class PartialScanError(Exception):
    """A scanner finished, but some sources or entries could not be read.

    ``findings`` holds everything that was read; run_scan keeps them and lists the problems.
    """

    def __init__(self, findings: list[Finding], problems: list[str]) -> None:
        super().__init__("；".join(problems))
        self.findings = list(findings)
        self.problems = list(problems)


class Problems:
    """Collects unexpected failures inside one scanner so the rest of its findings survive.

    Missing keys/paths (KeyError) and refused access (AccessDenied) are normal on a real
    machine and stay silent; anything else is recorded with the place it happened.
    """

    def __init__(self) -> None:
        self.items: list[str] = []

    @contextmanager
    def guard(self, where: str) -> Iterator[None]:
        try:
            yield
        except (KeyError, AccessDenied):
            pass
        except Exception as e:  # noqa: BLE001 - one source/entry must never lose the rest
            self.items.append(f"{where}（{type(e).__name__}: {e}）")

    def result(self, findings: list[Finding]) -> list[Finding]:
        """The findings, or PartialScanError carrying them when anything failed."""
        if self.items:
            raise PartialScanError(findings, self.items)
        return findings


def partial_message(problems: list[str]) -> str:
    shown = "；".join(problems[:MAX_LISTED_PROBLEMS])
    more = f" 等 {len(problems)} 处" if len(problems) > MAX_LISTED_PROBLEMS else ""
    return f"部分内容未能读取，其余结果已列出：{shown}{more}"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)  # scanner key -> Chinese error text


def run_scan(sys: SystemAPI, keys: list[str] | None = None,
             progress: Callable[[str], None] | None = None) -> ScanResult:
    """Run the selected scanners (all, in registration order, when keys is None).

    A scanner that raises never aborts the scan; its failure is recorded in errors. A scanner
    that raises PartialScanError keeps its findings and its problems are recorded in errors.
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
        except PartialScanError as e:
            result.findings.extend(e.findings)
            result.errors[key] = partial_message(e.problems)
        except AccessDenied as e:
            result.errors[key] = f"权限不足：{e}"
        except Exception as e:  # noqa: BLE001 - one scanner must never abort the scan
            result.errors[key] = f"扫描出错：{type(e).__name__}: {e}"
    return result
