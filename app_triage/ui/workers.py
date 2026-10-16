"""Run blocking work (scans, AI calls, fixes) off the UI thread."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal, Slot


class _Relay(QObject):
    """Lives on the UI thread, so its slots (and the callbacks) run there."""

    done = Signal(object)
    failed = Signal(object)

    def __init__(self, on_done: Callable[[Any], None], on_error: Callable[[BaseException], None]):
        super().__init__()
        self._on_done, self._on_error = on_done, on_error
        self.done.connect(self._deliver_done)
        self.failed.connect(self._deliver_error)

    @Slot(object)
    def _deliver_done(self, result: object) -> None:
        _pending.discard(self)
        self._on_done(result)

    @Slot(object)
    def _deliver_error(self, exc: object) -> None:
        _pending.discard(self)
        self._on_error(exc)  # type: ignore[arg-type]


class _Task(QRunnable):
    def __init__(self, fn: Callable[[], Any], relay: _Relay):
        super().__init__()
        self._fn, self._relay = fn, relay

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001 - every failure is reported on the UI thread
            self._relay.failed.emit(exc)
        else:
            self._relay.done.emit(result)


_pending: set[_Relay] = set()  # keeps relays alive until their callback has run


def run_in_thread(fn: Callable[[], Any], on_done: Callable[[Any], None],
                  on_error: Callable[[BaseException], None]) -> None:
    """Run ``fn()`` on the global thread pool; ``on_done``/``on_error`` run on the UI thread."""
    relay = _Relay(on_done, on_error)
    _pending.add(relay)
    QThreadPool.globalInstance().start(_Task(fn, relay))
