"""Test doubles shared across test modules."""
from __future__ import annotations

import copy

from app_triage.ai.client import AssistantMessage


class ScriptedBackend:
    """ChatBackend that replays scripted responses (raising the ones that are exceptions).

    Every call records a deep copy of the ``messages`` and ``tools`` it received.
    """

    def __init__(self, responses: list[AssistantMessage | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[list[dict]] = []
        self.tools: list[list[dict]] = []

    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage:
        self.calls.append(copy.deepcopy(messages))
        self.tools.append(copy.deepcopy(tools))
        if not self.responses:
            raise AssertionError("ScriptedBackend: no scripted response left")
        r = self.responses.pop(0)
        if isinstance(r, BaseException):
            raise r
        return r
