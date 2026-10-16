"""Chat backend: DeepSeek through the OpenAI-compatible SDK, plus a connection check."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import openai
from openai import OpenAI

from app_triage.config import Config

REQUEST_TIMEOUT = 60
CONNECTION_TEST_TIMEOUT = 15


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # JSON text exactly as the model produced it


@dataclass
class AssistantMessage:
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)


class ChatBackend(Protocol):
    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage: ...


def describe_error(exc: BaseException) -> str:
    """Short Chinese description of a backend failure."""
    if isinstance(exc, (TimeoutError, openai.APITimeoutError)):  # APITimeoutError ⊂ APIConnectionError
        return "请求超时"
    if isinstance(exc, openai.AuthenticationError):
        return "API Key 无效"
    if isinstance(exc, openai.APIConnectionError):
        return "网络连接失败"
    return type(exc).__name__


class DeepSeekBackend:
    def __init__(self, cfg: Config) -> None:
        self._model = cfg.model
        self._client = OpenAI(api_key=cfg.api_key, base_url=cfg.base_url, timeout=REQUEST_TIMEOUT)

    def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage:
        resp = self._client.chat.completions.create(model=self._model, messages=messages, tools=tools)
        msg = resp.choices[0].message
        calls = [ToolCall(tc.id, tc.function.name, tc.function.arguments or "")
                 for tc in (msg.tool_calls or [])]
        return AssistantMessage(msg.content or "", calls)


def test_connection(cfg: Config) -> str | None:
    """None when the API answers; otherwise a short Chinese error. No network call without a key."""
    if not cfg.api_key.strip():
        return "请先填写 API Key"
    try:
        OpenAI(api_key=cfg.api_key, base_url=cfg.base_url,
               timeout=CONNECTION_TEST_TIMEOUT).models.list()
    except Exception as e:  # noqa: BLE001 - every failure becomes a message for the user
        return describe_error(e)
    return None


test_connection.__test__ = False  # not a pytest test, despite the name
