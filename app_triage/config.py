"""用户配置：DeepSeek API Key 以 DPAPI 加密后存放在 config.json。"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-chat"


@dataclass
class Config:
    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL


class Crypto(Protocol):
    def protect(self, data: bytes) -> bytes: ...
    def unprotect(self, data: bytes) -> bytes: ...


class DpapiCrypto:
    """Windows DPAPI（当前用户范围）。win32crypt 延迟导入，便于非 Windows 导入本模块。"""

    def protect(self, data: bytes) -> bytes:
        import win32crypt
        return win32crypt.CryptProtectData(data, "AppTriage", None, None, None, 0)

    def unprotect(self, data: bytes) -> bytes:
        import win32crypt
        return win32crypt.CryptUnprotectData(data, None, None, None, 0)[1]


class NullCrypto:
    """恒等变换：仅用于测试 / 演示模式。"""

    def protect(self, data: bytes) -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        return data


def default_config_path() -> Path:
    appdata = os.environ.get("APPDATA")
    if sys.platform == "win32" and appdata:
        return Path(appdata) / "AppTriage" / "config.json"
    return Path.home() / ".apptriage" / "config.json"


def _text_field(raw: dict, name: str, default: str) -> str:
    value = raw.get(name)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def load_config(path: Path, crypto: Crypto) -> Config:
    """读取配置；任何错误都回退到默认值，绝不抛出。"""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return Config()
    if not isinstance(raw, dict):
        return Config()
    cfg = Config(
        base_url=_text_field(raw, "base_url", DEFAULT_BASE_URL),
        model=_text_field(raw, "model", DEFAULT_MODEL),
    )
    protected = raw.get("api_key_protected")
    if isinstance(protected, str) and protected:
        try:
            cfg.api_key = crypto.unprotect(base64.b64decode(protected, validate=True)).decode("utf-8")
        except Exception:
            cfg.api_key = ""
    return cfg


def save_config(cfg: Config, path: Path, crypto: Crypto) -> None:
    """原子写入（同目录临时文件 + os.replace）。空 Key 不加密。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    protected = ""
    if cfg.api_key:
        protected = base64.b64encode(crypto.protect(cfg.api_key.encode("utf-8"))).decode("ascii")
    payload = {"api_key_protected": protected, "base_url": cfg.base_url, "model": cfg.model}
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
