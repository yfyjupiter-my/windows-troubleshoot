import base64
import json
import sys
from pathlib import Path

from app_triage import config as cfgmod
from app_triage.config import (
    Config, NullCrypto, default_config_path, load_config, save_config,
)


class ReverseCrypto:
    def protect(self, data: bytes) -> bytes:
        return data[::-1]

    def unprotect(self, data: bytes) -> bytes:
        return data[::-1]


class BrokenCrypto:
    def protect(self, data: bytes) -> bytes:
        return data

    def unprotect(self, data: bytes) -> bytes:
        raise OSError("cannot decrypt")


def test_roundtrip_key_never_plaintext_on_disk(tmp_path):
    p = tmp_path / "sub" / "config.json"
    cfg = Config(api_key="sk-secret-123", base_url="https://x.example", model="m1")
    save_config(cfg, p, ReverseCrypto())
    text = p.read_text(encoding="utf-8")
    assert "sk-secret-123" not in text
    raw = json.loads(text)
    assert base64.b64decode(raw["api_key_protected"]) == b"321-terces-ks"
    assert load_config(p, ReverseCrypto()) == cfg
    assert [f.name for f in p.parent.iterdir()] == ["config.json"]


def test_missing_file_defaults(tmp_path):
    assert load_config(tmp_path / "nope.json", NullCrypto()) == Config()


def test_corrupt_file_defaults(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{not json", encoding="utf-8")
    assert load_config(p, NullCrypto()) == Config()
    p.write_text("[1, 2]", encoding="utf-8")
    assert load_config(p, NullCrypto()) == Config()
    p.write_text(json.dumps({"base_url": 5, "model": None, "api_key_protected": 7}), encoding="utf-8")
    assert load_config(p, NullCrypto()) == Config()


def test_undecryptable_key_defaults_but_keeps_url_model(tmp_path):
    p = tmp_path / "c.json"
    save_config(Config(api_key="k", base_url="https://u", model="mm"), p, NullCrypto())
    got = load_config(p, BrokenCrypto())
    assert got == Config(api_key="", base_url="https://u", model="mm")
    p.write_text(json.dumps({"api_key_protected": "!!notbase64", "base_url": "https://u"}), encoding="utf-8")
    assert load_config(p, NullCrypto()) == Config(base_url="https://u")


def test_partial_and_blank_fields_fall_back_individually(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"base_url": "https://only.example"}), encoding="utf-8")
    assert load_config(p, NullCrypto()) == Config(base_url="https://only.example")
    p.write_text(json.dumps({"base_url": "  ", "model": ""}), encoding="utf-8")
    assert load_config(p, NullCrypto()) == Config()


def test_empty_key_is_not_encrypted(tmp_path):
    p = tmp_path / "c.json"
    save_config(Config(), p, BrokenCrypto())
    assert json.loads(p.read_text(encoding="utf-8"))["api_key_protected"] == ""
    assert load_config(p, BrokenCrypto()).api_key == ""


def test_default_config_path(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("APPDATA", str(tmp_path))
    assert default_config_path() == tmp_path / "AppTriage" / "config.json"
    monkeypatch.delenv("APPDATA")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert default_config_path() == tmp_path / ".apptriage" / "config.json"
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setenv("APPDATA", "/ignored")
    assert default_config_path() == tmp_path / ".apptriage" / "config.json"


def test_dpapi_import_is_lazy():
    assert "win32crypt" not in sys.modules or sys.platform == "win32"
    assert cfgmod.DpapiCrypto() is not None
