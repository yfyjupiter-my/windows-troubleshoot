# AppTriage（AI Windows 应用排查工具）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single-exe Windows desktop tool that scans for leftover / hidden / rogue software traces (e.g. bundled WPS hijacking image file associations), lets DeepSeek explain findings and investigate on request with read-only tools, and applies only user-confirmed, reversible fixes.

**Architecture:** Pure-Python core (models, scanners, actions, journal, AI agent) talks to Windows only through a `SystemAPI` protocol in `app_triage/sysapi/`. `FakeSystem` implements it in memory so the whole core is tested on Linux; `WindowsSystem` implements it with `winreg`/`subprocess`/`pywin32`. A thin PySide6 UI sits on top. PyInstaller builds the exe on Windows (local `build.bat` or GitHub Actions).

**Tech Stack:** Python 3.12, PySide6 ≥ 6.7, openai ≥ 1.40 (pointed at DeepSeek), pywin32 (Windows only), pytest, pytest-qt, PyInstaller ≥ 6, uv for env management.

**Spec:** `docs/superpowers/specs/2026-10-16-app-triage-design.md`

**Deviation from spec (my call):** the spec's `platform/` package is named `sysapi/` (avoids shadowing stdlib `platform`). The spec's `signature.py` scanner is folded into `SystemAPI.get_signature` + autoruns/leftovers risk scoring. Alternate data streams (ADS) are dropped from `hidden.py` (YAGNI for v1).

## Global Constraints

- Python 3.12 (`uv python install 3.12`; `requires-python = ">=3.12,<3.13"`).
- Package name `app_triage`; exe name `AppTriage.exe`; built with `--onefile --windowed --uac-admin`.
- AI: `openai` SDK, `base_url="https://api.deepseek.com"`, default model `"deepseek-chat"`, both editable in Settings.
- Config file: `%APPDATA%\AppTriage\config.json`; API key stored DPAPI-encrypted (`win32crypt.CryptProtectData`), base64 in JSON field `api_key_protected`.
- Data dir for journal/backups/quarantine: `%APPDATA%\AppTriage\sessions\<YYYYmmdd-HHMMSS>\`.
- Nothing is sent to the AI except metadata (names, paths, registry keys, signature/publisher); the user profile name in any path is replaced by `%USER%`; tool results truncated to 12000 chars.
- No system change without explicit user confirmation; every change is backed up first (`reg export` / previous value / quarantine move) and recorded in the journal; files are never deleted, only moved to quarantine.
- AI may call read-only tools and `propose_fix`; it can never execute an action.
- All user-facing text is Simplified Chinese.
- Tests run on Linux: `uv run pytest -q`. Qt tests run with `QT_QPA_PLATFORM=offscreen`.

## Review Focus

1. A scanner hitting access-denied / missing keys / unexpected value types must not abort the scan — the other scanners' findings still show, and the failure is listed. (Task 3: `test_failing_scanner_does_not_abort_scan`)
2. Command lines in Run keys/services are messy: unquoted paths with spaces, `%ProgramFiles%` env vars, `rundll32 x.dll,Entry`, trailing args. Exe path extraction must still find the binary. (Task 5: `test_extract_exe_path_cases`)
3. DeepSeek fails mid-conversation (bad key, timeout, network down): the user gets a Chinese error message, and the chat history stays valid so the next question works. (Task 11: `test_backend_error_returns_chinese_message_and_history_stays_valid`)
4. A fix session where one action fails: the remaining actions still run, and "撤销" undoes only the actions that actually applied, in reverse order. (Task 9: `test_undo_skips_failed_entries_reverse_order`)
5. The AI proposes the same fix twice, or a fix for a finding/action index that doesn't exist: no duplicates, no crash, a clear error goes back to the model. (Task 11: `test_propose_fix_dedupes_and_validates`)

---

### Task 1: Project scaffold, core models, vendor rules

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `app_triage/__init__.py`, `app_triage/models.py`, `app_triage/rules.py`
- Test: `tests/test_models.py`, `tests/test_rules.py`

**Interfaces:**
- Produces:
  - `class Risk(str, Enum)`: `INFO="info"`, `LOW="low"`, `MEDIUM="medium"`, `HIGH="high"`
  - `@dataclass(frozen=True) class ActionSpec: kind: str; target: str; params: tuple[tuple[str, str], ...] = (); high_risk: bool = False` with `def param(self, key: str, default: str = "") -> str`
  - `@dataclass class Finding: id: str; category: str; title: str; evidence: dict[str, str]; risk: Risk; actions: list[ActionSpec]; vendor: str | None = None` with `def to_dict(self) -> dict`
  - `def make_finding_id(category: str, key: str) -> str` — `sha1(f"{category}|{key.lower()}")` hex, first 12 chars
  - `@dataclass(frozen=True) class VendorRule: name: str; patterns: tuple[str, ...]; note: str`
  - `KNOWN_VENDORS: list[VendorRule]`; `def match_vendor(*texts: str) -> VendorRule | None`

- [ ] **Step 1: Scaffold**

`git init`; `uv python install 3.12`; `pyproject.toml` with deps `PySide6>=6.7`, `openai>=1.40`, `pywin32>=306; sys_platform=='win32'`, dev group `pytest>=8`, `pytest-qt>=4.4`, `pyinstaller>=6.0`; `[tool.pytest.ini_options] testpaths=["tests"]`. `.gitignore`: `.venv/ __pycache__/ build/ dist/ *.spec`. Run `uv sync`.

- [ ] **Step 2: Write failing tests**

```python
def test_finding_id_stable_and_case_insensitive():
    assert make_finding_id("file_assoc", ".JPG") == make_finding_id("file_assoc", ".jpg")
    assert len(make_finding_id("a", "b")) == 12

def test_action_spec_param_lookup():
    s = ActionSpec("delete_reg_value", r"HKCU\X", (("name", "WPS"),))
    assert s.param("name") == "WPS" and s.param("missing", "d") == "d"

def test_finding_to_dict_serializes_risk_and_actions():
    f = Finding("id1", "autoruns", "t", {"k": "v"}, Risk.HIGH, [ActionSpec("k", "t")])
    d = f.to_dict()
    assert d["risk"] == "high" and d["actions"][0]["kind"] == "k"

@pytest.mark.parametrize("text,vendor", [
    (r"C:\Users\a\AppData\Local\Kingsoft\WPS Office\ksolaunch.exe", "WPS (金山办公)"),
    ("WPS.PIC.jpg", "WPS (金山办公)"),
    ("wpscloudsvr", "WPS (金山办公)"),
    (r"C:\Program Files (x86)\2345Soft\2345Pic\2345PicViewer.exe", "2345"),
    (r"C:\Program Files\Ludashi\ComputerZTray.exe", "鲁大师"),
    (r"C:\Program Files\360\360safe\safemon\360tray.exe", "360"),
])
def test_match_vendor_known(text, vendor):
    assert match_vendor(text).name == vendor

def test_match_vendor_no_false_positive():
    assert match_vendor(r"C:\Windows\System32\wpshelper.dll", "Microsoft.Photos") is None
```

- [ ] **Step 3: Run** `uv run pytest -q` — Expected: FAIL (import errors).

- [ ] **Step 4: Implement `models.py` and `rules.py`**

Vendor patterns are case-insensitive regexes, matched with `re.search` against each text. Use word-ish boundaries so `wpshelper` doesn't match: WPS → `kingsoft`, `\bwps(office|cloud|cloudsvr|\.pic|\.|\b)`, `\bkso\w*`, `ksolaunch`, `wpscenter`; 2345 → `2345`; 鲁大师 → `ludashi`, `computerz`; 360 → `\b360(safe|tray|se|sd|chrome|\b)`, `qihoo`. Notes are one-line Chinese descriptions (e.g. WPS: "常被捆绑安装，会抢占图片/PDF 默认打开方式并添加自启和后台服务").

- [ ] **Step 5: Run** `uv run pytest -q` — Expected: PASS.

- [ ] **Step 6: Commit** `git add -A && git commit -m "feat: scaffold, core models, vendor rules"`

---

### Task 2: SystemAPI protocol and FakeSystem

**Files:**
- Create: `app_triage/sysapi/__init__.py`, `app_triage/sysapi/base.py`, `app_triage/sysapi/fake.py`
- Test: `tests/test_fake_system.py`

**Interfaces:**
- Produces (`base.py`), all paths are strings; registry paths use hive prefixes `HKLM\`, `HKCU\`, `HKCR\`, case-insensitive:
  - dataclasses: `DirEntry(name: str, path: str, is_dir: bool, hidden: bool, system: bool, size: int)`; `ServiceInfo(name, display_name, binary_path, start_type: str, status: str)` where `start_type ∈ {"auto","manual","disabled","boot","system"}`; `TaskInfo(path: str, command: str, enabled: bool, author: str)`; `SignatureInfo(status: str, publisher: str)` with `status ∈ {"valid","unsigned","invalid","unknown"}`; `ShortcutInfo(target: str, arguments: str)`
  - `class AccessDenied(Exception)`
  - `class SystemAPI(Protocol)` with methods:
    `reg_subkeys(path) -> list[str]`, `reg_values(path) -> dict[str, object]` (`""` key = default value), `reg_exists(path) -> bool`, `reg_set_value(path, name, value: object) -> None`, `reg_delete_value(path, name) -> None`, `reg_delete_key(path) -> None` (recursive), `reg_export(path, dest_file: str) -> None`, `reg_import(src_file: str) -> None`, `reg_take_ownership(path) -> None`,
    `known_folders() -> dict[str, str]` keys exactly `ProgramFiles, ProgramFilesX86, ProgramData, AppData, LocalAppData, Temp, UserProfile, Desktop, StartMenu, CommonStartMenu, Startup, CommonStartup, SystemRoot`, `username() -> str`, `expand_env(s) -> str`,
    `list_dir(path) -> list[DirEntry]`, `path_exists(path) -> bool`, `move(src, dst) -> None`,
    `list_services() -> list[ServiceInfo]`, `set_service_start(name, start_type) -> None`,
    `list_tasks() -> list[TaskInfo]`, `set_task_enabled(path, enabled: bool) -> None`,
    `get_signature(file_path) -> SignatureInfo`, `read_shortcut(lnk) -> ShortcutInfo`, `set_shortcut_arguments(lnk, args) -> None`,
    `read_text(path) -> str`, `create_restore_point(description) -> bool`, `open_uri(uri) -> None`, `launch(command_line) -> None`
  - Missing registry key/path → `KeyError`; permission problems → `AccessDenied`.
- Produces (`fake.py`): `class FakeSystem` implementing all of the above in memory. Builders for tests: `add_key(path, values: dict | None = None)`, `add_file(path, size=0, hidden=False, system=False, content="")`, `add_dir(path)`, `add_service(ServiceInfo)`, `add_task(TaskInfo)`, `set_signature(path, SignatureInfo)`, `add_shortcut(path, ShortcutInfo)`, `deny(path)` (makes any access to that registry/file path raise `AccessDenied` until `reg_take_ownership`). Records `launched: list[str]`, `opened_uris: list[str]`, `restore_points: list[str]`. `reg_export` writes JSON snapshot of the subtree to `dest_file` on the real filesystem; `reg_import` restores it. Default `known_folders()` uses `C:\Users\tester\...` style paths, `username()` → `"tester"`.

- [ ] **Step 1: Write failing tests**

```python
def test_registry_roundtrip_and_case_insensitive(tmp_path):
    s = FakeSystem(); s.add_key(r"HKCU\Software\Kingsoft\Office", {"ver": "12"})
    assert s.reg_subkeys(r"hkcu\software\kingsoft") == ["Office"]
    assert s.reg_values(r"HKCU\Software\Kingsoft\Office") == {"ver": "12"}
    s.reg_export(r"HKCU\Software\Kingsoft", str(tmp_path / "b.json"))
    s.reg_delete_key(r"HKCU\Software\Kingsoft")
    assert not s.reg_exists(r"HKCU\Software\Kingsoft\Office")
    s.reg_import(str(tmp_path / "b.json"))
    assert s.reg_values(r"HKCU\Software\Kingsoft\Office") == {"ver": "12"}

def test_missing_key_raises_keyerror():
    with pytest.raises(KeyError): FakeSystem().reg_values(r"HKLM\Nope")

def test_deny_then_take_ownership():
    s = FakeSystem(); s.add_key(r"HKCU\K\UserChoice", {"ProgId": "WPS.PIC.jpg"}); s.deny(r"HKCU\K\UserChoice")
    with pytest.raises(AccessDenied): s.reg_delete_key(r"HKCU\K\UserChoice")
    s.reg_take_ownership(r"HKCU\K\UserChoice"); s.reg_delete_key(r"HKCU\K\UserChoice")
    assert not s.reg_exists(r"HKCU\K\UserChoice")

def test_filesystem_list_and_move():
    s = FakeSystem(); s.add_file(r"C:\Users\tester\AppData\Roaming\x\a.exe", hidden=True)
    [e] = s.list_dir(r"C:\Users\tester\AppData\Roaming\x")
    assert e.name == "a.exe" and e.hidden and not e.is_dir
    s.move(r"C:\Users\tester\AppData\Roaming\x", r"D:\q\x")
    assert s.path_exists(r"D:\q\x\a.exe") and not s.path_exists(r"C:\Users\tester\AppData\Roaming\x")
```

- [ ] **Step 2: Run** `uv run pytest tests/test_fake_system.py -q` — Expected: FAIL.
- [ ] **Step 3: Implement `base.py` and `fake.py`** — fake registry: `dict[str(lowercased path), (display_path, dict values)]`, subkeys derived by prefix; fake fs: `dict[lowercased path, DirEntry]` with parent dirs auto-created; `ntpath` for path joins.
- [ ] **Step 4: Run** — Expected: PASS.
- [ ] **Step 5: Commit** `feat: SystemAPI protocol and in-memory FakeSystem`

---

### Task 3: Scan runner and installed-programs scanner

**Files:**
- Create: `app_triage/scanners/__init__.py`, `app_triage/scanners/base.py`, `app_triage/scanners/installed.py`
- Test: `tests/scanners/test_runner.py`, `tests/scanners/test_installed.py`

**Interfaces:**
- Consumes: `SystemAPI`, `Finding`, `ActionSpec`, `Risk`, `make_finding_id`, `match_vendor`
- Produces:
  - `Scanner = Callable[[SystemAPI], list[Finding]]`
  - `SCANNERS: dict[str, tuple[str, Scanner]]` — key → (Chinese label, fn). Keys used by later tasks exactly: `"installed"`, `"file_assoc"`, `"autoruns"`, `"leftovers"`, `"hidden"`, `"browser"`. Each scanner module registers itself via `def register(key: str, label: str)` decorator in `base.py`; `scanners/__init__.py` imports all modules.
  - `@dataclass class ScanResult: findings: list[Finding]; errors: dict[str, str]` (scanner key → Chinese error text)
  - `def run_scan(sys: SystemAPI, keys: list[str] | None = None, progress: Callable[[str], None] | None = None) -> ScanResult`
  - `@dataclass class InstalledApp: name: str; publisher: str; version: str; install_location: str; uninstall_string: str; key_path: str`
  - `def list_installed(sys: SystemAPI) -> list[InstalledApp]` — reads `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`, `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall`; skips entries without `DisplayName` or with `SystemComponent == 1`; missing hive → skipped.
  - `installed` scanner (label `"已安装程序"`): one `Finding(category="installed", risk=Risk.LOW, vendor=rule.name)` per app matching `match_vendor(name, publisher, install_location)`, title `f"已安装：{name}"`, action `ActionSpec("run_uninstaller", key_path, (("command", uninstall_string),))`.

- [ ] **Step 1: Write failing tests**

```python
def test_failing_scanner_does_not_abort_scan(monkeypatch):
    def boom(sys): raise AccessDenied(r"HKLM\X")
    def ok(sys): return [Finding("a", "x", "t", {}, Risk.LOW, [])]
    monkeypatch.setattr(base, "SCANNERS", {"boom": ("坏", boom), "ok": ("好", ok)})
    r = run_scan(FakeSystem())
    assert [f.id for f in r.findings] == ["a"]
    assert "boom" in r.errors and "权限" in r.errors["boom"]

def test_run_scan_subset_and_progress():
    seen = []; run_scan(FakeSystem(), ["installed"], progress=seen.append)
    assert seen == ["正在扫描：已安装程序"]

def test_list_installed_reads_all_hives_and_skips_system_components(): ...
    # fixture: WPS under HKCU Uninstall, 7-Zip under HKLM, a SystemComponent=1 entry, entry without DisplayName
    # assert names == {"WPS Office", "7-Zip"}

def test_installed_scanner_flags_only_vendor_apps(): ...
    # assert one finding, vendor "WPS (金山办公)", actions[0].kind == "run_uninstaller", param("command") == the UninstallString
```

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement**; error text: `AccessDenied` → `"权限不足：{e}"`, others → `"扫描出错：{type(e).__name__}: {e}"`. **Step 4: Run** — PASS. **Step 5: Commit** `feat: scan runner and installed-programs scanner`

---

### Task 4: File-association scanner

**Files:**
- Create: `app_triage/scanners/file_assoc.py`
- Test: `tests/scanners/test_file_assoc.py`

**Interfaces:**
- Consumes: Task 3 `register`, `match_vendor`
- Produces: scanner `"file_assoc"` (label `"文件默认打开方式"`). `WATCHED_EXTS = (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tif", ".tiff", ".webp", ".heic", ".ico", ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx")`. For each ext:
  - `user_choice = reg_values(HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{ext}\UserChoice).get("ProgId")`
  - `open_with = list(reg_values(...\FileExts\{ext}\OpenWithProgids))`
  - `command = HKCR\{progid}\shell\open\command` default value (missing → `""`)
  - If `match_vendor(user_choice, command)` → `Finding(category="file_assoc", risk=Risk.MEDIUM, title=f"{ext} 的默认打开方式被 {vendor} 占用", evidence={"ext", "progid", "command", "openwith"})`, action `ActionSpec("reset_file_assoc", ext, (("progid", user_choice), ("openwith", ";".join(vendor-matching open_with entries))))`.
  - Only `.doc/.docx/.xls/.xlsx/.ppt/.pptx` matching WPS → `Risk.INFO` (WPS may be the user's intended office suite), still with the action.
  - UserChoice key access denied → still produce the finding with `evidence["acl"] = "denied"` (WPS locks it).

- [ ] **Step 1: Write failing tests** — `test_wps_hijacked_jpg_detected` (UserChoice ProgId `WPS.PIC.jpg`, HKCR command under `Kingsoft`; assert MEDIUM, action params progid/openwith); `test_photos_association_not_flagged` (ProgId `AppX43hnxtbyyps62jhe9sqpdzxn1790zetc` → no finding); `test_office_ext_wps_is_info`; `test_denied_userchoice_still_reported` (use `FakeSystem.deny`; command lookup via HKCR still works; assert `evidence["acl"] == "denied"`).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** On `AccessDenied` for UserChoice, fall back to `HKCR\{ext}` default value as the progid. **Step 4: Run** — PASS. **Step 5: Commit** `feat: file association hijack scanner`

---

### Task 5: Autoruns scanner

**Files:**
- Create: `app_triage/scanners/cmdline.py`, `app_triage/scanners/autoruns.py`
- Test: `tests/scanners/test_cmdline.py`, `tests/scanners/test_autoruns.py`

**Interfaces:**
- Produces:
  - `def extract_exe_path(command: str, expand: Callable[[str], str] = lambda s: s, exists: Callable[[str], bool] = lambda p: True) -> str` — returns the binary path or `""`.
  - `def is_microsoft(sig: SignatureInfo) -> bool` — `status == "valid"` and publisher contains `"Microsoft"`.
  - scanner `"autoruns"` (label `"开机自启动与后台"`) covering, each producing `category="autoruns"` findings with `evidence["source"]` one of `run`, `startup`, `service`, `task`, `winlogon`, `ifeo`:
    - Run keys: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `...\RunOnce`, same two under `HKLM\SOFTWARE\...`, and `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` → action `ActionSpec("delete_reg_value", key, (("name", value_name),))`
    - Startup folders (`Startup`, `CommonStartup`) entries → `ActionSpec("quarantine_path", path)`
    - Services with `start_type == "auto"` whose binary is not under `SystemRoot` and not Microsoft-signed → `ActionSpec("set_service_start", name, (("start", "disabled"), ("previous", start_type)), high_risk=True)`
    - Tasks whose path does not start with `\Microsoft\` → `ActionSpec("disable_task", task.path)`
    - Winlogon `Shell` ≠ `explorer.exe` or `Userinit` ≠ `C:\Windows\system32\userinit.exe,` (case-insensitive, trailing comma optional) → HIGH, `ActionSpec("set_reg_value", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", (("name", n), ("value", expected_default)), high_risk=True)`
    - IFEO (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*`) with a `Debugger` value → HIGH, `ActionSpec("delete_reg_value", key, (("name","Debugger"),), high_risk=True)`
  - Risk rule (run/startup/service/task): vendor match → MEDIUM; unsigned/invalid signature → LOW; Microsoft-signed → not reported; other valid signature → INFO. `evidence` always has `command`, `exe`, `publisher`, `signature`.

- [ ] **Step 1: Write failing tests**

```python
@pytest.mark.parametrize("cmd,expected", [
    (r'"C:\Program Files\Kingsoft\wps.exe" /tray', r"C:\Program Files\Kingsoft\wps.exe"),
    (r"C:\Program Files\Kingsoft\wpscloudsvr.exe -s", r"C:\Program Files\Kingsoft\wpscloudsvr.exe"),
    (r"%ProgramFiles%\2345Soft\a.exe", r"C:\Program Files\2345Soft\a.exe"),
    (r"rundll32.exe C:\x\evil.dll,Start", r"C:\x\evil.dll"),
    (r"C:\Windows\system32\svchost.exe -k netsvcs", r"C:\Windows\system32\svchost.exe"),
    ("", ""),
])
def test_extract_exe_path_cases(cmd, expected): ...
    # expand replaces %ProgramFiles% with C:\Program Files; exists returns True only for the expected paths
```
Unquoted-with-spaces rule: grow the prefix token by token, return the first prefix ending in `.exe/.dll/.bat/.cmd/.vbs/.ps1/.com/.scr` that `exists`; for `rundll32`/`regsvr32` return the dll argument (strip `,Entry`).

Autoruns tests: `test_wps_run_value_medium`, `test_microsoft_signed_service_skipped`, `test_third_party_auto_service_high_risk_action`, `test_microsoft_tasks_skipped`, `test_winlogon_shell_hijack_high`, `test_ifeo_debugger_high`, `test_startup_shortcut_quarantine_action`.

- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: autoruns scanner and command-line parsing`

---

### Task 6: Leftovers scanner

**Files:**
- Create: `app_triage/scanners/leftovers.py`
- Test: `tests/scanners/test_leftovers.py`

**Interfaces:**
- Consumes: `list_installed` (Task 3), `match_vendor`
- Produces: scanner `"leftovers"` (label `"卸载残留"`), `category="leftovers"`:
  - Scans top-level dirs of `ProgramFiles`, `ProgramFilesX86`, `ProgramData`, `AppData`, `LocalAppData`, plus one level deeper for vendor folders (e.g. `AppData\Kingsoft\WPS Office`).
  - A dir is "owned" if any installed app's `install_location` is it or inside it, or the app's name/publisher shares a normalized token (lowercase alnum, ≥4 chars) with the dir name.
  - `SKIP_DIRS` (case-insensitive): `Common Files, Microsoft, Microsoft.NET, Windows Defender, Windows Mail, Windows Media Player, Windows NT, Windows Photo Viewer, WindowsApps, WindowsPowerShell, Internet Explorer, ModifiableWindowsApps, Packages, Temp, Microsoft Office, Uninstall Information`, and any name starting with `Microsoft` or `Windows`.
  - Not owned + vendor match → MEDIUM; not owned + under ProgramFiles/ProgramFilesX86 → LOW; otherwise not reported. Action `ActionSpec("quarantine_path", path)`; `evidence["size"]` = total bytes (sum of files, recursive).
  - Registry: subkeys of `HKCU\Software`, `HKLM\SOFTWARE`, `HKLM\SOFTWARE\WOW6432Node` matching `match_vendor` with no owning installed app → LOW, `ActionSpec("delete_reg_key", key)`.

- [ ] **Step 1: Write failing tests** — `test_wps_folder_left_after_uninstall_reported` (dirs present, no Uninstall entry → MEDIUM, quarantine action, size summed); `test_installed_app_folder_not_reported` (7-Zip installed with InstallLocation); `test_token_match_counts_as_owned` (dir `Notepad++`, app `Notepad++ (64-bit x64)`); `test_microsoft_and_skip_dirs_ignored`; `test_orphan_vendor_registry_key_reported`; `test_unicode_dir_names` (dir `AppData\Kingsoft\金山文档` with no installed app → reported MEDIUM, title and evidence keep the Chinese name intact).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: leftovers scanner`

---

### Task 7: Hidden-files and browser scanners

**Files:**
- Create: `app_triage/scanners/hidden.py`, `app_triage/scanners/browser.py`
- Test: `tests/scanners/test_hidden.py`, `tests/scanners/test_browser.py`

**Interfaces:**
- Produces:
  - scanner `"hidden"` (label `"隐藏的可执行文件"`): walks `AppData`, `LocalAppData`, `ProgramData`, `Temp`, `UserProfile` to depth 3 (`UserProfile` depth 1); files with `hidden or system` and extension in `(".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".com")`; skip Microsoft-signed; vendor match or unsigned → MEDIUM, else LOW; `ActionSpec("quarantine_path", path)`. `AccessDenied` on a subdirectory is skipped silently (does not fail the scanner).
  - scanner `"browser"` (label `"浏览器劫持"`): `.lnk` files in `Desktop`, `StartMenu`, `CommonStartMenu` (recursive) and `AppData\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar`, whose target basename is one of `chrome.exe, msedge.exe, firefox.exe, iexplore.exe, 360se.exe` and whose `arguments` contain `http://` or `https://` → MEDIUM, `ActionSpec("fix_shortcut_args", lnk, (("args", args_with_urls_removed),))`. Also reads Chrome/Edge `User Data\Default\Preferences` JSON (`homepage`, `session.startup_urls`) and reports vendor-matching or `hao123|2345|360` URLs as INFO with no actions (title says to change it in browser settings). Malformed JSON → skipped.

- [ ] **Step 1: Write failing tests** — `test_hidden_unsigned_exe_in_appdata_reported`, `test_hidden_microsoft_signed_skipped`, `test_non_hidden_or_non_exe_ignored`, `test_access_denied_subdir_skipped`; `test_edge_shortcut_with_url_flagged_and_args_cleaned` (args `--profile-directory=Default https://www.2345.com` → `--profile-directory=Default`), `test_clean_shortcut_ignored`, `test_chrome_homepage_hijack_info`, `test_malformed_preferences_ignored`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: hidden-file and browser hijack scanners`

---

### Task 8: Safety primitives — redaction, journal, quarantine

**Files:**
- Create: `app_triage/safety/__init__.py`, `app_triage/safety/redact.py`, `app_triage/safety/journal.py`
- Test: `tests/safety/test_redact.py`, `tests/safety/test_journal.py`

**Interfaces:**
- Produces:
  - `def redact(text: str, username: str) -> str` — replaces `\Users\{username}` (case-insensitive, both slash styles) with `\Users\%USER%`; no-op for empty username.
  - `@dataclass class JournalEntry: index: int; kind: str; target: str; params: dict[str, str]; status: str; backup: dict[str, str]; message: str = ""` — `status ∈ {"applied","failed","undone","undo_failed"}`
  - `class FixSession`: `id: str`, `dir: Path`, `created: str` (ISO), `label: str`, `entries: list[JournalEntry]`; `def backup_path(self, name: str) -> Path` (under `dir/backup/`); `def quarantine_dir(self) -> Path` (`dir/quarantine/`); `def record(self, entry: JournalEntry) -> None` and `def update(self, entry: JournalEntry) -> None` — both persist `dir/journal.json` immediately.
  - `class Journal(root: Path)`: `def begin(self, label: str) -> FixSession` (id `YYYYmmdd-HHMMSS`, suffix `-2`, `-3`… on collision), `def sessions(self) -> list[FixSession]` (newest first), `def load(self, session_id: str) -> FixSession`. Corrupt `journal.json` → session loaded with `entries=[]` and `label="（日志损坏）"`.

- [ ] **Step 1: Write failing tests** — `test_redact_user_paths` (`C:\Users\Tester\AppData` with username `tester` → `C:\Users\%USER%\AppData`; `C:/Users/tester/x` too; other user untouched), `test_journal_persists_and_reloads`, `test_session_id_collision_suffix`, `test_sessions_newest_first`, `test_corrupt_journal_loads_empty`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: redaction and fix journal`

---

### Task 9: Actions, executor, undo

**Files:**
- Create: `app_triage/actions/__init__.py`, `app_triage/actions/base.py`, `app_triage/actions/registry_actions.py`, `app_triage/actions/system_actions.py`, `app_triage/actions/executor.py`
- Test: `tests/actions/test_actions.py`, `tests/actions/test_executor.py`

**Interfaces:**
- Consumes: `SystemAPI`, `ActionSpec`, `FixSession`, `Journal`, `JournalEntry`, `is_microsoft`
- Produces:
  - `class Action(Protocol)`: `kind: str`; `reversible: bool`; `def describe(self, spec: ActionSpec) -> str` (Chinese one-liner for the confirm list); `def apply(self, spec, sys, session) -> dict[str, str]` (returns backup info); `def undo(self, entry: JournalEntry, sys, session) -> None`
  - `ACTIONS: dict[str, Action]` with kinds and behavior:
    - `delete_reg_value` / `delete_reg_key` / `set_reg_value`: backup `reg_export(key, session.backup_path(f"{index}.reg"))`; undo `reg_import`. For `delete_reg_key` undo also works when the key was fully removed.
    - `reset_file_assoc` (target = ext): export `HKCU\...\FileExts\{ext}`; on `AccessDenied` call `reg_take_ownership` then retry; delete `UserChoice` subkey; delete each `openwith` value from `OpenWithProgids`; undo `reg_import`. Sets backup `"needs_default_apps": "1"`.
    - `set_service_start`: backup `previous`; undo sets previous.
    - `disable_task`: undo `set_task_enabled(path, True)`.
    - `quarantine_path`: move to `session.quarantine_dir()/f"{index}_{basename}"`, backup `{"original": path, "moved_to": dest}`; undo moves back; undo fails with message `"原位置已存在同名文件，未覆盖"` if original path exists.
    - `fix_shortcut_args`: backup old args; undo restores.
    - `run_uninstaller`: `sys.launch(command)`; `reversible = False`; undo is a no-op that records message `"卸载操作无法撤销"`.
  - `def is_protected(spec: ActionSpec, sys: SystemAPI) -> bool` — True for `quarantine_path` targets under `SystemRoot`, or whose file is Microsoft-signed.
  - `@dataclass class ExecResult: session_id: str; entries: list[JournalEntry]; restore_point: bool; needs_default_apps: bool`
  - `def execute(specs: list[ActionSpec], sys: SystemAPI, journal: Journal, confirm_high_risk: Callable[[ActionSpec], bool], label: str = "修复") -> ExecResult` — creates restore point once (`"AppTriage 修复前"`; False result is recorded, not fatal); protected specs → entry `failed` with message `"受保护的系统文件，已拒绝"`; high-risk specs where `confirm_high_risk` returns False → `failed` with `"用户取消"`; exceptions → `failed` with message; continues with the rest.
  - `def undo_session(session_id: str, sys: SystemAPI, journal: Journal) -> list[JournalEntry]` — reverse order, only `applied` entries; sets `undone` / `undo_failed`.

- [ ] **Step 1: Write failing tests** — per action an apply→undo roundtrip against `FakeSystem` restoring the exact prior state (`test_reset_file_assoc_roundtrip_with_denied_acl` uses `deny`), plus:

```python
def test_undo_skips_failed_entries_reverse_order(tmp_path):
    # specs: delete_reg_value (ok), quarantine_path on missing path (fails), disable_task (ok)
    r = execute(specs, s, Journal(tmp_path), confirm_high_risk=lambda _: True)
    assert [e.status for e in r.entries] == ["applied", "failed", "applied"]
    undone = undo_session(r.session_id, s, Journal(tmp_path))
    assert [e.index for e in undone] == [2, 0]
    assert all(e.status == "undone" for e in undone)
    # registry value and task state restored

def test_protected_system_path_refused(): ...      # target under C:\Windows → failed, file still present
def test_high_risk_declined_not_applied(): ...     # confirm returns False → service start unchanged
def test_restore_point_failure_not_fatal(): ...    # monkeypatch create_restore_point → False; actions still applied; r.restore_point is False
def test_needs_default_apps_flag(): ...            # any reset_file_assoc applied → True
def test_undo_quarantine_conflict_reports_message(): ...
```
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: reversible fix actions, executor, undo`

---

### Task 10: Config with encrypted API key

**Files:**
- Create: `app_triage/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces:
  - `@dataclass class Config: api_key: str = ""; base_url: str = "https://api.deepseek.com"; model: str = "deepseek-chat"`
  - `class Crypto(Protocol)`: `protect(data: bytes) -> bytes`, `unprotect(data: bytes) -> bytes`
  - `class DpapiCrypto` (uses `win32crypt`, imported lazily), `class NullCrypto` (identity; tests / demo mode)
  - `def default_config_path() -> Path` — `%APPDATA%\AppTriage\config.json` (falls back to `~/.apptriage/config.json` off Windows)
  - `def load_config(path: Path, crypto: Crypto) -> Config`, `def save_config(cfg: Config, path: Path, crypto: Crypto) -> None` — JSON fields `api_key_protected` (base64), `base_url`, `model`. Missing file, bad JSON, or undecryptable key → defaults with empty `api_key` (never raises).

- [ ] **Step 1: Write failing tests** — `test_roundtrip_key_never_plaintext_on_disk` (crypto that reverses bytes; assert the raw key string not in file text), `test_missing_file_defaults`, `test_corrupt_file_defaults`, `test_undecryptable_key_defaults_but_keeps_url_model`.
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: config with DPAPI-protected API key`

---

### Task 11: AI tools and agent

**Files:**
- Create: `app_triage/ai/__init__.py`, `app_triage/ai/client.py`, `app_triage/ai/tools.py`, `app_triage/ai/agent.py`
- Test: `tests/ai/test_tools.py`, `tests/ai/test_agent.py`

**Interfaces:**
- Consumes: `run_scan`, `SCANNERS`, `list_installed`, `Finding`, `redact`, `Config`, `ACTIONS[kind].describe`
- Produces:
  - `@dataclass class ToolCall: id: str; name: str; arguments: str`; `@dataclass class AssistantMessage: content: str; tool_calls: list[ToolCall]`
  - `class ChatBackend(Protocol)`: `def complete(self, messages: list[dict], tools: list[dict]) -> AssistantMessage`
  - `class DeepSeekBackend(cfg: Config)` — `openai.OpenAI(api_key=cfg.api_key, base_url=cfg.base_url, timeout=60)`, `chat.completions.create(model=cfg.model, messages=..., tools=...)`; `def test_connection(cfg: Config) -> str | None` (None = ok, else Chinese error).
  - `@dataclass class Proposal: finding_id: str; action_index: int; reason: str` ; `@dataclass class TriageState: findings: dict[str, Finding]; proposals: list[Proposal]`
  - `class ToolBox(sys: SystemAPI, state: TriageState)`: `schemas: list[dict]` (OpenAI function format) for exactly: `run_scanner(name: enum of SCANNERS keys)`, `list_installed_apps(keyword: str = "")`, `get_finding(finding_id: str)`, `propose_fix(finding_id: str, action_index: int, reason: str)`; `def call(self, name: str, arguments: str) -> str` — always returns a JSON string, never raises; results redacted with `sys.username()` and truncated to 12000 chars (suffix `"…(已截断)"`); `run_scanner` merges findings into `state.findings` and returns compact `[{id, title, risk, vendor, evidence}]`; `propose_fix` returns `{"ok": true}` or `{"error": "..."}`; duplicate `(finding_id, action_index)` returns `{"ok": true, "note": "已在待确认列表中"}` without appending.
  - `SYSTEM_PROMPT: str` (Chinese): role = Windows 排查助手 for the owner of this PC; may only use the tools; must explain in plain Chinese what each finding is, why it's suspicious, and the risk of fixing; must use `propose_fix` for any change and never claim it already changed anything; must say when unsure rather than guess; WPS/2345/360/鲁大师 rules are hints, not proof.
  - `@dataclass class AgentReply: text: str; new_proposals: list[Proposal]`
  - `class Agent(backend: ChatBackend, toolbox: ToolBox, max_rounds: int = 8)`: `def ask(self, user_text: str) -> AgentReply`; `def explain(self, findings: list[Finding]) -> AgentReply` (adds findings to state, sends a user message `"请逐项解释以下扫描结果，并对你认为应该修复的项调用 propose_fix：\n" + redacted JSON`); `history: list[dict]`; `def reset(self) -> None`.
  - Errors: backend exception → reply text `"AI 调用失败：{简述}。请检查网络或在设置里检查 API Key。"`, and the history is rolled back to before this `ask` (so it never ends with a dangling user/tool_call message). Hitting `max_rounds` → reply `"已达到本次最大排查轮数（8 轮），以下是目前的结论：" + last assistant content`.

- [ ] **Step 1: Write failing tests** with a `ScriptedBackend(responses: list[AssistantMessage | Exception])` that records the messages it got:

```python
def test_agent_runs_tool_then_answers(): ...
    # 1st response: tool_call run_scanner{"name":"autoruns"}; 2nd: content "发现 WPS 自启"
    # assert reply.text == "发现 WPS 自启"; backend saw a role="tool" message with matching tool_call_id

def test_propose_fix_dedupes_and_validates():
    tb = ToolBox(s, TriageState({f.id: f}, []))
    assert json.loads(tb.call("propose_fix", json.dumps({"finding_id": f.id, "action_index": 0, "reason": "r"}))) == {"ok": True}
    assert "note" in json.loads(tb.call("propose_fix", json.dumps({"finding_id": f.id, "action_index": 0, "reason": "r"})))
    assert "error" in json.loads(tb.call("propose_fix", json.dumps({"finding_id": "nope", "action_index": 0, "reason": "r"})))
    assert "error" in json.loads(tb.call("propose_fix", json.dumps({"finding_id": f.id, "action_index": 9, "reason": "r"})))
    assert "error" in json.loads(tb.call("propose_fix", "{bad json"))
    assert "error" in json.loads(tb.call("rm_rf", "{}"))
    assert len(tb.state.proposals) == 1

def test_tool_results_redacted_and_truncated(): ...   # path with \Users\tester\ → %USER%; huge result ≤ 12000 + suffix

def test_backend_error_returns_chinese_message_and_history_stays_valid():
    agent = Agent(ScriptedBackend([TimeoutError("timed out"), AssistantMessage("好的", [])]), tb)
    r1 = agent.ask("开机很慢"); assert r1.text.startswith("AI 调用失败")
    assert agent.history == [{"role": "system", "content": SYSTEM_PROMPT}]
    assert agent.ask("再试一次").text == "好的"

def test_max_rounds_stops_loop(): ...                 # backend always returns a tool call; max_rounds=2 → reply starts with "已达到本次最大排查轮数"

def test_toolbox_never_executes_actions(): ...        # FakeSystem state unchanged after propose_fix + run_scanner
```
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS. **Step 5: Commit** `feat: DeepSeek agent with read-only tools and fix proposals`

---

### Task 12: WindowsSystem implementation

**Files:**
- Create: `app_triage/sysapi/windows.py`, `app_triage/sysapi/parsing.py`
- Test: `tests/test_parsing.py`

**Interfaces:**
- Consumes: `SystemAPI` protocol (Task 2) — must implement every method.
- Produces: `class WindowsSystem` (only importable on Windows; imports `winreg`, `win32com.client` lazily inside methods), and pure helpers in `parsing.py` tested on Linux:
  - `def parse_schtasks_csv(text: str) -> list[TaskInfo]` — input from `schtasks /query /fo csv /v` (header row repeats per folder; dedupe; `Status == "Disabled"` → `enabled=False`; uses columns `TaskName`, `Task To Run`, `Author`, `Scheduled Task State`)
  - `def parse_service_json(text: str) -> list[ServiceInfo]` — input from PowerShell `Get-CimInstance Win32_Service | Select Name,DisplayName,PathName,StartMode,State | ConvertTo-Json`; maps `StartMode` Auto/Manual/Disabled/Boot/System → lowercase; single object (not list) handled.
  - `def parse_signature_json(text: str) -> SignatureInfo` — from `Get-AuthenticodeSignature -LiteralPath p | Select Status,@{n='Publisher';e={$_.SignerCertificate.Subject}} | ConvertTo-Json`; `Valid`→`valid`, `NotSigned`→`unsigned`, `HashMismatch`/`NotTrusted`→`invalid`, else `unknown`; publisher = `CN=` value.
- Implementation notes (decisions): registry via `winreg` with `KEY_WOW64_64KEY`; `reg_export`/`reg_import` via `reg.exe export /y` / `reg.exe import`; `reg_take_ownership` via PowerShell setting the key ACL owner to the current user and removing Deny ACEs; services via `sc.exe config <name> start= disabled|demand|auto`; tasks via `schtasks /change /tn <path> /disable|/enable`; restore point via `powershell Checkpoint-Computer -Description <d> -RestorePointType MODIFY_SETTINGS` (returns False on non-zero exit; Windows limits to one per 24h by default — treat that as False, not error); shortcuts via `WScript.Shell` COM; `open_uri` via `os.startfile`; all subprocesses with `creationflags=CREATE_NO_WINDOW`, `encoding="utf-8"` and PowerShell `[Console]::OutputEncoding=[Text.Encoding]::UTF8` prefix (Chinese output); `PermissionError`/`WinError 5` → `AccessDenied`; `FileNotFoundError` → `KeyError`.

- [ ] **Step 1: Write failing tests** for the three parsers using captured sample text (include a Chinese task name and a single-object service JSON).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement** parsers and `WindowsSystem`. **Step 4: Run** — PASS (Linux covers parsers only; `WindowsSystem` is verified in Task 14's Windows check). **Step 5: Commit** `feat: Windows SystemAPI implementation`

---

### Task 13: PySide6 UI

**Files:**
- Create: `app_triage/ui/__init__.py`, `app_triage/ui/main_window.py`, `app_triage/ui/scan_page.py`, `app_triage/ui/chat_page.py`, `app_triage/ui/history_page.py`, `app_triage/ui/settings_page.py`, `app_triage/ui/workers.py`
- Test: `tests/ui/test_ui.py` (pytest-qt, `QT_QPA_PLATFORM=offscreen` set in `tests/ui/conftest.py`)

**Interfaces:**
- Consumes: `run_scan`, `SCANNERS`, `TriageState`, `Agent`, `ToolBox`, `ChatBackend`, `execute`, `undo_session`, `Journal`, `ACTIONS`, `Config`, `save_config`, `test_connection`
- Produces: `class MainWindow(QMainWindow)` — `__init__(self, sys: SystemAPI, journal: Journal, cfg: Config, save_cfg: Callable[[Config], None], backend_factory: Callable[[Config], ChatBackend])`; left nav with four pages: 扫描 / AI 助手 / 修复记录 / 设置. Shared `TriageState` between ScanPage and ChatPage.
  - `workers.run_in_thread(fn, on_done, on_error)` — `QThreadPool` + `QRunnable` with signals; scan, AI calls, and fixes all run off the UI thread.
  - **ScanPage**: "开始扫描" button; `QTreeWidget` grouped by scanner label; each finding row checkable, colored by risk (HIGH red, MEDIUM orange, LOW gray, INFO default), tooltip = evidence; scanner errors shown in a yellow banner; "让 AI 解释" sends checked (or all) findings to `agent.explain` and switches to ChatPage; "修复所选" opens confirm dialog.
  - **Confirm dialog**: lists `ACTIONS[kind].describe(spec)` per checked action, marks irreversible ones "（不可撤销）" and high-risk ones in red; OK → `execute(...)` with `confirm_high_risk` showing a per-item `QMessageBox.warning` Yes/No; afterwards shows a result summary, a warning if `restore_point` is False ("系统还原点创建失败，但已备份注册表和文件"), and if `needs_default_apps` → message explaining the last step then `sys.open_uri("ms-settings:defaultapps")`; then re-runs the affected scanners.
  - **ChatPage**: transcript view + input + send; AI proposals appear in a "待确认的修复" list below with checkboxes and the AI's reason; "执行所选修复" uses the same confirm dialog. If `cfg.api_key` empty → disabled input with a link "请先在设置里填写 DeepSeek API Key".
  - **HistoryPage**: list of `journal.sessions()` with time/label/entry statuses; "撤销此次修复" → confirm → `undo_session` → refresh.
  - **SettingsPage**: API Key (password field), Base URL, Model, "测试连接" (`test_connection`), "保存" (`save_cfg`, rebuilds the agent via `backend_factory`).

- [ ] **Step 1: Write failing tests** (`FakeSystem` seeded with the WPS scenario: hijacked `.jpg`, WPS Run value, WPS leftover dir; `ScriptedBackend` from Task 11 tests moved to `tests/fakes.py`):
  - `test_scan_populates_tree_and_errors` — click 开始扫描, `qtbot.waitUntil` tree has a `.jpg` row with orange color.
  - `test_fix_selected_applies_and_opens_default_apps` — check the `.jpg` row, auto-accept dialogs (monkeypatch `QMessageBox`/dialog `exec` to accept), assert `FakeSystem.opened_uris == ["ms-settings:defaultapps"]` and a journal session exists.
  - `test_chat_shows_proposals` — backend proposes a fix; proposal list has one checkable row with the reason.
  - `test_history_undo_restores_state` — after a fix, undo from HistoryPage restores the registry value.
  - `test_chat_disabled_without_api_key`.
- [ ] **Step 2: Run** `QT_QPA_PLATFORM=offscreen uv run pytest tests/ui -q` — FAIL. **Step 3: Implement.** **Step 4: Run** — PASS, then full suite `uv run pytest -q` PASS. **Step 5: Commit** `feat: PySide6 desktop UI`

---

### Task 14: Entry point, demo mode, packaging, README

**Files:**
- Create: `app_triage/__main__.py`, `app_triage/main.py`, `app_triage/sysapi/demo.py`, `build.bat`, `.github/workflows/build.yml`, `README.md`
- Test: `tests/test_main.py`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `def main(argv: list[str] | None = None) -> int` — `--demo` (or non-Windows) uses `demo_system()` + `NullCrypto` + config at `~/.apptriage/config.json`; on Windows uses `WindowsSystem` + `DpapiCrypto`; if not admin (`ctypes.windll.shell32.IsUserAnAdmin()`), shows a warning that fixes need administrator rights (the exe requests UAC via manifest, so this only appears when run from source).
  - `def demo_system() -> FakeSystem` — the WPS scenario: `.jpg/.png/.pdf` hijacked (one with denied ACL), WPS Run value, `wpscloudsvr` auto service unsigned, `\WPS\WpsUpdateTask` task, leftover `AppData\Kingsoft` dir, a hidden unsigned exe in `ProgramData`, an Edge shortcut with `https://www.2345.com`.
  - `build.bat`: `uv sync --group dev` then `uv run pyinstaller --onefile --windowed --uac-admin --name AppTriage --collect-submodules app_triage app_triage\__main__.py`; output `dist\AppTriage.exe`.
  - `.github/workflows/build.yml`: on push/workflow_dispatch, `windows-latest`, `astral-sh/setup-uv`, run tests, run `build.bat`, upload `dist/AppTriage.exe` as artifact `AppTriage`.
  - `README.md` (Chinese): what it does, safety model (confirm, backup, quarantine, undo), how to set the DeepSeek key, how to build on Windows / via GitHub Actions, `--demo` on Linux, known limitation about default-app selection step.

- [ ] **Step 1: Write failing tests** — `test_demo_scan_finds_all_scenario_items` (`run_scan(demo_system())` has findings in all six categories and the denied `.jpg`), `test_main_demo_constructs_window` (monkeypatch `QApplication.exec` → 0; `main(["--demo"]) == 0`).
- [ ] **Step 2: Run** — FAIL. **Step 3: Implement.** **Step 4: Run** full suite — PASS. Launch `uv run python -m app_triage --demo` under `QT_QPA_PLATFORM=offscreen` for 3 s to confirm no startup exception.
- [ ] **Step 5: Commit** `feat: entry point, demo mode, Windows build`
- [ ] **Step 6: Windows verification (by the user, on a VM snapshot)** — run `build.bat` (or download the Actions artifact); install WPS; run `AppTriage.exe` → UAC prompt; scan shows hijacked `.jpg/.png`, WPS Run/service/task; fix them → system settings opens to default apps, pick 照片 → re-scan clean; 修复记录 → 撤销 restores the previous state; uninstall WPS → re-scan lists leftovers; AI 助手: "开机很慢" → AI calls autoruns and only proposes fixes.
