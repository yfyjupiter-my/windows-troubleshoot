import pytest

from app_triage.sysapi.base import ServiceInfo, SignatureInfo, TaskInfo
from app_triage.sysapi.parsing import (
    expand_env_vars, looks_access_denied, normalize_image_path, parse_service_json,
    parse_signature_json, parse_tasks_json, ps_quote, split_reg_path, split_task_path,
)

# Captured shape of: Get-ScheduledTask | Select TaskPath,TaskName,State,Author,@{n='Command';...}
# | ConvertTo-Json  (Windows PowerShell 5.1 serializes the State enum as an int: 1 = Disabled, 3 = Ready)
TASKS_JSON = r"""
[
    {
        "TaskPath":  "\\",
        "TaskName":  "WpsUpdateTask_tester",
        "State":  3,
        "Author":  "Kingsoft",
        "Command":  "C:\\Users\\tester\\AppData\\Local\\Kingsoft\\WPS Office\\wpsupdate.exe /from:setup"
    },
    {
        "TaskPath":  "\\2345Soft\\",
        "TaskName":  "2345看图王自动更新",
        "State":  1,
        "Author":  null,
        "Command":  "\"C:\\Program Files (x86)\\2345Soft\\2345Pic\\upgrade.exe\""
    },
    {
        "TaskPath":  "\\Microsoft\\Windows\\Defrag\\",
        "TaskName":  "ScheduledDefrag",
        "State":  "Ready",
        "Author":  "Microsoft Corporation",
        "Command":  "%windir%\\system32\\defrag.exe -c -h -o -$ ; C:\\x\\second.exe"
    },
    {
        "TaskPath":  "\\",
        "TaskName":  "ComHandlerOnly",
        "State":  "Disabled",
        "Author":  "",
        "Command":  null
    }
]
"""


def test_parse_tasks_json_list():
    tasks = parse_tasks_json(TASKS_JSON)
    assert tasks == [
        TaskInfo(r"\WpsUpdateTask_tester",
                 r"C:\Users\tester\AppData\Local\Kingsoft\WPS Office\wpsupdate.exe /from:setup",
                 True, "Kingsoft"),
        TaskInfo("\\2345Soft\\2345看图王自动更新",
                 r'"C:\Program Files (x86)\2345Soft\2345Pic\upgrade.exe"', False, ""),
        TaskInfo(r"\Microsoft\Windows\Defrag\ScheduledDefrag",
                 r"%windir%\system32\defrag.exe -c -h -o -$ ; C:\x\second.exe", True,
                 "Microsoft Corporation"),
        TaskInfo(r"\ComHandlerOnly", "", False, ""),
    ]


def test_parse_tasks_json_single_object_and_empty():
    single = '{"TaskPath": "\\\\", "TaskName": "Solo", "State": 4, "Author": "me", "Command": "a.exe"}'
    assert parse_tasks_json(single) == [TaskInfo(r"\Solo", "a.exe", True, "me")]
    assert parse_tasks_json("") == []
    assert parse_tasks_json("  \r\n") == []
    assert parse_tasks_json("null") == []


def test_parse_tasks_json_tolerates_utf8_bom():
    assert parse_tasks_json('\ufeff{"TaskPath": "\\\\", "TaskName": "X", "State": 3}') == [
        TaskInfo(r"\X", "", True, "")]


SERVICES_JSON = r"""
[
    {
        "Name":  "wpscloudsvr",
        "DisplayName":  "WPS Office Cloud Service",
        "PathName":  "\"C:\\Program Files (x86)\\Kingsoft\\WPS Office\\wpscloudsvr.exe\"",
        "StartMode":  "Auto",
        "State":  "Running"
    },
    {
        "Name":  "2345PicSvc",
        "DisplayName":  "2345看图王服务",
        "PathName":  "C:\\Program Files (x86)\\2345Soft\\2345Pic\\PicSvc.exe -s",
        "StartMode":  "Manual",
        "State":  "Stopped"
    },
    {
        "Name":  "Odd",
        "DisplayName":  null,
        "PathName":  null,
        "StartMode":  "Disabled",
        "State":  "Stopped"
    },
    {"Name": "b", "DisplayName": "b", "PathName": "x", "StartMode": "Boot", "State": "Running"},
    {"Name": "s", "DisplayName": "s", "PathName": "y", "StartMode": "System", "State": "Running"}
]
"""


def test_parse_service_json_list():
    assert parse_service_json(SERVICES_JSON) == [
        ServiceInfo("wpscloudsvr", "WPS Office Cloud Service",
                    r'"C:\Program Files (x86)\Kingsoft\WPS Office\wpscloudsvr.exe"', "auto", "Running"),
        ServiceInfo("2345PicSvc", "2345看图王服务",
                    r"C:\Program Files (x86)\2345Soft\2345Pic\PicSvc.exe -s", "manual", "Stopped"),
        ServiceInfo("Odd", "", "", "disabled", "Stopped"),
        ServiceInfo("b", "b", "x", "boot", "Running"),
        ServiceInfo("s", "s", "y", "system", "Running"),
    ]


def test_parse_service_json_single_object_and_empty():
    single = ('{"Name": "Spooler", "DisplayName": "Print Spooler", '
              '"PathName": "C:\\\\Windows\\\\System32\\\\spoolsv.exe", "StartMode": "Auto", "State": "Running"}')
    assert parse_service_json(single) == [
        ServiceInfo("Spooler", "Print Spooler", r"C:\Windows\System32\spoolsv.exe", "auto", "Running")]
    assert parse_service_json("") == []


@pytest.mark.parametrize("text,expected", [
    ('{"Status": "Valid", "Publisher": "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, '
     'S=Washington, C=US"}', SignatureInfo("valid", "Microsoft Windows")),
    ('{"Status": 0, "Publisher": "CN=Microsoft Corporation, O=Microsoft Corporation, C=US"}',
     SignatureInfo("valid", "Microsoft Corporation")),
    ('{"Status": "NotSigned", "Publisher": null}', SignatureInfo("unsigned", "")),
    ('{"Status": 2, "Publisher": null}', SignatureInfo("unsigned", "")),
    ('{"Status": "HashMismatch", "Publisher": "CN=\\"Zhuhai Kingsoft Office Software Co.,Ltd\\", O=Zhuhai"}',
     SignatureInfo("invalid", "Zhuhai Kingsoft Office Software Co.,Ltd")),
    ('{"Status": "NotTrusted", "Publisher": "CN=\\"Shanghai 2345, Inc.\\", O=2345, C=CN"}',
     SignatureInfo("invalid", "Shanghai 2345, Inc.")),
    ('{"Status": 4, "Publisher": "O=No Common Name, C=CN"}', SignatureInfo("invalid", "O=No Common Name, C=CN")),
    ('{"Status": "UnknownError", "Publisher": null}', SignatureInfo("unknown", "")),
    ('{"Status": "NotSupportedFileFormat", "Publisher": null}', SignatureInfo("unknown", "")),
    ("", SignatureInfo("unknown", "")),
    ('[{"Status": "Valid", "Publisher": "CN=北京某某科技有限公司, O=x"}]', SignatureInfo("valid", "北京某某科技有限公司")),
])
def test_parse_signature_json(text, expected):
    assert parse_signature_json(text) == expected


@pytest.mark.parametrize("raw,expected", [
    (r"\??\C:\Program Files\Vendor\drv.exe", r"C:\Program Files\Vendor\drv.exe"),
    (r"\SystemRoot\System32\drivers\x.sys", r"%SystemRoot%\System32\drivers\x.sys"),
    (r"\systemroot\system32\svchost.exe -k x", r"%SystemRoot%\system32\svchost.exe -k x"),
    (r"system32\DRIVERS\y.sys", r"%SystemRoot%\system32\DRIVERS\y.sys"),
    (r"System32\svchost.exe -k LocalService", r"%SystemRoot%\System32\svchost.exe -k LocalService"),
    (r'"\??\C:\a b\c.exe" -x', r'"C:\a b\c.exe" -x'),
    (r"C:\Windows\system32\svchost.exe -k netsvcs", r"C:\Windows\system32\svchost.exe -k netsvcs"),
    (r"%ProgramFiles%\x\y.exe", r"%ProgramFiles%\x\y.exe"),
    (r"C:\tools\system32\z.exe", r"C:\tools\system32\z.exe"),
    ("", ""),
])
def test_normalize_image_path(raw, expected):
    assert normalize_image_path(raw) == expected


def test_expand_env_vars_case_insensitive_and_unknown_left_alone():
    env = {"SYSTEMROOT": r"C:\Windows", "ProgramFiles(x86)": r"C:\Program Files (x86)"}
    assert expand_env_vars(r"%SystemRoot%\system32\a.exe", env) == r"C:\Windows\system32\a.exe"
    assert expand_env_vars(r"%programfiles(x86)%\b", env) == r"C:\Program Files (x86)\b"
    assert expand_env_vars(r"%NOPE%\c 100%", env) == r"%NOPE%\c 100%"


def test_ps_quote_escapes_single_quotes_including_smart_quotes():
    assert ps_quote(r"C:\it's\a.exe") == r"'C:\it''s\a.exe'"
    assert ps_quote("a\u2019b") == "'a\u2019\u2019b'"
    assert ps_quote("中文 $x") == "'中文 $x'"


@pytest.mark.parametrize("path,expected", [
    (r"HKLM\SOFTWARE\Microsoft", ("HKLM", r"SOFTWARE\Microsoft")),
    (r"hkcu\Software\x\\", ("HKCU", r"Software\x")),
    (r"HKEY_CLASSES_ROOT\.jpg", ("HKCR", ".jpg")),
    (r"HKEY_LOCAL_MACHINE", ("HKLM", "")),
    ("HKEY_CURRENT_USER/Software/y", ("HKCU", r"Software\y")),
])
def test_split_reg_path(path, expected):
    assert split_reg_path(path) == expected


def test_split_reg_path_rejects_unknown_hive():
    with pytest.raises(KeyError):
        split_reg_path(r"HKU\S-1-5-18\x")


def test_split_task_path():
    assert split_task_path(r"\Microsoft\Windows\Defrag\ScheduledDefrag") == (
        "\\Microsoft\\Windows\\Defrag\\", "ScheduledDefrag")
    assert split_task_path("\\2345看图王自动更新") == ("\\", "2345看图王自动更新")
    assert split_task_path("Solo") == ("\\", "Solo")


@pytest.mark.parametrize("text,denied", [
    ("ERROR: Access is denied.\r\n", True),
    ("错误: 拒绝访问。", True),
    ("ERROR: Error accessing the registry.", True),
    ("ERROR: The system was unable to find the specified registry key or value.", False),
    ("", False),
])
def test_looks_access_denied(text, denied):
    assert looks_access_denied(text) is denied


def test_windows_known_folders_keys_match_fake(monkeypatch):
    """windows.py imports on Linux; known_folders wiring is checked with the registry stubbed out."""
    from app_triage.sysapi.fake import FakeSystem
    from app_triage.sysapi.windows import WindowsSystem

    shell = {"HKCU": {"Desktop": r"%USERPROFILE%\OneDrive\桌面",
                      "Start Menu": r"%APPDATA%\Microsoft\Windows\Start Menu",
                      "Startup": r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"}}

    def reg_values(self, path):
        hive = path.split("\\")[0]
        if hive not in shell:
            raise KeyError(path)  # HKLM unreadable -> fall back to %ProgramData%
        return shell[hive]

    monkeypatch.setattr(WindowsSystem, "reg_values", reg_values)
    for name in ("ProgramW6432", "ProgramFiles(x86)", "TEMP", "LOCALAPPDATA"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("USERPROFILE", r"C:\Users\张三")
    monkeypatch.setenv("APPDATA", r"C:\Users\张三\AppData\Roaming")
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    monkeypatch.setenv("ProgramData", r"C:\ProgramData")
    monkeypatch.setenv("SystemRoot", r"C:\Windows")

    folders = WindowsSystem().known_folders()
    assert set(folders) == set(FakeSystem().known_folders())
    assert folders["Desktop"] == r"C:\Users\张三\OneDrive\桌面"
    assert folders["Startup"] == r"C:\Users\张三\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    assert folders["CommonStartup"] == r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    assert folders["ProgramFilesX86"] == r"C:\Program Files"
    assert folders["Temp"] == r"C:\Users\张三\AppData\Local\Temp"
